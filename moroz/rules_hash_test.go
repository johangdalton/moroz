package moroz

import (
	"context"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/groob/moroz/santa"
)

func pilotRules(t *testing.T, name string) []santa.Rule {
	t.Helper()
	var config santa.Config
	if _, err := toml.DecodeFile("testdata/"+name, &config); err != nil {
		t.Fatal(err)
	}
	return config.Rules
}

// The expected values are the rules_hash Santa 2026.7 reported on the pilot
// fleet on 2026-11-03 for these published policies.
func TestSantaRulesHashMatchesSanta(t *testing.T) {
	if got := SantaRulesHash(pilotRules(t, "pilot-global-20261103.toml")); got != "54bdb898e9041a2398cd59b3fabff886" {
		t.Fatalf("global: %s", got)
	}
	// C29AJ received the HS group's Spotify TEAMID rule incrementally, so
	// Santa holds it last; a CLEAN sync would store the served order.
	hs := pilotRules(t, "pilot-hs-20261103.toml")
	var appended []santa.Rule
	var spotify santa.Rule
	for _, r := range hs {
		if r.Identifier == "2FNC3A47ZF" {
			spotify = r
		} else {
			appended = append(appended, r)
		}
	}
	if spotify.Identifier == "" {
		t.Fatal("fixture lost the HS rule")
	}
	appended = append(appended, spotify)
	if got := SantaRulesHash(appended); got != "13ec83b4fd27168c7f3f907fd9d1dbd3" {
		t.Fatalf("incremental order: %s", got)
	}
	if served := SantaRulesHash(hs); served == SantaRulesHash(appended) {
		t.Fatal("order did not change the hash")
	}
	// Writing a rule again moves it to the end; REMOVE deletes it.
	if SantaRulesHash(append(append([]santa.Rule(nil), hs...), spotify)) != SantaRulesHash(appended) {
		t.Fatal("rewrite did not move the rule last")
	}
	removed := append(append([]santa.Rule(nil), appended...), rule(santa.TeamID, santa.Remove, "2FNC3A47ZF", ""))
	if SantaRulesHash(removed) != SantaRulesHash(appended[:len(appended)-1]) {
		t.Fatal("REMOVE not applied")
	}
	if SantaRulesHash([]santa.Rule{rule(santa.SigningID, santa.Cel, "platform:com.apple.bash", "")}) != "" {
		t.Fatal("CEL rules must not be predicted")
	}
}

func TestRulesHashFindings(t *testing.T) {
	svc, _, logs, now := syncFixture(t, true)
	ctx := context.Background()
	served := SantaRulesHash([]santa.Rule{ruleA, ruleB, ruleC, ruleD})
	sync := func(pre santa.PreflightPayload, postHash string) *santa.Preflight {
		t.Helper()
		p, err := svc.Preflight(ctx, "mac-a", pre)
		if err != nil {
			t.Fatal(err)
		}
		rules, err := svc.RuleDownload(ctx, "mac-a")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Postflight(ctx, "mac-a", santa.PostflightPayload{SyncType: p.SyncType, RulesReceived: len(rules), RulesProcessed: len(rules), RulesHash: postHash}); err != nil {
			t.Fatal(err)
		}
		return p
	}
	withHash := func(hash string) santa.PreflightPayload {
		p := populated
		p.RulesHash = hash
		return p
	}
	findings := func() []HashFinding { return svc.SyncStats().RulesHashFindings }
	expectClean := func(p *santa.Preflight) {
		t.Helper()
		if mode, reason := lastDecision(t, logs); p.SyncType != santa.SyncTypeClean || mode != decisionClean || reason != "rules_hash_mismatch" {
			t.Fatalf("%+v %s %s", p, mode, reason)
		}
	}

	// First contact is a CLEAN; the right hash verifies it.
	sync(santa.PreflightPayload{}, served)
	if stats := svc.SyncStats(); len(stats.RulesHashFindings) != 0 || stats.RulesHashVerified != 1 {
		t.Fatalf("%+v", stats)
	}
	// Unchanged hash between syncs: nothing to report.
	if p := sync(withHash(served), served); p.SyncType != santa.SyncTypeNormal || len(findings()) != 0 {
		t.Fatalf("%+v %+v", p, findings())
	}
	// The rules changed on the machine without a sync: this same sync becomes
	// a CLEAN, which repairs and verifies.
	*now = now.Add(2 * time.Hour)
	expectClean(sync(withHash("0000"), served))
	if stats := svc.SyncStats(); len(stats.RulesHashFindings) != 0 || stats.RulesHashVerified != 2 {
		t.Fatalf("%+v", stats)
	}
	// A CLEAN that does not leave the served rules stays open...
	*now = now.Add(2 * time.Hour)
	expectClean(sync(withHash("0000"), "1111"))
	if f := findings(); len(f) != 1 || f[0].Kind != hashCleanMismatch || f[0].Expected != served || f[0].Reported != "1111" {
		t.Fatalf("%+v", f)
	}
	// ...is retried at most once an hour...
	*now = now.Add(59 * time.Minute)
	if p := sync(withHash("1111"), "1111"); p.SyncType != santa.SyncTypeNormal || len(findings()) != 1 {
		t.Fatalf("backoff ignored: %+v %+v", p, findings())
	}
	// ...and clears once a CLEAN verifies.
	*now = now.Add(time.Minute)
	expectClean(sync(withHash("1111"), served))
	if stats := svc.SyncStats(); len(stats.RulesHashFindings) != 0 || stats.RulesHashVerified != 3 {
		t.Fatalf("%+v", stats)
	}
	// Clients that send no hash are never judged.
	sync(santa.PreflightPayload{RequestCleanSync: true}, "")
	sync(populated, "")
	if len(findings()) != 0 {
		t.Fatalf("%+v", findings())
	}
}
