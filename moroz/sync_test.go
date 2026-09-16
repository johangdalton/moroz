package moroz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/groob/moroz/santa"
)

// generationStore is an in-memory ConfigStore that also keeps earlier
// generations, like santaconfig.FileRepo in manifest mode.
type generationStore struct {
	current     string
	generations map[string]map[string]santa.Config
}

func newGenerationStore() *generationStore {
	return &generationStore{generations: map[string]map[string]santa.Config{}}
}

func (g *generationStore) publish(generation string, configs map[string]santa.Config) {
	for id, c := range configs {
		c.MachineID = id
		configs[id] = c
	}
	g.generations[generation] = configs
	g.current = generation
}

func (g *generationStore) effective(generation, machineID string) (santa.Config, error) {
	configs, ok := g.generations[generation]
	if !ok {
		return santa.Config{}, fmt.Errorf("generation %q unavailable", generation)
	}
	if c, ok := configs[machineID]; ok {
		return c, nil
	}
	c, ok := configs["global"]
	if !ok {
		return c, fmt.Errorf("no global config")
	}
	return c, nil
}

func (g *generationStore) Config(_ context.Context, machineID string) (santa.Config, error) {
	return g.effective(g.current, machineID)
}
func (g *generationStore) AllConfigs(context.Context) ([]santa.Config, error) { return nil, nil }
func (g *generationStore) EffectiveConfig(_ context.Context, machineID string) (santa.Config, string, error) {
	c, err := g.effective(g.current, machineID)
	return c, g.current, err
}
func (g *generationStore) HistoricConfig(_ context.Context, generation, machineID string) (santa.Config, error) {
	return g.effective(generation, machineID)
}

func rule(ruleType santa.RuleType, policy santa.Policy, identifier, msg string) santa.Rule {
	return santa.Rule{RuleType: ruleType, Policy: policy, Identifier: identifier, CustomMessage: msg}
}

var (
	ruleA = rule(santa.Binary, santa.Allowlist, strings.Repeat("a", 64), "")
	ruleB = rule(santa.TeamID, santa.Blocklist, "EQHXZ8M8AV", "no chrome")
	ruleC = rule(santa.SigningID, santa.Allowlist, "EQHXZ8M8AV:com.google.Chrome", "")
	ruleD = rule(santa.Binary, santa.AllowlistCompiler, strings.Repeat("d", 64), "")
	ruleE = rule(santa.CdHash, santa.SilentBlocklist, strings.Repeat("e", 40), "")
)

func lockdown(rules ...santa.Rule) santa.Config {
	return santa.Config{Preflight: santa.Preflight{ClientMode: santa.Lockdown, SyncType: santa.SyncTypeClean, BatchSize: 100}, Rules: rules}
}

// syncFixture builds a service over a generation store with a fake clock and
// captured logs.
func syncFixture(t *testing.T, incremental bool) (*SantaService, *generationStore, *bytes.Buffer, *time.Time) {
	t.Helper()
	store := newGenerationStore()
	store.publish("g1", map[string]santa.Config{"global": lockdown(ruleA, ruleB, ruleC, ruleD)})
	svc, err := NewService(store, t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return now }
	var logs bytes.Buffer
	svc.SetLogger(log.NewLogfmtLogger(&logs))
	svc.SetIncrementalSync(incremental)
	return svc, store, &logs, &now
}

// fullSync runs preflight, rule download and a complete postflight.
func fullSync(t *testing.T, svc *SantaService, machine string, p santa.PreflightPayload) (*santa.Preflight, []santa.Rule) {
	t.Helper()
	ctx := context.Background()
	pre, err := svc.Preflight(ctx, machine, p)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := svc.RuleDownload(ctx, machine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Postflight(ctx, machine, santa.PostflightPayload{SyncType: pre.SyncType, RulesReceived: len(rules), RulesProcessed: len(rules)}); err != nil {
		t.Fatal(err)
	}
	return pre, rules
}

func lastDecision(t *testing.T, logs *bytes.Buffer) (mode, reason string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.Contains(lines[i], "sync_decision=") {
			for _, field := range strings.Fields(lines[i]) {
				if strings.HasPrefix(field, "sync_decision=") {
					mode = strings.TrimPrefix(field, "sync_decision=")
				}
				if strings.HasPrefix(field, "reason=") {
					reason = strings.TrimPrefix(field, "reason=")
				}
			}
			return mode, reason
		}
	}
	t.Fatal("no sync decision logged")
	return
}

var populated = santa.PreflightPayload{BinaryRuleCount: 2, TeamIDRuleCount: 1, SigningIDRuleCount: 1}

func TestIncrementalSyncServesDiff(t *testing.T) {
	svc, store, logs, _ := syncFixture(t, true)
	pre, rules := fullSync(t, svc, "mac-a", santa.PreflightPayload{})
	if pre.SyncType != santa.SyncTypeClean || !pre.CleanSync || len(rules) != 4 {
		t.Fatalf("first contact: %+v %d rules", pre, len(rules))
	}
	if mode, reason := lastDecision(t, logs); mode != decisionClean || reason != "no_acknowledgement" {
		t.Fatal(mode, reason)
	}
	// g2: A unchanged, B changed, C unchanged, D removed, E added.
	changedB := ruleB
	changedB.Policy = santa.SilentBlocklist
	store.publish("g2", map[string]santa.Config{"global": lockdown(ruleA, changedB, ruleC, ruleE)})
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeNormal || pre.CleanSync {
		t.Fatalf("diff sync announced as %+v", pre)
	}
	want := []santa.Rule{{RuleType: santa.Binary, Policy: santa.Remove, Identifier: ruleD.Identifier}, changedB, ruleE}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("diff\n got %+v\nwant %+v", rules, want)
	}
	if mode, reason := lastDecision(t, logs); mode != decisionNormalDiff || reason != "generation_changed" {
		t.Fatal(mode, reason)
	}
	// Same generation again: nothing to send.
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeNormal || len(rules) != 0 {
		t.Fatalf("unchanged: %+v %v", pre, rules)
	}
	if mode, reason := lastDecision(t, logs); mode != decisionNormalUnchanged || reason != "digest_unchanged" {
		t.Fatal(mode, reason)
	}
	// A new generation that only changes preflight settings sends no rules either.
	tweaked := lockdown(ruleA, changedB, ruleC, ruleE)
	tweaked.BatchSize = 50
	store.publish("g3", map[string]santa.Config{"global": tweaked})
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeNormal || pre.BatchSize != 50 || len(rules) != 0 {
		t.Fatalf("settings-only change: %+v %v", pre, rules)
	}
	if mode, reason := lastDecision(t, logs); mode != decisionNormalUnchanged || reason != "rules_unchanged" {
		t.Fatal(mode, reason)
	}
	// The client may always ask for a clean sync.
	pre, rules = fullSync(t, svc, "mac-a", santa.PreflightPayload{RequestCleanSync: true, BinaryRuleCount: 1})
	if pre.SyncType != santa.SyncTypeClean || len(rules) != 4 {
		t.Fatalf("requested clean: %+v %d", pre, len(rules))
	}
	stats := svc.SyncStats()
	if stats.Clean != 2 || stats.NormalDiff != 1 || stats.NormalUnchanged != 2 || stats.Acknowledgements != 1 || !stats.IncrementalSync || stats.LastDecision != decisionClean {
		t.Fatalf("%+v", stats)
	}
	ack, ok := svc.acks.Get("mac-a")
	if !ok || ack.Generation != "g3" || ack.LastCleanAt.IsZero() || ack.ConfigDigest != configDigest(store.generations["g3"]["global"]) {
		t.Fatalf("%+v", ack)
	}
}

func TestDiffRules(t *testing.T) {
	changedB := ruleB
	changedB.CustomMessage = "different text"
	cases := []struct {
		name          string
		before, after []santa.Rule
		want          []santa.Rule
	}{
		{"unchanged", []santa.Rule{ruleA, ruleB}, []santa.Rule{ruleB, ruleA}, nil},
		{"added", []santa.Rule{ruleA}, []santa.Rule{ruleA, ruleE}, []santa.Rule{ruleE}},
		{"removed", []santa.Rule{ruleA, ruleB}, []santa.Rule{ruleA}, []santa.Rule{{RuleType: ruleB.RuleType, Policy: santa.Remove, Identifier: ruleB.Identifier}}},
		{"custom field changed", []santa.Rule{ruleB}, []santa.Rule{changedB}, []santa.Rule{changedB}},
		{"same identifier other type is distinct", []santa.Rule{ruleA}, []santa.Rule{rule(santa.Certificate, santa.Allowlist, ruleA.Identifier, "")},
			[]santa.Rule{{RuleType: santa.Binary, Policy: santa.Remove, Identifier: ruleA.Identifier}, rule(santa.Certificate, santa.Allowlist, ruleA.Identifier, "")}},
		{"removed rule that was already REMOVE", []santa.Rule{rule(santa.Binary, santa.Remove, ruleA.Identifier, "")}, nil, nil},
		{"last duplicate wins", []santa.Rule{ruleA}, []santa.Rule{ruleA, rule(santa.Binary, santa.Blocklist, ruleA.Identifier, "")}, []santa.Rule{rule(santa.Binary, santa.Blocklist, ruleA.Identifier, "")}},
		{"empty to full", nil, []santa.Rule{ruleA, ruleB}, []santa.Rule{ruleA, ruleB}},
	}
	for _, tc := range cases {
		if got := diffRules(tc.before, tc.after); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

func TestIncrementalSyncFallsBackToClean(t *testing.T) {
	svc, store, logs, _ := syncFixture(t, true)
	fullSync(t, svc, "mac-a", santa.PreflightPayload{})

	// Previous generation pruned from disk.
	delete(store.generations, "g1")
	store.publish("g2", map[string]santa.Config{"global": lockdown(ruleA, ruleB, ruleC, ruleD, ruleE)})
	pre, rules := fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeClean || len(rules) != 5 {
		t.Fatalf("%+v %d", pre, len(rules))
	}
	if mode, reason := lastDecision(t, logs); mode != decisionClean || reason != "previous_generation_unavailable" {
		t.Fatal(mode, reason)
	}
	// Diff (5 REMOVEs + 1 add) larger than the new full set (1 rule).
	store.publish("g3", map[string]santa.Config{"global": lockdown(rule(santa.TeamID, santa.Allowlist, "ABCDEFGHIJ", ""))})
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeClean || len(rules) != 1 {
		t.Fatalf("%+v %d", pre, len(rules))
	}
	if mode, reason := lastDecision(t, logs); mode != decisionClean || reason != "diff_larger_than_full" {
		t.Fatal(mode, reason)
	}
	// The stored digest no longer matches what the previous generation contains.
	store.generations["g3"]["global"] = lockdown(ruleE)
	store.publish("g4", map[string]santa.Config{"global": lockdown(ruleE, ruleA)})
	pre, _ = fullSync(t, svc, "mac-a", populated)
	if mode, reason := lastDecision(t, logs); pre.SyncType != santa.SyncTypeClean || mode != decisionClean || reason != "previous_generation_mismatch" {
		t.Fatal(pre.SyncType, mode, reason)
	}
	// A repository without generations (legacy directory) cannot diff.
	svc.repo = &fixtureStore{config: lockdown(ruleA, ruleB)}
	svc.acks.Put(Acknowledgement{MachineID: "mac-a", Generation: "g4", ConfigDigest: "stale", AcknowledgedAt: svc.now()}, true)
	pre, _ = fullSync(t, svc, "mac-a", populated)
	if mode, reason := lastDecision(t, logs); pre.SyncType != santa.SyncTypeClean || mode != decisionClean || reason != "generation_unknown" {
		t.Fatal(pre.SyncType, mode, reason)
	}
}

func TestIncrementalSyncOffKeepsPassthrough(t *testing.T) {
	svc, store, logs, _ := syncFixture(t, false)
	pre, rules := fullSync(t, svc, "mac-a", santa.PreflightPayload{})
	if pre.SyncType != santa.SyncTypeClean || len(rules) != 4 {
		t.Fatalf("%+v %d", pre, len(rules))
	}
	// Unchanged: NORMAL with the full list, as before.
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeNormal || pre.CleanSync || len(rules) != 4 {
		t.Fatalf("%+v %d", pre, len(rules))
	}
	if mode, _ := lastDecision(t, logs); mode != decisionNormalUnchanged {
		t.Fatal(mode)
	}
	// Changed: CLEAN with the full list, never a diff.
	store.publish("g2", map[string]santa.Config{"global": lockdown(ruleA, ruleB, ruleC, ruleE)})
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeClean || len(rules) != 4 || rules[3].Policy == santa.Remove {
		t.Fatalf("%+v %+v", pre, rules)
	}
	if mode, reason := lastDecision(t, logs); mode != decisionClean || reason != "policy_changed" {
		t.Fatal(mode, reason)
	}
	// A TOML without sync_type passes through unchanged on a policy change
	// (today's behaviour) but the safety nets still force CLEAN.
	store.publish("g3", map[string]santa.Config{"global": {Preflight: santa.Preflight{ClientMode: santa.Monitor}, Rules: []santa.Rule{ruleA}}})
	pre, rules = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeUnspecified || pre.CleanSync || len(rules) != 1 {
		t.Fatalf("passthrough lost: %+v %d", pre, len(rules))
	}
	if mode, reason := lastDecision(t, logs); mode != decisionClean || reason != "policy_changed" {
		t.Fatal(mode, reason)
	}
	pre, _ = fullSync(t, svc, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeNormal {
		t.Fatalf("%+v", pre)
	}
	pre, _ = fullSync(t, svc, "mac-a", santa.PreflightPayload{})
	if pre.SyncType != santa.SyncTypeClean || !pre.CleanSync {
		t.Fatalf("safety net did not override the TOML: %+v", pre)
	}
}

func TestPeriodicDitheredClean(t *testing.T) {
	for _, incremental := range []bool{true, false} {
		svc, _, logs, now := syncFixture(t, incremental)
		fullSync(t, svc, "mac-a", santa.PreflightPayload{})
		interval := cleanInterval("mac-a")
		if interval < 7*24*time.Hour || interval > 17*24*time.Hour {
			t.Fatalf("interval %v", interval)
		}
		*now = now.Add(interval - time.Minute)
		pre, _ := fullSync(t, svc, "mac-a", populated)
		if mode, _ := lastDecision(t, logs); pre.SyncType != santa.SyncTypeNormal || mode != decisionNormalUnchanged {
			t.Fatalf("incremental=%v: early clean %+v %s", incremental, pre, mode)
		}
		*now = now.Add(time.Minute)
		pre, rules := fullSync(t, svc, "mac-a", populated)
		if mode, reason := lastDecision(t, logs); pre.SyncType != santa.SyncTypeClean || len(rules) != 4 || mode != decisionClean || reason != "periodic" {
			t.Fatalf("incremental=%v: %+v %d %s %s", incremental, pre, len(rules), mode, reason)
		}
		// The clean restarted the clock: the next sync is NORMAL again until the
		// interval has passed once more.
		pre, _ = fullSync(t, svc, "mac-a", populated)
		if pre.SyncType != santa.SyncTypeNormal {
			t.Fatalf("incremental=%v: clean did not reset the clock: %+v", incremental, pre)
		}
		*now = now.Add(interval)
		pre, _ = fullSync(t, svc, "mac-a", populated)
		if pre.SyncType != santa.SyncTypeClean {
			t.Fatalf("incremental=%v: second periodic clean missing: %+v", incremental, pre)
		}
	}
	// Machines spread over the 11-day window.
	seen := map[time.Duration]bool{}
	for i := 0; i < 200; i++ {
		seen[cleanInterval(fmt.Sprintf("mac-%d", i))] = true
	}
	if len(seen) < 8 {
		t.Fatalf("dither too narrow: %d distinct intervals", len(seen))
	}
}

func TestZeroReportedRulesForcesClean(t *testing.T) {
	for _, incremental := range []bool{true, false} {
		svc, store, logs, _ := syncFixture(t, incremental)
		fullSync(t, svc, "mac-a", santa.PreflightPayload{})
		pre, rules := fullSync(t, svc, "mac-a", santa.PreflightPayload{})
		if mode, reason := lastDecision(t, logs); pre.SyncType != santa.SyncTypeClean || len(rules) != 4 || mode != decisionClean || reason != "zero_rules_reported" {
			t.Fatalf("incremental=%v: %+v %d %s %s", incremental, pre, len(rules), mode, reason)
		}
		// Any single count is enough; transitive rules count too.
		pre, _ = fullSync(t, svc, "mac-a", santa.PreflightPayload{TransitiveRuleCount: 3})
		if pre.SyncType != santa.SyncTypeNormal {
			t.Fatalf("incremental=%v: %+v", incremental, pre)
		}
		// A server with no rules for the machine does not force anything.
		store.publish("g2", map[string]santa.Config{"global": lockdown()})
		fullSync(t, svc, "mac-a", populated)
		pre, _ = fullSync(t, svc, "mac-a", santa.PreflightPayload{})
		if pre.SyncType != santa.SyncTypeNormal {
			t.Fatalf("incremental=%v: %+v", incremental, pre)
		}
	}
}

func TestIncompletePostflightIsNotAcknowledged(t *testing.T) {
	svc, _, logs, _ := syncFixture(t, true)
	ctx := context.Background()
	if _, err := svc.Preflight(ctx, "mac-a", santa.PreflightPayload{}); err != nil {
		t.Fatal(err)
	}
	svc.RuleDownload(ctx, "mac-a")
	if _, err := svc.Postflight(ctx, "mac-a", santa.PostflightPayload{RulesReceived: 4, RulesProcessed: 3}); err != nil {
		t.Fatal(err)
	}
	if svc.acks.Count() != 0 {
		t.Fatal("incomplete sync acknowledged")
	}
	pre, _ := fullSync(t, svc, "mac-a", populated)
	if mode, reason := lastDecision(t, logs); pre.SyncType != santa.SyncTypeClean || reason != "no_acknowledgement" || mode != decisionClean {
		t.Fatal(pre.SyncType, mode, reason)
	}
	// A postflight without a session (restart in mid-sync) is harmless.
	if _, err := svc.Postflight(ctx, "mac-b", santa.PostflightPayload{}); err != nil || svc.acks.Count() != 1 {
		t.Fatal(err, svc.acks.Count())
	}
}

func TestPostflightTelemetryEnvelope(t *testing.T) {
	svc, _, _, _ := syncFixture(t, true)
	dir := t.TempDir()
	q, err := NewOutbox(dir, "http://127.0.0.1:1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	svc.SetOutbox(q)
	ctx := context.Background()
	if _, err := svc.Preflight(ctx, "mac-a", santa.PreflightPayload{RulesHash: "pre-hash", Hostname: "Synthetic"}); err != nil {
		t.Fatal(err)
	}
	svc.RuleDownload(ctx, "mac-a")
	if _, err := svc.Postflight(ctx, "mac-a", santa.PostflightPayload{SyncType: santa.SyncTypeClean, RulesReceived: 4, RulesProcessed: 4, RulesHash: "post-hash"}); err != nil {
		t.Fatal(err)
	}
	// Second sync: incomplete, no rules_hash from postflight, telemetry falls back to the preflight one.
	if _, err := svc.Preflight(ctx, "mac-a", santa.PreflightPayload{RulesHash: "pre-hash-2", BinaryRuleCount: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Postflight(ctx, "mac-a", santa.PostflightPayload{SyncType: santa.SyncTypeNormal, RulesReceived: 1, RulesProcessed: 0}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 4 {
		t.Fatalf("%d batches", len(files))
	}
	var batches []TelemetryBatch
	for _, file := range files {
		data, _ := os.ReadFile(file)
		batch, err := validateBatch(data, filepath.Base(file))
		if err != nil {
			t.Fatal(err)
		}
		batches = append(batches, batch)
	}
	if kinds := strings.Join([]string{batches[0].Kind, batches[1].Kind, batches[2].Kind, batches[3].Kind}, " "); kinds != "preflight postflight preflight postflight" {
		t.Fatal(kinds)
	}
	if batches[0].Preflight.RulesHash != "pre-hash" {
		t.Fatalf("preflight telemetry lacks rules_hash: %+v", batches[0].Preflight)
	}
	first := batches[1]
	if first.MachineID != "mac-a" || first.ReceivedAt == "" || first.Version != 1 {
		t.Fatalf("%+v", first)
	}
	p := first.Postflight
	if p == nil || p.RulesReceived != 4 || p.RulesProcessed != 4 || p.SyncType != santa.SyncTypeClean || p.RulesHash != "post-hash" || p.RulesHashSource != "postflight" ||
		!p.Complete || !p.Acknowledged || p.SyncDecision != decisionClean || p.ServedSyncType != santa.SyncTypeClean || p.RulesServed != 4 ||
		p.AcknowledgedGeneration == nil || p.AcknowledgedGeneration.ManifestGeneration != "g1" || len(p.AcknowledgedGeneration.ConfigDigest) != 64 {
		t.Fatalf("%+v %+v", p, p.AcknowledgedGeneration)
	}
	second := batches[3].Postflight
	if second.Complete || second.Acknowledged || second.RulesHash != "pre-hash-2" || second.RulesHashSource != "preflight" || second.SyncDecision != decisionNormalUnchanged || second.ServedSyncType != santa.SyncTypeNormal || second.RulesServed != 0 {
		t.Fatalf("%+v", second)
	}
	// Exact wire shape for the manager.
	data, _ := os.ReadFile(files[1])
	var wire map[string]interface{}
	json.Unmarshal(data, &wire)
	body := wire["postflight"].(map[string]interface{})
	for _, key := range []string{"rules_received", "rules_processed", "sync_type", "rules_hash", "rules_hash_source", "complete", "acknowledged", "sync_decision", "served_sync_type", "rules_served", "acknowledged_generation"} {
		if _, ok := body[key]; !ok {
			t.Errorf("postflight envelope lacks %s: %s", key, data)
		}
	}
	if body["sync_type"] != "CLEAN" || body["acknowledged_generation"].(map[string]interface{})["manifest_generation"] != "g1" {
		t.Fatalf("%s", data)
	}
	// The outbox accepts the kind after a restart and a full outbox never fails the postflight.
	q.Close()
	q, err = NewOutbox(dir, "http://127.0.0.1:1/", strings.Repeat("a", 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if n, _ := q.Pending(); n != 4 {
		t.Fatalf("%d pending after restart", n)
	}
	svc.SetOutbox(q)
	if _, err := svc.Postflight(ctx, "mac-a", santa.PostflightPayload{}); err != nil {
		t.Fatalf("outbox error failed the postflight: %v", err)
	}
}

func TestAcknowledgementsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acknowledged.json")
	svc, store, logs, _ := syncFixture(t, true)
	acks := OpenAckStore(path)
	svc.SetAckStore(acks)
	fullSync(t, svc, "mac-a", santa.PreflightPayload{})
	if err := acks.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file acknowledgementFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	rec := file.Machines["mac-a"]
	if file.Version != 1 || rec.MachineID != "mac-a" || rec.Generation != "g1" || len(rec.ConfigDigest) != 64 || rec.AcknowledgedAt.IsZero() || rec.LastCleanAt != rec.AcknowledgedAt || rec.SyncType != santa.SyncTypeClean {
		t.Fatalf("%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}

	// "Restart": a new service over the same store and the same policy.
	restarted, err := NewService(store, t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = svc.now
	restarted.SetLogger(log.NewLogfmtLogger(logs))
	restarted.SetIncrementalSync(true)
	reopened := OpenAckStore(path)
	if len(reopened.Warnings()) != 0 || reopened.Count() != 1 {
		t.Fatal(reopened.Warnings(), reopened.Count())
	}
	restarted.SetAckStore(reopened)
	pre, rules := fullSync(t, restarted, "mac-a", populated)
	if mode, _ := lastDecision(t, logs); pre.SyncType != santa.SyncTypeNormal || len(rules) != 0 || mode != decisionNormalUnchanged {
		t.Fatalf("restart forced a clean sync: %+v %d %s", pre, len(rules), mode)
	}
	// ...and a publish after the restart still yields a diff.
	store.publish("g2", map[string]santa.Config{"global": lockdown(ruleA, ruleB, ruleC, ruleD, ruleE)})
	pre, rules = fullSync(t, restarted, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeNormal || len(rules) != 1 || rules[0].Identifier != ruleE.Identifier {
		t.Fatalf("%+v %+v", pre, rules)
	}

	// The operator deletes an entry to force one machine's next sync to be CLEAN.
	old := identityFlushInterval
	identityFlushInterval = 10 * time.Millisecond
	defer func() { identityFlushInterval = old }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reopened.Run(ctx, func(err error) { t.Error(err) })
	}()
	waitFor(t, "flush", func() bool { data, _ := os.ReadFile(path); return strings.Contains(string(data), `"generation": "g2"`) })
	waitFor(t, "adopt operator edit", func() bool {
		writeAtomic(t, path, `{"version":1,"machines":{}}`)
		time.Sleep(3 * identityFlushInterval)
		return reopened.Count() == 0
	})
	cancel()
	<-done
	pre, _ = fullSync(t, restarted, "mac-a", populated)
	if pre.SyncType != santa.SyncTypeClean {
		t.Fatalf("%+v", pre)
	}

	// Corrupt store: quarantined, never fatal, every machine cleans once.
	for _, content := range []string{`{nope`, `{"version":1,"machines":{"mac-a":{"machine_id":"other","config_digest":"x"}}}`, `{"version":1,"machines":{"mac-a":{"machine_id":"mac-a"}}}`} {
		os.WriteFile(path, []byte(content), 0600)
		s := OpenAckStore(path)
		if w := s.Warnings(); len(w) != 1 || !strings.Contains(w[0], "quarantined") || s.Count() != 0 {
			t.Fatalf("%q: %v", content, w)
		}
	}
	if quarantined, _ := filepath.Glob(path + ".corrupt-*"); len(quarantined) < 1 {
		t.Fatal("no quarantine file")
	}
	// In-memory store: Run just waits, Flush is a no-op.
	memory := OpenAckStore("")
	memory.Put(Acknowledgement{MachineID: "mac-z", ConfigDigest: "d", AcknowledgedAt: time.Now()}, true)
	if err := memory.Flush(); err != nil || memory.Count() != 1 {
		t.Fatal(err)
	}
}

func TestInvalidEventsAreSkippedNotRejected(t *testing.T) {
	svc, _, _, _ := syncFixture(t, false)
	dir := t.TempDir()
	q, err := NewOutbox(dir, "http://127.0.0.1:1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	svc.SetOutbox(q)
	router := mux.NewRouter()
	router.Use(ClientGuard(nil, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	root := http.NewServeMux()
	root.Handle("/healthz", HealthHandler(fixturePolicy{generation: "g", loaded: true}, q, AuthStatus{}, svc))
	root.Handle("/", router)
	good := strings.Repeat("a", 64)
	body := `{"events":[{"file_sha256":"not-a-hash","file_name":"bad"},{"file_sha256":"` + good + `","file_name":"good","file_bundle_name":"Zoom","signing_status":"SIGNING_STATUS_PRODUCTION","static_rule":true,"entitlement_info":{"entitlements_filtered":false,"entitlements":[]}},{"file_sha256":"","file_name":"empty"}]}`
	r := httptest.NewRequest(http.MethodPost, "/v1/santa/eventupload/mac-a", strings.NewReader(body))
	r.Header.Set("Content-Encoding", "identity")
	w := httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("%d batches", len(files))
	}
	data, _ := os.ReadFile(files[0])
	var batch TelemetryBatch
	json.Unmarshal(data, &batch)
	if len(batch.Events) != 1 || batch.Events[0].FileName != "good" || batch.Events[0].FileBundleName != "Zoom" || !batch.Events[0].StaticRule || string(batch.Events[0].EntitlementInfo) == "" {
		t.Fatalf("%s", data)
	}
	if svc.SyncStats().InvalidEventsSkipped != 2 {
		t.Fatalf("%+v", svc.SyncStats())
	}
	// A batch of only invalid events is acknowledged without a telemetry batch.
	r = httptest.NewRequest(http.MethodPost, "/v1/santa/eventupload/mac-a", strings.NewReader(`{"events":[{"file_sha256":"zz"}]}`))
	r.Header.Set("Content-Encoding", "identity")
	w = httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if n, _ := q.Pending(); n != 1 {
		t.Fatal(n)
	}
	// Health reports the sync block.
	w = httptest.NewRecorder()
	root.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var health map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &health)
	sync := health["sync"].(map[string]interface{})
	if sync["invalid_events_skipped"] != 3.0 || sync["acknowledgements"] != 0.0 || sync["incremental_sync"] != false || sync["clean"] != 0.0 {
		t.Fatalf("%v", health)
	}
	fullSync(t, svc, "mac-a", santa.PreflightPayload{})
	w = httptest.NewRecorder()
	root.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	json.Unmarshal(w.Body.Bytes(), &health)
	sync = health["sync"].(map[string]interface{})
	if sync["acknowledgements"] != 1.0 || sync["clean"] != 1.0 || sync["last_decision"] != "clean" {
		t.Fatalf("%v", sync)
	}
}

func TestEventSanitisation(t *testing.T) {
	long := strings.Repeat("é", 1000) // 2000 bytes
	chain := make([]santa.SigningEntry, 12)
	ev := santa.EventUploadEvent{FileName: long, FilePath: "/ok", LoggedInUsers: make([]string, 40), SigningChain: chain,
		EntitlementInfo: json.RawMessage(`{"entitlements":[{"key":"` + strings.Repeat("k", 20000) + `"}]}`)}
	sanitizeEvent(&ev)
	if len(ev.FileName) > maxEventString || !strings.HasSuffix(ev.FileName, "é") || ev.FilePath != "/ok" {
		t.Fatalf("%d %q", len(ev.FileName), ev.FileName[len(ev.FileName)-4:])
	}
	if len(ev.LoggedInUsers) != maxEventList || len(ev.SigningChain) != maxSigningChain || string(ev.EntitlementInfo) != entitlementsTooLarge {
		t.Fatalf("%d %d %s", len(ev.LoggedInUsers), len(ev.SigningChain), ev.EntitlementInfo)
	}
	// A STANDALONE client and CLEAN_STANDALONE postflight must not be rejected.
	svc, _, _, _ := syncFixture(t, false)
	router := mux.NewRouter()
	router.Use(ClientGuard(nil, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	for path, body := range map[string]string{"preflight": `{"client_mode":"STANDALONE","rules_hash":"abc","sip_status":127,"primary_user_groups":["staff"],"push_notification_sync":false}`, "postflight": `{"sync_type":"CLEAN_STANDALONE","rules_received":1,"rules_processed":1,"rules_hash":"abc"}`} {
		r := httptest.NewRequest(http.MethodPost, "/v1/santa/"+path+"/mac-a", strings.NewReader(body))
		r.Header.Set("Content-Encoding", "identity")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
