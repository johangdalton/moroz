package moroz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/groob/moroz/santa"
)

// GenerationStore is implemented by policy repositories that keep earlier
// generations on disk (santaconfig.FileRepo in manifest mode). It is optional:
// without it the server always falls back to CLEAN when a machine's policy
// changed.
type GenerationStore interface {
	// EffectiveConfig returns the machine's config (its own or global) and the
	// manifest generation id of the snapshot it came from ("" if unknown).
	EffectiveConfig(ctx context.Context, machineID string) (santa.Config, string, error)
	// HistoricConfig returns the machine's effective config in an earlier
	// generation, or an error when that generation is no longer available.
	HistoricConfig(ctx context.Context, generation, machineID string) (santa.Config, error)
}

// Sync decision modes, logged as sync_decision=... and counted on /healthz.
const (
	decisionClean           = "clean"
	decisionNormalDiff      = "normal-diff"
	decisionNormalUnchanged = "normal-unchanged"
)

// sessionTTL bounds how long a preflight's pinned snapshot is served.
const sessionTTL = 15 * time.Minute

// mismatchCleanBackoff limits rule_count_mismatch CLEAN syncs to one per
// machine per hour, so a rule Santa keeps rejecting cannot force a CLEAN on
// every sync.
const mismatchCleanBackoff = time.Hour

// reportedRules is the number of server-delivered execution rules in the
// client's database. Santa counts BINARY, CERTIFICATE, TEAMID, SIGNINGID and
// CDHASH rules by type and transitive rules by state (they are also one of
// those types); compiler_rule_count is a state count that overlaps the type
// counts and is left out (SNTRuleTable.mm, Santa 2026.7).
func reportedRules(p santa.PreflightPayload) int {
	return p.BinaryRuleCount + p.CertificateRuleCount + p.TeamIDRuleCount + p.SigningIDRuleCount + p.CdHashRuleCount - p.TransitiveRuleCount
}

// expectedRules is the number of rules Santa keeps after applying rules:
// one per rule_type + identifier, the last entry winning, REMOVE dropping it.
func expectedRules(rules []santa.Rule) int {
	effective := make(map[ruleKey]bool, len(rules))
	for _, r := range rules {
		effective[ruleKey{r.RuleType, r.Identifier}] = r.Policy != santa.Remove
	}
	n := 0
	for _, kept := range effective {
		if kept {
			n++
		}
	}
	return n
}

// syncSession pins the snapshot chosen at preflight until postflight so a
// policy publish in the middle of a sync cannot mix generations.
type syncSession struct {
	config     santa.Config
	digest     string
	generation string
	rules      []santa.Rule
	decision   string
	reason     string
	clean      bool
	rulesHash  string
	expires    time.Time
}

// syncDecision is the outcome of the preflight decision.
type syncDecision struct {
	mode, reason       string
	clean              bool
	rules              []santa.Rule
	previousGeneration string
}

// configDigest identifies one machine's effective config across restarts.
func configDigest(config santa.Config) string {
	encoded, _ := json.Marshal(config)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// decide chooses between CLEAN and NORMAL for this preflight. The safety nets
// (client request, no acknowledgement, periodic dithered CLEAN, zero reported
// rules, a reported rule count that differs from the acknowledged policy)
// apply regardless of the incremental-sync flag. With the flag off a
// changed policy is always a CLEAN sync with the full list, and an unchanged
// one a NORMAL sync with the full list (historic passthrough). With the flag
// on the TOML's sync_type is ignored and a changed policy becomes a NORMAL
// sync carrying only the diff, falling back to CLEAN when the previous
// generation cannot be reconstructed or the diff is not smaller.
func (svc *SantaService) decide(ctx context.Context, machine string, config santa.Config, generation, digest string, p santa.PreflightPayload, now time.Time) syncDecision {
	full := syncDecision{mode: decisionClean, clean: true, rules: config.Rules}
	previous, acknowledged := svc.acks.Get(machine)
	full.previousGeneration = previous.Generation
	switch {
	case p.RequestCleanSync:
		full.reason = "client_requested"
		return full
	case !acknowledged:
		full.reason = "no_acknowledgement"
		return full
	case cleanDue(previous, now):
		full.reason = "periodic"
		return full
	case p.TotalRuleCount() == 0 && len(config.Rules) > 0:
		full.reason = "zero_rules_reported"
		return full
	case previous.ConfigDigest == digest && reportedRules(p) != expectedRules(config.Rules) && now.Sub(previous.LastCleanAt) >= mismatchCleanBackoff:
		full.reason = "rule_count_mismatch"
		return full
	case previous.ConfigDigest == digest:
		unchanged := syncDecision{mode: decisionNormalUnchanged, reason: "digest_unchanged", previousGeneration: previous.Generation}
		if !svc.incremental {
			unchanged.rules = config.Rules
		}
		return unchanged
	case !svc.incremental:
		full.reason = "policy_changed"
		return full
	}
	store, ok := svc.repo.(GenerationStore)
	if !ok || previous.Generation == "" || generation == "" {
		full.reason = "generation_unknown"
		return full
	}
	if previous.Generation == generation {
		// Same generation but a different digest: the file changed under an
		// existing generation, which the manager never does. Do not guess.
		full.reason = "generation_reused"
		return full
	}
	before, err := store.HistoricConfig(ctx, previous.Generation, machine)
	if err != nil {
		full.reason = "previous_generation_unavailable"
		return full
	}
	if configDigest(before) != previous.ConfigDigest {
		full.reason = "previous_generation_mismatch"
		return full
	}
	diff := diffRules(before.Rules, config.Rules)
	if len(diff) > len(config.Rules) {
		full.reason = "diff_larger_than_full"
		return full
	}
	if len(diff) == 0 {
		return syncDecision{mode: decisionNormalUnchanged, reason: "rules_unchanged", previousGeneration: previous.Generation}
	}
	return syncDecision{mode: decisionNormalDiff, reason: "generation_changed", rules: diff, previousGeneration: previous.Generation}
}

type ruleKey struct {
	ruleType   santa.RuleType
	identifier string
}

// diffRules returns the rules Santa must apply to move from before to after:
// a REMOVE for every rule that disappeared, and every added or changed rule
// as it appears in after. Within one list the last rule for a rule_type +
// identifier wins, as in Santa. Rules that were already REMOVE in before are
// not removed again.
func diffRules(before, after []santa.Rule) []santa.Rule {
	index := func(rules []santa.Rule) map[ruleKey]santa.Rule {
		m := make(map[ruleKey]santa.Rule, len(rules))
		for _, r := range rules {
			m[ruleKey{r.RuleType, r.Identifier}] = r
		}
		return m
	}
	old, current := index(before), index(after)
	var diff []santa.Rule
	for _, r := range before {
		key := ruleKey{r.RuleType, r.Identifier}
		if _, kept := current[key]; kept || old[key].Policy == santa.Remove {
			continue
		}
		if len(diff) > 0 && diff[len(diff)-1].RuleType == r.RuleType && diff[len(diff)-1].Identifier == r.Identifier {
			continue // duplicate entry in before
		}
		diff = append(diff, santa.Rule{RuleType: r.RuleType, Policy: santa.Remove, Identifier: r.Identifier})
	}
	emitted := make(map[ruleKey]bool)
	for _, r := range after {
		key := ruleKey{r.RuleType, r.Identifier}
		if emitted[key] {
			continue
		}
		effective := current[key]
		if previous, existed := old[key]; existed && reflect.DeepEqual(previous, effective) {
			continue
		}
		emitted[key] = true
		diff = append(diff, effective)
	}
	return diff
}

// beginSync records the decision as the machine's session and returns the
// preflight response to send.
func (svc *SantaService) beginSync(ctx context.Context, machine string, config santa.Config, generation string, p santa.PreflightPayload) santa.Preflight {
	now := svc.now()
	digest := configDigest(config)
	decision := svc.decide(ctx, machine, config, generation, digest, p, now)
	rules := decision.rules
	if rules == nil {
		rules = []santa.Rule{}
	}
	pre := config.Preflight
	switch {
	case decision.clean && !svc.incremental && decision.reason == "policy_changed":
		// Historic passthrough: the TOML's sync_type decides (the manager
		// writes CLEAN); the full list is served either way.
	case decision.clean:
		pre.SyncType = santa.SyncTypeClean
		pre.CleanSync = true
	default:
		pre.SyncType = santa.SyncTypeNormal
		pre.CleanSync = false
	}
	announcedClean := pre.SyncType.IsClean() || pre.CleanSync
	session := syncSession{config: config, digest: digest, generation: generation, rules: rules, decision: decision.mode, reason: decision.reason, clean: announcedClean, rulesHash: p.RulesHash, expires: now.Add(sessionTTL)}
	svc.sessionMu.Lock()
	for id, s := range svc.sessions {
		if now.After(s.expires) {
			delete(svc.sessions, id)
		}
	}
	svc.sessions[machine] = session
	svc.sessionMu.Unlock()
	svc.countDecision(decision.mode)
	level.Info(svc.logger).Log("msg", "sync decision", "machine_id", machine, "sync_decision", decision.mode, "reason", decision.reason,
		"sync_type", textOf(pre.SyncType), "rules", len(rules), "generation", generation, "previous_generation", decision.previousGeneration, "incremental_sync", svc.incremental)
	return pre
}

func (svc *SantaService) session(machine string) (syncSession, bool) {
	svc.sessionMu.Lock()
	defer svc.sessionMu.Unlock()
	s, ok := svc.sessions[machine]
	if ok && svc.now().Before(s.expires) {
		return s, true
	}
	delete(svc.sessions, machine)
	return syncSession{}, false
}

// sessionConfig returns the snapshot pinned at preflight, if still valid.
func (svc *SantaService) sessionConfig(machine string) (santa.Config, bool) {
	s, ok := svc.session(machine)
	return s.config, ok
}

// finishSync closes the session and, when the client reports every received
// rule as processed, records the acknowledgement. An incomplete sync leaves
// the previous acknowledgement in place so the next sync is CLEAN again.
// It returns the session and whether the acknowledgement was recorded.
func (svc *SantaService) finishSync(machine string, p santa.PostflightPayload) (syncSession, bool) {
	svc.sessionMu.Lock()
	s, ok := svc.sessions[machine]
	if ok && !svc.now().Before(s.expires) {
		ok = false
	}
	delete(svc.sessions, machine)
	svc.sessionMu.Unlock()
	if !ok || p.RulesReceived != p.RulesProcessed {
		return s, false
	}
	now := svc.now().UTC()
	svc.acks.Put(Acknowledgement{MachineID: machine, Generation: s.generation, ConfigDigest: s.digest, SyncType: p.SyncType, RulesHash: p.RulesHash, AcknowledgedAt: now}, s.clean || p.SyncType.IsClean())
	return s, true
}
