package moroz

import (
	"encoding/binary"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/groob/moroz/santa"
	"github.com/zeebo/xxh3"
)

// Santa's rule type and state numbers (SNTCommonEnums.h, Santa 2026.7).
var (
	santaRuleTypes  = map[santa.RuleType]int32{santa.CdHash: 500, santa.Binary: 1000, santa.SigningID: 2000, santa.Certificate: 3000, santa.TeamID: 4000}
	santaRuleStates = map[santa.Policy]int32{santa.Allowlist: 1, santa.Blocklist: 2, santa.SilentBlocklist: 3,
		santa.AllowlistCompiler: 5, santa.SilentGuiBlocklist: 12, santa.SilentTtyBlocklist: 13}
)

// SantaRulesHash returns the rules_hash Santa reports after a CLEAN sync that
// delivered rules in this order, or "" when it cannot be predicted (a CEL
// rule, whose stored state depends on the client, or an unknown type).
//
// Santa hashes its execution_rules table in row order with XXH3-128 over
// identifier, cel_expr, seatbelt_policy, state and type, skipping transitive
// rules (SNTRuleTable.mm executionRulesHashSerialized). Rows are written with
// INSERT OR REPLACE, so a rule moves to the end each time it is written and a
// REMOVE deletes it. The order matters: the same rules applied incrementally
// hash differently, which is why only CLEAN syncs are verified against this.
func SantaRulesHash(rules []santa.Rule) string {
	type key struct {
		ruleType   santa.RuleType
		identifier string
	}
	var order []key
	rows := make(map[key]santa.Rule, len(rules))
	for _, r := range rules {
		k := key{r.RuleType, r.Identifier}
		if _, ok := rows[k]; ok {
			delete(rows, k)
			for i := range order {
				if order[i] == k {
					order = append(order[:i], order[i+1:]...)
					break
				}
			}
		}
		if r.Policy == santa.Remove {
			continue
		}
		if _, ok := santaRuleStates[r.Policy]; !ok {
			return ""
		}
		if _, ok := santaRuleTypes[r.RuleType]; !ok {
			return ""
		}
		rows[k] = r
		order = append(order, k)
	}
	h := xxh3.New()
	var n [4]byte
	for _, k := range order {
		r := rows[k]
		h.Write([]byte(r.Identifier))
		h.Write([]byte(r.CelExpr))
		binary.LittleEndian.PutUint32(n[:], uint32(santaRuleStates[r.Policy]))
		h.Write(n[:])
		binary.LittleEndian.PutUint32(n[:], uint32(santaRuleTypes[r.RuleType]))
		h.Write(n[:])
	}
	sum := h.Sum128().Bytes()
	return hex.EncodeToString(sum[:])
}

// Rules hash finding kinds.
const (
	// hashChanged: the hash a machine reports at preflight differs from the one
	// it reported at its last acknowledged postflight, so its rules changed
	// outside a sync.
	hashChanged = "changed_between_syncs"
	// hashCleanMismatch: after a complete CLEAN sync the reported hash is not
	// the hash of the rules that were served.
	hashCleanMismatch = "clean_mismatch"
)

// HashFinding is one machine whose reported rules hash failed a check. It is
// reported on /healthz, and forces a CLEAN at most once an hour, until a CLEAN
// sync of that machine verifies.
type HashFinding struct {
	MachineID string    `json:"machine_id"`
	Kind      string    `json:"kind"`
	Expected  string    `json:"expected"`
	Reported  string    `json:"reported"`
	At        time.Time `json:"at"`
}

// hashFindings is in memory only: a restart forgets open findings, and the
// next CLEAN sync of each machine verifies it again.
type hashFindings struct {
	mu       sync.Mutex
	open     map[string]HashFinding
	verified int64
}

func (f *hashFindings) record(finding HashFinding) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.open == nil {
		f.open = make(map[string]HashFinding)
	}
	f.open[finding.MachineID] = finding
}

func (f *hashFindings) verify(machine string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.open, machine)
	f.verified++
}

func (f *hashFindings) has(machine string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.open[machine]
	return ok
}

func (f *hashFindings) snapshot() ([]HashFinding, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := make([]HashFinding, 0, len(f.open))
	for _, finding := range f.open {
		list = append(list, finding)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].MachineID < list[j].MachineID })
	return list, f.verified
}

// checkPreflightHash compares the hash a machine reports now with the one it
// reported when it last acknowledged a sync. It runs before decide, so a
// finding turns this same sync into a CLEAN (rules_hash_mismatch).
func (svc *SantaService) checkPreflightHash(machine string, p santa.PreflightPayload) {
	previous, ok := svc.acks.Get(machine)
	if !ok || previous.RulesHash == "" || p.RulesHash == "" || previous.RulesHash == p.RulesHash {
		return
	}
	svc.hashes.record(HashFinding{MachineID: machine, Kind: hashChanged, Expected: previous.RulesHash, Reported: p.RulesHash, At: svc.now().UTC()})
	level.Warn(svc.logger).Log("msg", "rules hash changed between syncs", "machine_id", machine, "acknowledged_hash", previous.RulesHash, "reported_hash", p.RulesHash)
}

// checkCleanHash verifies a complete CLEAN sync: the client database now holds
// exactly the served rules in the served order.
func (svc *SantaService) checkCleanHash(machine string, session syncSession, p santa.PostflightPayload) {
	if !session.clean || p.RulesHash == "" || p.RulesReceived != len(session.rules) {
		return
	}
	expected := SantaRulesHash(session.rules)
	if expected == "" {
		return
	}
	if expected == p.RulesHash {
		svc.hashes.verify(machine)
		return
	}
	svc.hashes.record(HashFinding{MachineID: machine, Kind: hashCleanMismatch, Expected: expected, Reported: p.RulesHash, At: svc.now().UTC()})
	level.Warn(svc.logger).Log("msg", "rules hash after CLEAN sync does not match served rules", "machine_id", machine, "expected_hash", expected, "reported_hash", p.RulesHash, "rules", len(session.rules))
}
