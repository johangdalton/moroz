package santaconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/groob/moroz/santa"
)

func fixture(t *testing.T, root, generation, policy string) {
	t.Helper()
	dir := filepath.Join(root, "generations", generation)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	body := []byte("client_mode = \"MONITOR\"\nbatch_size = 100\n[[rules]]\nrule_type = \"BINARY\"\npolicy = \"" + policy + "\"\nidentifier = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n")
	if err := os.WriteFile(filepath.Join(dir, "global.toml"), body, 0644); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(manifest{Version: 1, Generation: generation, Files: []string{"global.toml"}})
	if err := os.WriteFile(filepath.Join(root, "next.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "next.json"), filepath.Join(root, "current.json")); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotCachesAndRetainsLastValidPolicy(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	fixture(t, root, "first", "BLOCKLIST")
	repo := NewFileRepo(root)
	first, err := repo.Config(ctx, "global")
	if err != nil {
		t.Fatal(err)
	}
	// Requests must use memory even if the underlying policy file is unavailable.
	if err := os.Remove(filepath.Join(root, "generations", "first", "global.toml")); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Config(ctx, "global"); err != nil {
		t.Fatalf("lookup read disk: %v", err)
	}
	fixture(t, root, "invalid", "INVALID_POLICY")
	if err := repo.Reload(ctx); err == nil {
		t.Fatal("invalid policy was accepted")
	}
	current, err := repo.Config(ctx, "global")
	if err != nil {
		t.Fatal(err)
	}
	if current.Rules[0].Policy != first.Rules[0].Policy {
		t.Fatal("failed reload changed active policy")
	}
	fixture(t, root, "next", "ALLOWLIST")
	if err := repo.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	current, _ = repo.Config(ctx, "global")
	if current.Rules[0].Policy == first.Rules[0].Policy {
		t.Fatal("valid reload was not applied")
	}
}

func TestConcurrentReadsDuringReload(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	fixture(t, root, "first", "BLOCKLIST")
	repo := NewFileRepo(root)
	if err := repo.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c, err := repo.Config(ctx, "global")
				if err != nil || len(c.Rules) != 1 {
					t.Errorf("incomplete snapshot: %v", err)
					return
				}
			}
		}()
	}
	fixture(t, root, "second", "ALLOWLIST")
	if err := repo.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestManifestRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	data := []byte(`{"version":1,"generation":"../outside","files":["global.toml"]}`)
	if err := os.WriteFile(filepath.Join(root, "current.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := NewFileRepo(root).Reload(context.Background()); err == nil {
		t.Fatal("unsafe generation accepted")
	}
}

func TestLegacyConfigStillLoads(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "global.toml"), []byte("client_mode=\"MONITOR\"\nbatch_size=100\n"), 0644); err != nil {
		t.Fatal(err)
	}
	c, err := NewFileRepo(root).Config(context.Background(), "global")
	if err != nil || c.BatchSize != 100 {
		t.Fatalf("legacy config failed: %v", err)
	}
}

func writeLegacy(t *testing.T, root, body string) *FileRepo {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "global.toml"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return NewFileRepo(root)
}

func TestUnknownKeysAreRejected(t *testing.T) {
	// The README's former sample used sha256 instead of identifier, which
	// silently produced a rule with an empty identifier.
	body := "client_mode = \"MONITOR\"\nbatch_size = 100\n[[rules]]\nrule_type = \"BINARY\"\npolicy = \"BLOCKLIST\"\nsha256 = \"" + strings.Repeat("a", 64) + "\"\n"
	err := writeLegacy(t, t.TempDir(), body).Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "global.toml") || !strings.Contains(err.Error(), "rules.sha256") {
		t.Fatalf("unknown key accepted: %v", err)
	}
	err = writeLegacy(t, t.TempDir(), "client_mode = \"MONITOR\"\nbatch_sizes = 100\n").Reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "batch_sizes") {
		t.Fatalf("unknown top-level key accepted: %v", err)
	}
}

func TestRuleValidation(t *testing.T) {
	rule := func(ruleType, policy, identifier string) string {
		return "client_mode = \"MONITOR\"\n[[rules]]\nrule_type = \"" + ruleType + "\"\npolicy = \"" + policy + "\"\nidentifier = \"" + identifier + "\"\n"
	}
	sha := strings.Repeat("ab", 32)
	valid := []string{
		rule("BINARY", "BLOCKLIST", sha),
		rule("CERTIFICATE", "ALLOWLIST", strings.ToUpper(sha)),
		rule("CDHASH", "SILENT_BLOCKLIST", strings.Repeat("0f", 20)),
		rule("TEAMID", "ALLOWLIST", "EQHXZ8M8AV"),
		rule("SIGNINGID", "ALLOWLIST", "EQHXZ8M8AV:com.google.Chrome"),
		rule("SIGNINGID", "BLOCKLIST", "platform:com.apple.BluetoothFileExchange"),
		rule("BINARY", "REMOVE", sha),
	}
	for i, body := range valid {
		repo := writeLegacy(t, t.TempDir(), body)
		if err := repo.Reload(context.Background()); err != nil {
			t.Fatalf("valid rule %d rejected: %v", i, err)
		}
		c, _ := repo.Config(context.Background(), "global")
		if c.Rules[0].Identifier != strings.ToLower(c.Rules[0].Identifier) && c.Rules[0].RuleType != santa.TeamID && c.Rules[0].RuleType != santa.SigningID {
			t.Fatalf("hex identifier not normalised: %q", c.Rules[0].Identifier)
		}
	}
	invalid := map[string]string{
		"missing rule_type":       "client_mode = \"MONITOR\"\n[[rules]]\npolicy = \"BLOCKLIST\"\nidentifier = \"" + sha + "\"\n",
		"missing policy":          "client_mode = \"MONITOR\"\n[[rules]]\nrule_type = \"BINARY\"\nidentifier = \"" + sha + "\"\n",
		"missing identifier":      "client_mode = \"MONITOR\"\n[[rules]]\nrule_type = \"BINARY\"\npolicy = \"BLOCKLIST\"\n",
		"unknown rule_type":       rule("RULETYPE_UNKNOWN", "BLOCKLIST", sha),
		"unknown policy":          rule("BINARY", "POLICY_UNKNOWN", sha),
		"short binary hash":       rule("BINARY", "BLOCKLIST", sha[:63]),
		"non-hex certificate":     rule("CERTIFICATE", "BLOCKLIST", strings.Repeat("g", 64)),
		"sha256 as cdhash":        rule("CDHASH", "BLOCKLIST", sha),
		"lowercase team id":       rule("TEAMID", "ALLOWLIST", "eqhxz8m8av"),
		"short team id":           rule("TEAMID", "ALLOWLIST", "EQHXZ8M8A"),
		"signing id without team": rule("SIGNINGID", "ALLOWLIST", "com.google.Chrome"),
		"signing id with space":   rule("SIGNINGID", "ALLOWLIST", "EQHXZ8M8AV:com.google Chrome"),
		"signing id with colon":   rule("SIGNINGID", "ALLOWLIST", "EQHXZ8M8AV:com:google"),
		"signing id empty suffix": rule("SIGNINGID", "ALLOWLIST", "EQHXZ8M8AV:"),
		"signing id bad platform": rule("SIGNINGID", "ALLOWLIST", "Platform:com.apple.ls"),
	}
	for name, body := range invalid {
		err := writeLegacy(t, t.TempDir(), body).Reload(context.Background())
		if err == nil || !strings.Contains(err.Error(), "global.toml") {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

// A validation failure keeps the previous snapshot, exactly like a parse error.
func TestInvalidRuleRetainsPreviousSnapshot(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	fixture(t, root, "first", "BLOCKLIST")
	repo := NewFileRepo(root)
	if err := repo.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "generations", "second")
	os.MkdirAll(dir, 0755)
	os.WriteFile(filepath.Join(dir, "global.toml"), []byte("client_mode = \"MONITOR\"\n[[rules]]\nrule_type = \"TEAMID\"\npolicy = \"ALLOWLIST\"\nidentifier = \"tooshort\"\n"), 0644)
	data, _ := json.Marshal(manifest{Version: 1, Generation: "second", Files: []string{"global.toml"}})
	os.WriteFile(filepath.Join(root, "current.json"), data, 0644)
	if err := repo.Reload(ctx); err == nil {
		t.Fatal("invalid identifier accepted")
	}
	c, err := repo.Config(ctx, "global")
	if err != nil || c.Rules[0].Policy != santa.Blocklist {
		t.Fatalf("previous snapshot lost: %v %+v", err, c.Rules)
	}
	if generation, ok := repo.Generation(); !ok || !strings.HasPrefix(generation, "manifest:") {
		t.Fatalf("generation %q %v", generation, ok)
	}
}

func TestExampleConfigValidates(t *testing.T) {
	c, err := NewFileRepo("../configs").Config(context.Background(), "global")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) < 4 {
		t.Fatalf("expected the sample rules, got %d", len(c.Rules))
	}
}

func TestThrottleErrors(t *testing.T) {
	var logged []string
	var repeats []int
	now := time.Unix(1_700_000_000, 0)
	report := throttleErrors(5*time.Minute, func(err error, n int) {
		logged = append(logged, err.Error())
		repeats = append(repeats, n)
	}, func() time.Time { return now })
	for i := 0; i < 100; i++ {
		report(errors.New("decode global.toml: broken"))
		now = now.Add(time.Second)
	}
	report(errors.New("different failure"))
	now = now.Add(4 * time.Minute)
	report(errors.New("different failure"))
	now = now.Add(time.Minute)
	report(errors.New("different failure"))
	want := []string{"decode global.toml: broken", "different failure", "different failure"}
	if strings.Join(logged, "|") != strings.Join(want, "|") {
		t.Fatalf("logged %v", logged)
	}
	if repeats[0] != 0 || repeats[1] != 99 || repeats[2] != 1 {
		t.Fatalf("suppressed counts %v", repeats)
	}
}
