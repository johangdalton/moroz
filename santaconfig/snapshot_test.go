package santaconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
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
