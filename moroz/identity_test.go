package moroz

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/groob/moroz/santa"
)

func TestIdentityBindingOnFirstPreflight(t *testing.T) {
	svc, _ := fixtureService(t)
	path := filepath.Join(t.TempDir(), "identities.json")
	store := OpenIdentityStore(path)
	svc.SetIdentityStore(store)
	var refused []string
	svc.SetAuthErrorLogger(func(err error) { refused = append(refused, err.Error()) })
	creds := mustStatic(t, map[string]string{"mac-a": machineTokenA}, []FleetToken{{Name: "pilot-2026", Token: fleetToken1}})
	h := guardedRouter(t, svc, GuardOptions{Credentials: creds}, nil)

	// No serial: accepted, not bound.
	if w := post(h, "/v1/santa/preflight/mac-a", machineTokenA, `{}`); w.Code != 200 || store.Count() != 0 {
		t.Fatalf("%d count=%d", w.Code, store.Count())
	}
	if w := post(h, "/v1/santa/preflight/mac-a", machineTokenA, `{"serial_num":"C02AAA"}`); w.Code != 200 || store.Count() != 1 {
		t.Fatalf("%d count=%d", w.Code, store.Count())
	}
	svc.finishSync("mac-a", santa.PostflightPayload{})
	// Same serial keeps working, also through a fleet token.
	if w := post(h, "/v1/santa/preflight/mac-a", fleetToken1, `{"serial_num":"C02AAA"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	svc.finishSync("mac-a", santa.PostflightPayload{})
	w := post(h, "/v1/santa/preflight/mac-a", machineTokenA, `{"serial_num":"C02BBB"}`)
	if w.Code != 403 {
		t.Fatalf("mismatch returned %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || body["error"] != "identity mismatch" || len(body) != 1 {
		t.Fatalf("%s", w.Body.String())
	}
	if _, ok := svc.sessionConfig("mac-a"); ok {
		t.Fatal("sync session started for a mismatching machine")
	}
	if store.Mismatches() != 1 || len(refused) != 1 || !strings.Contains(refused[0], "C02AAA") || !strings.Contains(refused[0], "C02BBB") {
		t.Fatalf("mismatches=%d refused=%v", store.Mismatches(), refused)
	}
	// The other routes only need authentication; identity is checked where
	// the serial is reported.
	if w := post(h, "/v1/santa/ruledownload/mac-a", machineTokenA, ""); w.Code != 200 {
		t.Fatalf("rule download %d", w.Code)
	}
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file identityFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	rec := file.Machines["mac-a"]
	if file.Version != 1 || rec.MachineID != "mac-a" || rec.SerialNum != "C02AAA" || rec.LastAuth != "fleet:pilot-2026" || rec.FirstSeen.IsZero() || rec.LastSeen.Before(rec.FirstSeen) {
		t.Fatalf("%s", data)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", info.Mode())
	}
	// A restart reads the binding back.
	again := OpenIdentityStore(path)
	if again.Count() != 1 || len(again.Warnings()) != 0 {
		t.Fatalf("count=%d warnings=%v", again.Count(), again.Warnings())
	}
	if err := again.Bind("mac-a", "C02BBB", AuthMachine, time.Now()); err == nil {
		t.Fatal("reloaded store accepted a different serial")
	}
}

func TestIdentityStoreCoalescedWritesAndOperatorReset(t *testing.T) {
	old := identityFlushInterval
	identityFlushInterval = 10 * time.Millisecond
	defer func() { identityFlushInterval = old }()
	path := filepath.Join(t.TempDir(), "identities.json")
	store := OpenIdentityStore(path)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		store.Run(ctx, func(err error) { t.Error(err) })
	}()
	for i := 0; i < 50; i++ {
		if err := store.Bind("mac-a", "C02AAA", AuthMachine, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "first write", func() bool { _, err := os.Stat(path); return err == nil })
	// The operator deletes the entry (atomically) to rebind the machine.
	waitFor(t, "adopt operator edit", func() bool {
		writeAtomic(t, path, `{"version":1,"machines":{}}`)
		time.Sleep(3 * identityFlushInterval)
		return store.Count() == 0
	})
	if err := store.Bind("mac-a", "C02BBB", AuthMachine, time.Now()); err != nil {
		t.Fatalf("rebinding after reset failed: %v", err)
	}
	cancel()
	<-done
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"serial_num": "C02BBB"`) {
		t.Fatalf("final flush missing: %s", data)
	}
	if entries, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".identities-*")); len(entries) != 0 {
		t.Fatalf("temporary files left: %v", entries)
	}
}

func TestCorruptIdentityStoreIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identities.json")
	for _, content := range []string{`{not json`, `{"version":2,"machines":{}}`, `{"version":1,"machines":{"../x":{"machine_id":"../x"}}}`} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		store := OpenIdentityStore(path)
		warnings := store.Warnings()
		if len(warnings) != 1 || !strings.Contains(warnings[0], "quarantined") || store.Count() != 0 {
			t.Fatalf("%q: warnings=%v count=%d", content, warnings, store.Count())
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("corrupt file left in place")
		}
		if err := store.Bind("mac-a", "C02AAA", AuthMachine, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := store.Flush(); err != nil {
			t.Fatal(err)
		}
		if OpenIdentityStore(path).Count() != 1 {
			t.Fatal("fresh store not persisted")
		}
	}
	quarantined, _ := filepath.Glob(filepath.Join(dir, "identities.json.corrupt-*"))
	if len(quarantined) < 1 {
		t.Fatal("no quarantine file")
	}
	// A missing file is an empty store, no warning.
	if store := OpenIdentityStore(filepath.Join(dir, "none.json")); len(store.Warnings()) != 0 || store.Count() != 0 {
		t.Fatal(store.Warnings())
	}
}
