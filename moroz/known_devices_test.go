package moroz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownDevicesGateFleetTokensOnly(t *testing.T) {
	svc, _ := fixtureService(t)
	path := filepath.Join(t.TempDir(), "known-devices.json")
	known := NewKnownDevices(path)
	if err := known.Reload(); err != ErrKnownDevicesMissing {
		t.Fatalf("first reload of missing file: %v", err)
	}
	if err := known.Reload(); err != nil || known.Loaded() || known.Count() != -1 {
		t.Fatalf("missing file must be reported once: %v", err)
	}
	var refused []string
	svc.SetAuthErrorLogger(func(err error) { refused = append(refused, err.Error()) })
	svc.SetKnownDevices(known, true)
	creds := mustStatic(t, map[string]string{"mac-b": machineTokenB}, []FleetToken{{Name: "pilot-2026", Token: fleetToken1}})
	h := guardedRouter(t, svc, GuardOptions{Credentials: creds, KnownDevices: known, RequireKnownDevices: true}, nil)

	// Feature off while the file is missing.
	if w := post(h, "/v1/santa/preflight/mac-x", fleetToken1, `{"serial_num":"SX"}`); w.Code != 200 {
		t.Fatalf("ungated fleet preflight: %d", w.Code)
	}
	writeAtomic(t, path, `{"mac-a":{"serial":"C02AAA","name":"Lab Mac"},"mac-c":{"serial":"","name":"No serial yet"}}`)
	if err := known.Reload(); err != nil || !known.Loaded() || known.Count() != 2 {
		t.Fatalf("%v loaded=%v", err, known.Loaded())
	}
	cases := []struct {
		name, route, machine, token, body string
		status                            int
	}{
		{"unknown machine with fleet token", "preflight", "mac-x", fleetToken1, `{"serial_num":"SX"}`, 403},
		{"unknown machine rule download", "ruledownload", "mac-x", fleetToken1, ``, 403},
		{"known machine wrong serial", "preflight", "mac-a", fleetToken1, `{"serial_num":"C02ZZZ"}`, 403},
		{"known machine right serial", "preflight", "mac-a", fleetToken1, `{"serial_num":"C02AAA"}`, 200},
		{"known machine other routes", "postflight", "mac-a", fleetToken1, `{}`, 200},
		{"known machine without listed serial", "preflight", "mac-c", fleetToken1, `{"serial_num":"ANY"}`, 200},
		{"per-machine token bypasses allowlist", "preflight", "mac-b", machineTokenB, `{"serial_num":"SB"}`, 200},
		{"per-machine token rule download", "ruledownload", "mac-b", machineTokenB, ``, 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := post(h, "/v1/santa/"+tc.route+"/"+tc.machine, tc.token, tc.body)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if tc.status == 403 && !strings.Contains(w.Body.String(), "unknown device") {
				t.Fatalf("body %s", w.Body.String())
			}
		})
	}
	if len(refused) != 1 || !strings.Contains(refused[0], "C02ZZZ") || !strings.Contains(refused[0], "C02AAA") {
		t.Fatalf("refusals %v", refused)
	}
	// Invalid content keeps the previous allowlist; a vanished file turns gating off again.
	if err := os.WriteFile(path, []byte(`{"mac-a":{"serial":1}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := known.Reload(); err == nil || !known.Loaded() || known.Count() != 2 {
		t.Fatalf("invalid file: %v loaded=%v", err, known.Loaded())
	}
	os.Remove(path)
	if err := known.Reload(); err != ErrKnownDevicesMissing || known.Loaded() {
		t.Fatalf("removed file: %v", err)
	}
	if w := post(h, "/v1/santa/preflight/mac-x", fleetToken1, `{"serial_num":"SX"}`); w.Code != 200 {
		t.Fatalf("gating still on after file removal: %d", w.Code)
	}
	for _, body := range []string{`{"../x":{"serial":"a"}}`, `{"mac-a":{"serial":"a","extra":1}}`, `null`, `[]`} {
		if _, err := parseKnownDevices([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}
