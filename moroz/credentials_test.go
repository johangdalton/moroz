package moroz

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
)

const (
	machineTokenA = "machine-token-a-0123456789abcdef0123456789"
	machineTokenB = "machine-token-b-0123456789abcdef0123456789"
	fleetToken1   = "fleet-token-pilot-2026-0123456789abcdef01234"
	fleetToken2   = "fleet-token-pilot-2027-0123456789abcdef01234"
	fleetToken3   = "fleet-token-pilot-2028-0123456789abcdef01234"
)

func mustStatic(t *testing.T, machines map[string]string, fleet []FleetToken) *Credentials {
	t.Helper()
	c, err := StaticCredentials(machines, fleet)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// guardedRouter serves the Santa routes behind Guard with the logging
// middleware writing logfmt lines into logs (may be nil).
func guardedRouter(t *testing.T, svc *SantaService, o GuardOptions, logs *bytes.Buffer) http.Handler {
	t.Helper()
	logger := log.NewNopLogger()
	if logs != nil {
		logger = log.NewLogfmtLogger(log.NewSyncWriter(logs))
	}
	router := mux.NewRouter()
	router.Use(Guard(o))
	AddHTTPRoutes(router, MakeServerEndpoints(LoggingMiddleware(logger, false)(svc)), logger)
	return router
}

func post(h http.Handler, path, token, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r.Header.Set("Content-Encoding", "identity")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestFleetTokenAuthentication(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	creds := mustStatic(t, map[string]string{"mac-a": machineTokenA}, []FleetToken{
		{Name: "live", Token: fleetToken1, Expires: &future},
		{Name: "off", Token: fleetToken2, Disabled: true},
		{Name: "old", Token: fleetToken3, Expires: &past},
	})
	cases := []struct {
		name, machine, token string
		want                 AuthMethod
		ok                   bool
	}{
		{"machine token wins", "mac-a", machineTokenA, AuthMachine, true},
		{"machine token bound to its ID", "mac-b", machineTokenA, "", false},
		{"fleet token for unprovisioned machine", "mac-b", fleetToken1, "fleet:live", true},
		{"fleet token for provisioned machine", "mac-a", fleetToken1, "fleet:live", true},
		{"disabled fleet token", "mac-b", fleetToken2, "", false},
		{"expired fleet token", "mac-b", fleetToken3, "", false},
		{"unknown token", "mac-b", strings.Repeat("x", 40), "", false},
		{"prefix only", "mac-b", fleetToken1[:31], "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := creds.Authenticate(tc.machine, "Bearer "+tc.token)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("got %q %v, want %q %v", got, ok, tc.want, tc.ok)
			}
		})
	}
	if _, ok := creds.Authenticate("mac-b", fleetToken1); ok {
		t.Fatal("accepted token without Bearer scheme")
	}
	status := creds.FleetStatus(time.Now())
	if len(status) != 3 || status[0].Uses != 2 || status[0].LastUsed == nil || !status[0].Enabled || status[1].Enabled || status[2].Enabled || status[1].LastUsed != nil {
		t.Fatalf("%+v", status)
	}
}

func TestFleetCredentialValidation(t *testing.T) {
	cases := []struct {
		name     string
		machines map[string]string
		fleet    []FleetToken
	}{
		{"too short", nil, []FleetToken{{Name: "a", Token: strings.Repeat("a", 31)}}},
		{"empty name", nil, []FleetToken{{Name: "", Token: fleetToken1}}},
		{"name with space", nil, []FleetToken{{Name: "pilot 2026", Token: fleetToken1}}},
		{"duplicate name", nil, []FleetToken{{Name: "a", Token: fleetToken1}, {Name: "a", Token: fleetToken2}}},
		{"duplicate fleet token", nil, []FleetToken{{Name: "a", Token: fleetToken1}, {Name: "b", Token: fleetToken1}}},
		{"fleet token equals machine token", map[string]string{"mac-a": machineTokenA}, []FleetToken{{Name: "a", Token: machineTokenA}}},
		{"short machine token", map[string]string{"mac-a": "short"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := StaticCredentials(tc.machines, tc.fleet)
			if err == nil {
				t.Fatal("accepted invalid credentials")
			}
			for _, secret := range []string{fleetToken1, fleetToken2, machineTokenA} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks token: %v", err)
				}
			}
		})
	}
	for _, body := range []string{`{"tokens":[{"name":"a","token":"` + fleetToken1 + `","disable":true}]}`, `{}`, `[]`, `{"tokens":[{"name":"a","token":"` + fleetToken1 + `","expires":"tomorrow"}]}`} {
		if _, err := parseFleetCredentials([]byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}

func writeAtomic(t *testing.T, path, content string) {
	t.Helper()
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal(err)
	}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestCredentialHotReload(t *testing.T) {
	dir := t.TempDir()
	machinePath := filepath.Join(dir, "client_credentials")
	fleetPath := filepath.Join(dir, "fleet_credentials")
	writeAtomic(t, machinePath, `{"mac-a":"`+machineTokenA+`"}`)
	writeAtomic(t, fleetPath, `{"tokens":[{"name":"pilot-2026","token":"`+fleetToken1+`"}]}`)
	if _, err := LoadCredentials(machinePath, filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing fleet file must fail startup")
	}
	if _, err := LoadCredentials(filepath.Join(dir, "missing"), fleetPath); err == nil {
		t.Fatal("missing machine file must fail startup")
	}
	creds, err := LoadCredentials(machinePath, fleetPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var (
		errMu sync.Mutex
		errs  []string
	)
	errorCount := func() int { errMu.Lock(); defer errMu.Unlock(); return len(errs) }
	done := make(chan struct{})
	go func() {
		defer close(done)
		creds.Watch(ctx, 10*time.Millisecond, func(err error) { errMu.Lock(); errs = append(errs, err.Error()); errMu.Unlock() })
	}()
	accepts := func(machine, token string) func() bool {
		return func() bool { _, ok := creds.Authenticate(machine, "Bearer "+token); return ok }
	}
	rejects := func(machine, token string) func() bool {
		return func() bool { return !accepts(machine, token)() }
	}

	// A rotated file (rename) adds a token; the old one still works.
	writeAtomic(t, fleetPath, `{"tokens":[{"name":"pilot-2026","token":"`+fleetToken1+`"},{"name":"pilot-2027","token":"`+fleetToken2+`"}]}`)
	waitFor(t, "new fleet token", accepts("mac-z", fleetToken2))
	if !accepts("mac-z", fleetToken1)() {
		t.Fatal("existing token dropped by rotation")
	}
	// An in-place edit revokes the old token.
	if err := os.WriteFile(fleetPath, []byte(`{"tokens":[{"name":"pilot-2026","token":"`+fleetToken1+`","disabled":true},{"name":"pilot-2027","token":"`+fleetToken2+`"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "revoked fleet token", rejects("mac-z", fleetToken1))
	// A new device appears in the per-machine file.
	writeAtomic(t, machinePath, `{"mac-a":"`+machineTokenA+`","mac-b":"`+machineTokenB+`"}`)
	waitFor(t, "new machine token", accepts("mac-b", machineTokenB))
	// Invalid content keeps the previous set and is reported.
	writeAtomic(t, fleetPath, `{"tokens":[{"name":"pilot-2027","token":"`+machineTokenB+`"}]}`)
	waitFor(t, "reload error", func() bool { return errorCount() > 0 })
	time.Sleep(30 * time.Millisecond)
	if !accepts("mac-z", fleetToken2)() || !accepts("mac-b", machineTokenB)() || accepts("mac-z", machineTokenB)() {
		t.Fatal("invalid file replaced the previous set")
	}
	cancel()
	<-done
	for _, e := range errs {
		if strings.Contains(e, machineTokenB) || strings.Contains(e, fleetToken2) {
			t.Fatalf("reload error leaks token: %s", e)
		}
	}
	// Usage counters survive a reload.
	if status := creds.FleetStatus(time.Now()); len(status) != 2 || status[1].Uses == 0 || status[0].Enabled {
		t.Fatalf("%+v", status)
	}
}

func TestGuardRecordsAuthMethodAndNeverLogsTokens(t *testing.T) {
	svc, _ := fixtureService(t)
	creds := mustStatic(t, map[string]string{"mac-a": machineTokenA}, []FleetToken{{Name: "pilot-2026", Token: fleetToken1}})
	var logs bytes.Buffer
	known := NewKnownDevices(filepath.Join(t.TempDir(), "absent"))
	known.Reload()
	h := guardedRouter(t, svc, GuardOptions{Credentials: creds, KnownDevices: known, RequireKnownDevices: true}, &logs)
	paths := []string{"preflight", "ruledownload", "eventupload", "postflight"}
	for _, p := range paths {
		if w := post(h, "/v1/santa/"+p+"/mac-a", machineTokenA, "{}"); w.Code != 200 {
			t.Fatalf("%s machine: %d %s", p, w.Code, w.Body.String())
		}
		// require-known-devices without a loaded file does not gate fleet tokens.
		if w := post(h, "/v1/santa/"+p+"/mac-b", fleetToken1, "{}"); w.Code != 200 {
			t.Fatalf("%s fleet: %d %s", p, w.Code, w.Body.String())
		}
	}
	if w := post(h, "/v1/santa/preflight/mac-a", fleetToken2, "{}"); w.Code != 401 {
		t.Fatalf("unknown token: %d", w.Code)
	}
	if w := post(h, "/v1/santa/preflight/mac-a", machineTokenA, `{"machine_id":"mac-b"}`); w.Code != 400 {
		t.Fatalf("identity override: %d", w.Code)
	}
	out := logs.String()
	for _, p := range []string{"Preflight", "RuleDownload", "UploadEvent", "Postflight"} {
		if !strings.Contains(out, "method="+p+" machine_id=mac-a auth=machine") || !strings.Contains(out, "method="+p+" machine_id=mac-b auth=fleet:pilot-2026") {
			t.Fatalf("missing auth field for %s in:\n%s", p, out)
		}
	}
	for _, secret := range []string{machineTokenA, fleetToken1, fleetToken2} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains a token:\n%s", out)
		}
	}
}

func TestHealthAuthBlock(t *testing.T) {
	svc, _ := fixtureService(t)
	creds := mustStatic(t, map[string]string{"mac-a": machineTokenA, "mac-b": machineTokenB}, []FleetToken{{Name: "pilot-2026", Token: fleetToken1}, {Name: "retired", Token: fleetToken2, Disabled: true}})
	store := OpenIdentityStore(filepath.Join(t.TempDir(), "identities.json"))
	svc.SetIdentityStore(store)
	api := guardedRouter(t, svc, GuardOptions{Credentials: creds}, nil)
	if w := post(api, "/v1/santa/preflight/mac-c", fleetToken1, `{"serial_num":"C02FLEET"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := post(api, "/v1/santa/preflight/mac-c", fleetToken1, `{"serial_num":"C02OTHER"}`); w.Code != 403 {
		t.Fatal(w.Code)
	}
	health := HealthHandler(fixturePolicy{generation: "g", loaded: true}, nil, AuthStatus{Credentials: creds, Identities: store}, nil)
	w := httptest.NewRecorder()
	health.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var body struct {
		Auth struct {
			MachineTokens      int                `json:"machine_tokens"`
			FleetTokens        []FleetTokenStatus `json:"fleet_tokens"`
			Identities         int                `json:"identities"`
			IdentityMismatches int                `json:"identity_mismatches"`
			KnownDevices       *int               `json:"known_devices"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	a := body.Auth
	if a.MachineTokens != 2 || len(a.FleetTokens) != 2 || a.Identities != 1 || a.IdentityMismatches != 1 || a.KnownDevices != nil {
		t.Fatalf("%s", w.Body.String())
	}
	if a.FleetTokens[0].Name != "pilot-2026" || !a.FleetTokens[0].Enabled || a.FleetTokens[0].Uses != 2 || a.FleetTokens[0].LastUsed == nil {
		t.Fatalf("%s", w.Body.String())
	}
	if a.FleetTokens[1].Name != "retired" || a.FleetTokens[1].Enabled || a.FleetTokens[1].Uses != 0 || a.FleetTokens[1].LastUsed != nil {
		t.Fatalf("%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"last_used":null`) {
		t.Fatalf("null last_used expected: %s", w.Body.String())
	}
	for _, secret := range []string{machineTokenA, machineTokenB, fleetToken1, fleetToken2} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("health output contains a token")
		}
	}
	known := NewKnownDevices(filepath.Join(t.TempDir(), "known.json"))
	writeAtomic(t, known.path, `{"mac-a":{"serial":"S1","name":"A"},"mac-b":{"serial":"","name":"B"}}`)
	if err := known.Reload(); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	HealthHandler(fixturePolicy{loaded: true}, nil, AuthStatus{KnownDevices: known}, nil).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !strings.Contains(w.Body.String(), `"known_devices":2`) || !strings.Contains(w.Body.String(), `"fleet_tokens":[]`) {
		t.Fatalf("%s", w.Body.String())
	}
}
