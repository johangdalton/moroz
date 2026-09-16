package moroz

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/groob/moroz/santa"
)

type fixtureStore struct{ config santa.Config }

func (f *fixtureStore) Config(context.Context, string) (santa.Config, error) { return f.config, nil }
func (f *fixtureStore) AllConfigs(context.Context) ([]santa.Config, error) {
	return []santa.Config{f.config}, nil
}
func fixtureService(t *testing.T) (*SantaService, *fixtureStore) {
	t.Helper()
	store := &fixtureStore{config: santa.Config{Preflight: santa.Preflight{SyncType: santa.SyncTypeClean, CleanSync: true}}}
	svc, err := NewService(store, t.TempDir(), true)
	if err != nil {
		t.Fatal(err)
	}
	return svc, store
}

func TestClientAuthenticationAndInput(t *testing.T) {
	svc, _ := fixtureService(t)
	router := mux.NewRouter()
	router.Use(ClientGuard(map[string]string{"mac-a": strings.Repeat("a", 32), "mac-b": strings.Repeat("b", 32)}, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	cases := []struct {
		name, machine, token, body string
		status                     int
	}{
		{"missing token", "mac-a", "", "{}", 401},
		{"wrong machine token", "mac-b", strings.Repeat("a", 32), "{}", 401},
		{"identity override", "mac-a", strings.Repeat("a", 32), `{"machine_id":"mac-b"}`, 400},
		{"malformed JSON", "mac-a", strings.Repeat("a", 32), `{`, 400},
		{"valid", "mac-a", strings.Repeat("a", 32), "{}", 200},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/santa/preflight/"+tc.machine, strings.NewReader(tc.body))
			r.Header.Set("Content-Encoding", "identity")
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestRequestEncodingAndDecompressionLimit(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip", "deflate"} {
		t.Run(encoding, func(t *testing.T) {
			var b bytes.Buffer
			switch encoding {
			case "gzip":
				w := gzip.NewWriter(&b)
				w.Write([]byte(`{"ok":true}`))
				w.Close()
			case "deflate":
				w := zlib.NewWriter(&b)
				w.Write([]byte(`{"ok":true}`))
				w.Close()
			default:
				b.WriteString(`{"ok":true}`)
			}
			r := httptest.NewRequest("POST", "/", &b)
			r.Header.Set("Content-Encoding", encoding)
			var value map[string]bool
			if err := decodeJSON(r, &value); err != nil || !value["ok"] {
				t.Fatalf("%v %v", value, err)
			}
		})
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write(bytes.Repeat([]byte(" "), maxDecodedBytes+1))
	w.Close()
	r := httptest.NewRequest("POST", "/", &b)
	r.Header.Set("Content-Encoding", "gzip")
	var value interface{}
	if err := decodeJSON(r, &value); err == nil {
		t.Fatal("accepted decompression bomb")
	}
}

func TestSnapshotPinnedUntilPostflight(t *testing.T) {
	svc, store := fixtureService(t)
	ctx := context.Background()
	first := svc.beginSync(ctx, "mac-a", store.config, "", santa.PreflightPayload{})
	if !first.CleanSync {
		t.Fatal("initial snapshot must clean stale rules")
	}
	changed := store.config
	changed.Preflight.BatchSize = 51
	store.config = changed
	pinned, ok := svc.sessionConfig("mac-a")
	if !ok || pinned.Preflight.BatchSize == 51 {
		t.Fatal("in-flight snapshot changed")
	}
	svc.finishSync("mac-a", santa.PostflightPayload{})
	same := svc.beginSync(ctx, "mac-a", pinned, "", santa.PreflightPayload{})
	if same.CleanSync || same.SyncType != santa.SyncTypeNormal {
		t.Fatal("unchanged policy should use normal sync")
	}
	next := svc.beginSync(ctx, "mac-a", changed, "", santa.PreflightPayload{})
	if !next.CleanSync {
		t.Fatal("changed policy should clean stale rules")
	}
	svc.finishSync("mac-a", santa.PostflightPayload{})
	forced := svc.beginSync(ctx, "mac-a", changed, "", santa.PreflightPayload{RequestCleanSync: true})
	if !forced.CleanSync {
		t.Fatal("client clean request ignored")
	}
	svc.sessions["mac-a"] = syncSession{expires: time.Now().Add(-time.Second)}
	if _, ok := svc.sessionConfig("mac-a"); ok {
		t.Fatal("expired session survived")
	}
}

func TestEventBatchPersistenceAndRetention(t *testing.T) {
	svc, _ := fixtureService(t)
	svc.SetEventRetentionDays(7)
	old := filepath.Join(svc.eventDir, "2000-01-01.jsonl")
	os.WriteFile(old, []byte("old"), 0600)
	legacy := filepath.Join(svc.eventDir, "legacy.json")
	os.WriteFile(legacy, []byte("keep"), 0600)
	hash := strings.Repeat("a", 64)
	events := []santa.EventPayload{{FileSHA: hash, EventInfo: santa.EventUploadEvent{FileSHA256: hash, FileName: "Synthetic", ExecutionTime: 123}}}
	for i := 0; i < 2; i++ {
		if err := svc.UploadEvent(context.Background(), "mac-a", events); err != nil {
			t.Fatal(err)
		}
	}
	contents, err := os.ReadFile(filepath.Join(svc.eventDir, time.Now().UTC().Format("2006-01-02")+".jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event["machine_id"] != "mac-a" || event["file_sha256"] != hash {
		t.Fatal(event)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("old JSONL file remains")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("legacy file removed")
	}
}

func TestOversizedBodyAndBatch(t *testing.T) {
	svc, _ := fixtureService(t)
	router := mux.NewRouter()
	router.Use(ClientGuard(nil, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	bodies := []string{strings.Repeat(" ", maxRequestBytes+1), `{"events":[` + strings.Repeat(`{"file_sha256":"`+strings.Repeat("a", 64)+`"},`, maxBatchEvents) + `{"file_sha256":"` + strings.Repeat("a", 64) + `"}]}`}
	for _, body := range bodies {
		r := httptest.NewRequest(http.MethodPost, "/v1/santa/eventupload/mac-a", strings.NewReader(body))
		r.Header.Set("Content-Encoding", "identity")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatalf("status %d", w.Code)
		}
	}
}

// An explicitly configured empty allowlist starts the server with enrollment closed.
func TestEmptyClientAllowlistRejectsEveryMachine(t *testing.T) {
	svc, _ := fixtureService(t)
	router := mux.NewRouter()
	router.Use(ClientGuard(map[string]string{}, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	r := httptest.NewRequest("POST", "/v1/santa/preflight/unregistered-mac", strings.NewReader("{}"))
	r.Header.Set("Content-Encoding", "none")
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 48))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty allowlist returned %d", w.Code)
	}
}
