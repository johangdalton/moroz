package moroz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/groob/moroz/santa"
)

func TestOutboxRestartAndLostAcknowledgement(t *testing.T) {
	var requests atomic.Int32
	ids := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 32) {
			t.Error("service auth missing")
		}
		var batch TelemetryBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Error(err)
		}
		ids[batch.ID]++
		if requests.Add(1) == 1 {
			http.Error(w, "simulated lost acknowledgement after commit", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true, "batch_id": batch.ID})
	}))
	defer server.Close()
	dir := t.TempDir()
	q, err := NewOutbox(dir, server.URL, strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Preflight(context.Background(), "test-mac", santa.PreflightPayload{Hostname: "Synthetic", PushNotificationToken: "do-not-retain"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.deliverNext(context.Background()); err == nil {
		t.Fatal("HTTP failure was acknowledged")
	}
	if n, _ := q.Pending(); n != 1 {
		t.Fatal("failed delivery was dropped")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	raw, _ := os.ReadFile(files[0])
	if strings.Contains(string(raw), "do-not-retain") {
		t.Fatal("push token retained")
	}
	q.Close()
	q, err = NewOutbox(dir, server.URL, strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err := q.deliverNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatal("batch ID changed on restart")
	}
	for _, count := range ids {
		if count != 2 {
			t.Fatal("expected replay of same receipt")
		}
	}
	if n, size := q.Pending(); n != 0 || size != 0 {
		t.Fatal("acknowledged batch remains queued")
	}
}

func TestOutboxRefusesFalseAcknowledgementAndRedirect(t *testing.T) {
	var phase atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if phase.Load() == 0 {
			w.Header().Set("Location", "http://example.invalid")
			w.WriteHeader(302)
			return
		}
		w.Write([]byte(`{"accepted":true,"batch_id":"wrong"}`))
	}))
	defer server.Close()
	q, err := NewOutbox(t.TempDir(), server.URL, strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.Preflight(context.Background(), "test-mac", santa.PreflightPayload{})
	for _, value := range []int32{0, 1} {
		phase.Store(value)
		if _, err := q.deliverNext(context.Background()); err == nil {
			t.Fatal("invalid acknowledgement accepted")
		}
	}
	if n, _ := q.Pending(); n != 1 {
		t.Fatal("batch lost")
	}
}

func TestOutboxBackpressureAndSingleWriter(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if other, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20); err == nil {
		other.Close()
		t.Fatal("second writer allowed")
	}
	svc, _ := fixtureService(t)
	svc.SetOutbox(q)
	router := mux.NewRouter()
	router.Use(ClientGuard(nil, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	body := `{"events":[{"file_sha256":"` + strings.Repeat("a", 64) + `"}]}`
	r := httptest.NewRequest("POST", "/v1/santa/eventupload/test-mac", strings.NewReader(body))
	r.Header.Set("Content-Encoding", "identity")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 503 {
		t.Fatalf("full outbox returned %d", w.Code)
	}
	if n, _ := q.Pending(); n != 0 {
		t.Fatal("full queue accepted a batch")
	}
}

// A failed preflight aborts Santa's whole sync, so telemetry storage problems
// must never prevent rule delivery.
func TestPreflightSucceedsWhenOutboxFullOrClosed(t *testing.T) {
	q, err := NewOutbox(t.TempDir(), "http://127.0.0.1/", strings.Repeat("a", 32), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	svc, _ := fixtureService(t)
	svc.SetOutbox(q)
	router := mux.NewRouter()
	router.Use(ClientGuard(nil, nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	preflight := func(state string) {
		r := httptest.NewRequest("POST", "/v1/santa/preflight/test-mac", strings.NewReader(`{"hostname":"Synthetic"}`))
		r.Header.Set("Content-Encoding", "identity")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s outbox blocked preflight: %d %s", state, w.Code, w.Body.String())
		}
		var response santa.Preflight
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || !response.CleanSync {
			t.Fatalf("%s outbox returned an unusable preflight: %v %s", state, err, w.Body.String())
		}
	}
	preflight("full")
	if n, _ := q.Pending(); n != 0 {
		t.Fatal("full queue accepted a batch")
	}
	q.Close()
	preflight("closed")
}

func TestOutboxDeadLettersRejectedBatchAndContinues(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch TelemetryBatch
		json.NewDecoder(r.Body).Decode(&batch)
		switch calls.Add(1) {
		case 1:
			http.Error(w, "schema mismatch", 400)
		case 2:
			http.Error(w, "slow down", 429)
		case 3:
			http.Error(w, "token rotated", 401)
		default:
			json.NewEncoder(w).Encode(map[string]interface{}{"accepted": true, "batch_id": batch.ID})
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	q, err := NewOutbox(dir, server.URL, strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for i := 0; i < 2; i++ {
		if err := q.Preflight(context.Background(), "test-mac", santa.PreflightPayload{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.deliverNext(context.Background()); !errors.As(err, new(deadLettered)) {
		t.Fatalf("HTTP 400 was not dead-lettered: %v", err)
	}
	dead, _ := filepath.Glob(filepath.Join(dir, deadDir, "*.json"))
	if s := q.Stats(); s.Pending != 1 || s.Dead != 1 || len(dead) != 1 {
		t.Fatalf("stats %+v, dead files %d", s, len(dead))
	}
	// Throttling and rejected service credentials are not batch problems.
	for _, code := range []string{"429", "401"} {
		if _, err := q.deliverNext(context.Background()); err == nil || errors.As(err, new(deadLettered)) {
			t.Fatalf("HTTP %s should be retried: %v", code, err)
		}
	}
	if _, err := q.deliverNext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s := q.Stats(); s.Pending != 0 || s.Dead != 1 {
		t.Fatalf("delivery did not continue past the dead letter: %+v", s)
	}
	q.Close()
	// The dead count survives a restart.
	q, err = NewOutbox(dir, server.URL, strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if s := q.Stats(); s.Dead != 1 {
		t.Fatalf("dead count lost on restart: %+v", s)
	}
}

func TestOutboxDeadLettersUnreadableBatchAfterRepeatedFailures(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOutbox(dir, "http://127.0.0.1:1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Preflight(context.Background(), "test-mac", santa.PreflightPayload{}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if err := os.WriteFile(files[0], []byte("corrupt after commit"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < deadLetterAfterFailures; i++ {
		if _, err := q.deliverNext(context.Background()); err == nil || errors.As(err, new(deadLettered)) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, err := q.deliverNext(context.Background()); !errors.As(err, new(deadLettered)) {
		t.Fatalf("corrupt batch not dead-lettered: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, deadDir, filepath.Base(files[0]))); err != nil {
		t.Fatal("dead-lettered file was not preserved")
	}
	if s := q.Stats(); s.Pending != 0 || s.Dead != 1 {
		t.Fatalf("%+v", s)
	}
	if found, err := q.deliverNext(context.Background()); found || err != nil {
		t.Fatal("queue should be idle")
	}
}

func TestOutboxConcurrentProducersRecoverEveryBatch(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if err := q.Preflight(context.Background(), "test-mac", santa.PreflightPayload{}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if n, _ := q.Pending(); n != 100 {
		t.Fatal(n)
	}
	q.Close()
	q, err = NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if n, _ := q.Pending(); n != 100 {
		t.Fatal("restart lost batches", n)
	}
}

// A corrupt file must neither be delivered nor crash-loop the sync server.
func TestOutboxCorruptionIsQuarantinedAtStartup(t *testing.T) {
	dir := t.TempDir()
	name := "00000000000000000001-" + strings.Repeat("a", 32) + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	q, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatalf("corrupt file prevented startup: %v", err)
	}
	defer q.Close()
	if n, _ := q.Pending(); n != 0 {
		t.Fatal("corrupt batch was queued")
	}
	if quarantined := q.Quarantined(); len(quarantined) != 1 || !strings.HasPrefix(quarantined[0], name) {
		t.Fatalf("quarantine not reported: %v", quarantined)
	}
	if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
		t.Fatal("corrupt file left in the queue")
	}
	if data, err := os.ReadFile(filepath.Join(dir, corruptDir, name)); err != nil || string(data) != "truncated" {
		t.Fatal("corrupt data was discarded")
	}
}

func TestOutboxCleansOnlyUncommittedTemporaryWrites(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "outbox")
	q, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	q.Close()
	for _, name := range []string{".pending-123456", ".pending-not-a-temporary-write"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("partial"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	q, err = NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err := os.Stat(filepath.Join(dir, ".pending-123456")); !os.IsNotExist(err) {
		t.Fatal("uncommitted temporary write retained", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".pending-not-a-temporary-write")); err != nil {
		t.Fatal("unrelated file removed", err)
	}
}
