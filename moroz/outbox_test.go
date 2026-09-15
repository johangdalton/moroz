package moroz

import (
	"context"
	"encoding/json"
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
	router.Use(ClientGuard(nil))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	r := httptest.NewRequest("POST", "/v1/santa/preflight/test-mac", strings.NewReader("{}"))
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

func TestOutboxCorruptionFailsClosed(t *testing.T) {
	dir := t.TempDir()
	name := "00000000000000000001-" + strings.Repeat("a", 32) + ".json"
	if err := os.WriteFile(filepath.Join(dir, name), []byte("truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if q, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20); err == nil {
		q.Close()
		t.Fatal("corrupt outbox accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
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
