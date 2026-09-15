package moroz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
)

func TestRateLimiterTokenBucket(t *testing.T) {
	l := NewRateLimiter(3, 20*time.Second, 0)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("mac-a", now); !ok {
			t.Fatalf("burst request %d refused", i)
		}
	}
	ok, retry := l.Allow("mac-a", now)
	if ok || retry != 20*time.Second {
		t.Fatalf("burst exceeded: ok=%v retry=%s", ok, retry)
	}
	if ok, _ := l.Allow("mac-b", now); !ok {
		t.Fatal("limit leaked across machines")
	}
	if ok, retry := l.Allow("mac-a", now.Add(10*time.Second)); ok || retry != 10*time.Second {
		t.Fatalf("partial refill: ok=%v retry=%s", ok, retry)
	}
	if ok, _ := l.Allow("mac-a", now.Add(20*time.Second)); !ok {
		t.Fatal("token not refilled")
	}
	if ok, _ := l.Allow("mac-a", now.Add(21*time.Second)); ok {
		t.Fatal("refill exceeded rate")
	}
	// A long idle period refills to the burst, never beyond it.
	later := now.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("mac-a", later); !ok {
			t.Fatalf("request %d after idle refused", i)
		}
	}
	if ok, _ := l.Allow("mac-a", later); ok {
		t.Fatal("bucket exceeded burst")
	}
	if ok, _ := NewRateLimiter(0, time.Second, 0).Allow("mac-a", now); !ok {
		t.Fatal("zero burst should disable the limit")
	}
}

func TestRateLimiterPrunesIdleBuckets(t *testing.T) {
	l := NewRateLimiter(1, time.Second, 0)
	now := time.Unix(1_700_000_000, 0)
	for i := 0; i < 4096; i++ {
		l.Allow("mac-"+strings.Repeat("x", i%64)+string(rune('a'+i/64)), now)
	}
	l.Allow("fresh", now.Add(time.Minute))
	if len(l.buckets) != 1 {
		t.Fatalf("idle buckets retained: %d", len(l.buckets))
	}
}

func TestRateLimitedRequestsGet429(t *testing.T) {
	svc, _ := fixtureService(t)
	router := mux.NewRouter()
	router.Use(ClientGuard(map[string]string{"mac-a": strings.Repeat("a", 32), "mac-b": strings.Repeat("b", 32)}, NewRateLimiter(2, 20*time.Second, 8)))
	AddHTTPRoutes(router, MakeServerEndpoints(svc), log.NewNopLogger())
	call := func(machine, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/santa/preflight/"+machine, strings.NewReader("{}"))
		r.Header.Set("Content-Encoding", "identity")
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		if w := call("mac-a", strings.Repeat("a", 32)); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := call("mac-a", strings.Repeat("a", 32))
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "20" {
		t.Fatalf("%d Retry-After=%q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := call("mac-b", strings.Repeat("b", 32)); w.Code != 200 {
		t.Fatalf("other machine limited: %d", w.Code)
	}
	// Unauthenticated requests never consume a machine's budget.
	call("mac-b", "wrong")
	if w := call("mac-b", strings.Repeat("b", 32)); w.Code != 200 {
		t.Fatalf("failed authentication consumed budget: %d", w.Code)
	}
}

func TestConcurrencySemaphore(t *testing.T) {
	l := NewRateLimiter(0, time.Second, 2)
	var releases []func()
	for i := 0; i < 2; i++ {
		release, ok := l.acquire(context.Background())
		if !ok {
			t.Fatal("slot refused")
		}
		releases = append(releases, release)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, ok := l.acquire(ctx); ok {
		t.Fatal("third slot granted")
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, ok := l.acquire(context.Background()); !ok {
			t.Error("slot not granted after release")
		}
	}()
	releases[0]()
	wg.Wait()
}
