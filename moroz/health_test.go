package moroz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-kit/kit/log"
	"github.com/gorilla/mux"
	"github.com/groob/moroz/santa"
)

type fixturePolicy struct {
	generation string
	loaded     bool
}

func (p fixturePolicy) Generation() (string, bool) { return p.generation, p.loaded }

func TestHealthEndpoint(t *testing.T) {
	dir := t.TempDir()
	q, err := NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	policy := fixturePolicy{generation: "manifest:abc", loaded: true}
	svc, _ := fixtureService(t)
	svc.SetOutbox(q)
	root := http.NewServeMux()
	root.Handle("/healthz", HealthHandler(policy, q))
	api := mux.NewRouter()
	api.Use(ClientGuard(map[string]string{}, nil))
	AddHTTPRoutes(api, MakeServerEndpoints(svc), log.NewNopLogger())
	root.Handle("/", api)

	get := func(method string) (int, map[string]interface{}) {
		r := httptest.NewRequest(method, "/healthz", strings.NewReader("ignored body"))
		w := httptest.NewRecorder()
		root.ServeHTTP(w, r)
		var body map[string]interface{}
		if strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") && w.Body.Len() > 0 {
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("%s: %v %s", method, err, w.Body.String())
			}
		}
		return w.Code, body
	}
	code, body := get(http.MethodGet)
	if code != 200 || body["status"] != "ok" || body["generation"] != "manifest:abc" || body["pending"] != 0.0 || body["dead"] != 0.0 {
		t.Fatalf("%d %v", code, body)
	}
	if code, body := get(http.MethodHead); code != 200 || body != nil {
		t.Fatalf("HEAD %d %v", code, body)
	}
	if code, _ := get(http.MethodPost); code != 405 {
		t.Fatalf("POST %d", code)
	}
	// Above 90% of the byte capacity the process is not ready for more telemetry.
	if err := q.Preflight(context.Background(), "test-mac", santa.PreflightPayload{}); err != nil {
		t.Fatal(err)
	}
	_, size := q.Pending()
	q.Close()
	if q, err = NewOutbox(dir, "http://127.0.0.1/", strings.Repeat("a", 32), size); err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	root.Handle("/healthz-full", HealthHandler(policy, q))
	r := httptest.NewRequest(http.MethodGet, "/healthz-full", nil)
	w := httptest.NewRecorder()
	root.ServeHTTP(w, r)
	code, body = w.Code, nil
	json.Unmarshal(w.Body.Bytes(), &body)
	if code != 503 || body["status"] != "unavailable" || body["pending"] != 1.0 || !strings.Contains(body["reason"].(string), "90%") {
		t.Fatalf("%d %v", code, body)
	}
	// The protected API is unaffected by the health route and vice versa.
	r = httptest.NewRequest(http.MethodPost, "/v1/santa/preflight/test-mac", strings.NewReader("{}"))
	w = httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code == 200 {
		t.Fatal("API route served without credentials")
	}
	root.Handle("/healthz-unloaded", HealthHandler(fixturePolicy{}, nil))
	r = httptest.NewRequest(http.MethodGet, "/healthz-unloaded", nil)
	w = httptest.NewRecorder()
	root.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "no policy snapshot") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
