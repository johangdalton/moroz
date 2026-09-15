package moroz

import (
	"encoding/json"
	"net/http"
)

// PolicyStatus reports whether a policy snapshot is loaded and its generation.
type PolicyStatus interface {
	Generation() (generation string, loaded bool)
}

// HealthHandler serves GET /healthz for the container health check. It is
// registered outside ClientGuard, needs no credentials and never reads the
// request body. The ingress only forwards Santa's POST routes, so it stays
// internal. A nil outbox (standalone mode) reports zero pending batches.
func HealthHandler(policy PolicyStatus, outbox *Outbox) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		status := struct {
			Status     string `json:"status"`
			Reason     string `json:"reason,omitempty"`
			Generation string `json:"generation"`
			Pending    int    `json:"pending"`
			Dead       int    `json:"dead"`
		}{Status: "ok"}
		code := http.StatusOK
		if generation, loaded := policy.Generation(); loaded {
			status.Generation = generation
		} else {
			code, status.Status, status.Reason = http.StatusServiceUnavailable, "unavailable", "no policy snapshot loaded"
		}
		if outbox != nil {
			s := outbox.Stats()
			status.Pending, status.Dead = s.Pending, s.Dead
			if code == http.StatusOK && (int64(s.Pending)*10 >= int64(s.MaxPending)*9 || s.PendingBytes*10 >= s.MaxBytes*9) {
				code, status.Status, status.Reason = http.StatusServiceUnavailable, "unavailable", "telemetry outbox is above 90% of capacity"
			}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(code)
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(status)
		}
	})
}
