package moroz

import (
	"encoding/json"
	"net/http"
	"time"
)

// PolicyStatus reports whether a policy snapshot is loaded and its generation.
type PolicyStatus interface {
	Generation() (generation string, loaded bool)
}

// AuthStatus collects the authentication components reported by /healthz.
// Any field may be nil when the feature is disabled.
type AuthStatus struct {
	Credentials  *Credentials
	Identities   *IdentityStore
	KnownDevices *KnownDevices
}

type authReport struct {
	MachineTokens      int                `json:"machine_tokens"`
	FleetTokens        []FleetTokenStatus `json:"fleet_tokens"`
	Identities         int                `json:"identities"`
	IdentityMismatches int64              `json:"identity_mismatches"`
	KnownDevices       *int               `json:"known_devices"`
}

// report never includes token values; counters live in memory only.
func (a AuthStatus) report(now time.Time) authReport {
	r := authReport{FleetTokens: []FleetTokenStatus{}}
	if a.Credentials != nil {
		r.MachineTokens = a.Credentials.MachineTokens()
		r.FleetTokens = a.Credentials.FleetStatus(now)
	}
	if a.Identities != nil {
		r.Identities = a.Identities.Count()
		r.IdentityMismatches = a.Identities.Mismatches()
	}
	if a.KnownDevices.Loaded() {
		n := a.KnownDevices.Count()
		r.KnownDevices = &n
	}
	return r
}

// HealthHandler serves GET /healthz for the container health check. It is
// registered outside ClientGuard, needs no credentials and never reads the
// request body. The ingress only forwards Santa's POST routes, so it stays
// internal. A nil outbox (standalone mode) reports zero pending batches.
func HealthHandler(policy PolicyStatus, outbox *Outbox, auth AuthStatus) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		status := struct {
			Status     string     `json:"status"`
			Reason     string     `json:"reason,omitempty"`
			Generation string     `json:"generation"`
			Pending    int        `json:"pending"`
			Dead       int        `json:"dead"`
			Auth       authReport `json:"auth"`
		}{Status: "ok", Auth: auth.report(time.Now())}
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
