package moroz

import (
	"compress/gzip"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const maxRequestBytes = 4 << 20

// Santa uploads at most batch_size (100) events per request, well under 1 MiB.
const maxDecodedBytes = 4 << 20
const maxBatchEvents = 1000

var machineName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var fileHash = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

func validMachine(id string) bool {
	return machineName.MatchString(id) && !strings.Contains(id, "..") && id != "global"
}

// ClientGuard binds each token to one explicitly provisioned machine. Tests can
// pass nil credentials only through the CLI's explicit development-mode flag.
// A nil limiter disables per-machine rate and global concurrency limits.
func ClientGuard(credentials map[string]string, limiter *RateLimiter) func(http.Handler) http.Handler {
	var creds *Credentials
	if credentials != nil {
		creds = staticCredentials(credentials)
	}
	return Guard(GuardOptions{Credentials: creds, Limiter: limiter})
}

// GuardOptions configures Guard. Nil Credentials disable authentication
// (development mode only). KnownDevices with RequireKnownDevices restricts
// fleet-token authentication to machine IDs listed in a loaded allowlist;
// per-machine tokens are never subject to it.
type GuardOptions struct {
	Credentials         *Credentials
	Limiter             *RateLimiter
	KnownDevices        *KnownDevices
	RequireKnownDevices bool
}

// Guard authenticates every Santa route, records the AuthMethod on the
// request context and applies the request limits.
func Guard(o GuardOptions) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := machineIDFromRequest(r)
			if err != nil || !validMachine(id) {
				http.Error(w, "invalid machine ID", http.StatusBadRequest)
				return
			}
			method := AuthNone
			if o.Credentials != nil {
				var ok bool
				method, ok = o.Credentials.Authenticate(id, r.Header.Get("Authorization"))
				if !ok {
					http.Error(w, "invalid client credentials", http.StatusUnauthorized)
					return
				}
				if method.IsFleet() && o.RequireKnownDevices && o.KnownDevices.Loaded() {
					if _, known := o.KnownDevices.Lookup(id); !known {
						http.Error(w, "unknown device", http.StatusForbidden)
						return
					}
				}
			}
			r = r.WithContext(withAuth(r.Context(), method))
			limiter := o.Limiter
			if limiter != nil {
				// Limits apply only after authentication so they are keyed on
				// a provisioned machine, never on attacker-chosen input.
				if ok, retryAfter := limiter.Allow(id, time.Now()); !ok {
					w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(retryAfter.Seconds()))))
					http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
					return
				}
				release, ok := limiter.acquire(r.Context())
				if !ok {
					w.Header().Set("Retry-After", strconv.Itoa(int(semaphoreWait.Seconds())))
					http.Error(w, "server busy", http.StatusServiceUnavailable)
					return
				}
				defer release()
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
			next.ServeHTTP(w, r)
		})
	}
}

func decodeJSON(r *http.Request, target interface{}) error {
	defer r.Body.Close()
	var reader io.Reader = r.Body
	var compressed io.ReadCloser
	var err error
	switch strings.ToLower(r.Header.Get("Content-Encoding")) {
	case "gzip":
		compressed, err = gzip.NewReader(r.Body)
	case "none", "identity":
	case "", "deflate":
		compressed, err = zlib.NewReader(r.Body)
	default:
		return fmt.Errorf("unsupported content encoding")
	}
	if err != nil {
		return fmt.Errorf("invalid compressed request: %w", err)
	}
	if compressed != nil {
		defer compressed.Close()
		reader = compressed
	}
	limited := io.LimitReader(reader, maxDecodedBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(data) > maxDecodedBytes {
		return fmt.Errorf("decoded request exceeds limit")
	}
	if err := json.Unmarshal(data, target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func validatePayloadID(urlID, payloadID string) error {
	if !validMachine(urlID) {
		return fmt.Errorf("invalid machine ID")
	}
	if payloadID != "" && payloadID != urlID {
		return fmt.Errorf("payload machine ID differs from authenticated URL")
	}
	return nil
}
