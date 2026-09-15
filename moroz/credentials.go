package moroz

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AuthMethod records how a request authenticated: "machine" for the
// per-machine token bound to the URL machine ID, "fleet:<name>" for a shared
// fleet token, "none" when authentication is disabled. It never contains a
// token value and is safe to log.
type AuthMethod string

const (
	AuthNone    AuthMethod = "none"
	AuthMachine AuthMethod = "machine"
)

func fleetAuth(name string) AuthMethod { return AuthMethod("fleet:" + name) }

// IsFleet reports whether a shared fleet token authenticated the request.
func (m AuthMethod) IsFleet() bool { return strings.HasPrefix(string(m), "fleet:") }

// FleetName returns the fleet token name, or "" for other methods.
func (m AuthMethod) FleetName() string { return strings.TrimPrefix(string(m), "fleet:") }

type authContextKey struct{}

func withAuth(ctx context.Context, m AuthMethod) context.Context {
	return context.WithValue(ctx, authContextKey{}, m)
}

// AuthFromContext returns the method ClientGuard recorded for the request.
func AuthFromContext(ctx context.Context) AuthMethod {
	if m, ok := ctx.Value(authContextKey{}).(AuthMethod); ok {
		return m
	}
	return AuthNone
}

// FleetToken is one entry of the fleet credentials file. Fleet tokens are
// shared by every managed Mac; identity comes from the machine ID and the
// serial binding, not from the token.
type FleetToken struct {
	Name     string     `json:"name"`
	Token    string     `json:"token"`
	Disabled bool       `json:"disabled,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"`
}

// usable reports whether the token may authenticate requests at now.
func (t FleetToken) usable(now time.Time) bool {
	return !t.Disabled && (t.Expires == nil || now.Before(*t.Expires))
}

type fleetCredentialsFile struct {
	Tokens []FleetToken `json:"tokens"`
}

// credentialSet is an immutable, validated view of both credential files.
type credentialSet struct {
	machines map[string]string
	fleet    []FleetToken
}

// fleetUsage is kept per token name in memory for the health endpoint.
type fleetUsage struct {
	uses     atomic.Int64
	lastUsed atomic.Int64 // UnixNano, 0 = never
}

// FleetTokenStatus is the health endpoint's view of one fleet token.
type FleetTokenStatus struct {
	Name     string     `json:"name"`
	Enabled  bool       `json:"enabled"`
	LastUsed *time.Time `json:"last_used"`
	Uses     int64      `json:"uses"`
}

// Credentials holds the per-machine token map and the fleet token list, both
// reloaded from disk without a restart. Readers see one consistent set.
type Credentials struct {
	machinePath, fleetPath string
	current                atomic.Pointer[credentialSet]
	reloadMu               sync.Mutex
	machineStamp           fileStamp
	fleetStamp             fileStamp
	usageMu                sync.Mutex
	usage                  map[string]*fleetUsage
}

const minTokenLength = 32

var fleetTokenName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// LoadCredentials reads and validates both files once. Either path may be
// empty; an empty machine path means no per-machine tokens, an empty fleet
// path disables fleet tokens. Errors here are startup failures.
func LoadCredentials(machinePath, fleetPath string) (*Credentials, error) {
	c := &Credentials{machinePath: machinePath, fleetPath: fleetPath, usage: make(map[string]*fleetUsage)}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

// StaticCredentials builds a validated in-memory set that never reloads.
func StaticCredentials(machines map[string]string, fleet []FleetToken) (*Credentials, error) {
	if machines == nil {
		machines = map[string]string{}
	}
	set, err := validateCredentialSet(machines, fleet)
	if err != nil {
		return nil, err
	}
	c := &Credentials{usage: make(map[string]*fleetUsage)}
	c.publish(set)
	return c, nil
}

// staticCredentials keeps the historic ClientGuard behaviour: the map is
// used as given, without validation.
func staticCredentials(machines map[string]string) *Credentials {
	c := &Credentials{usage: make(map[string]*fleetUsage)}
	c.publish(&credentialSet{machines: machines})
	return c
}

func parseMachineCredentials(data []byte) (map[string]string, error) {
	var machines map[string]string
	if err := json.Unmarshal(data, &machines); err != nil || machines == nil {
		return nil, fmt.Errorf("invalid client credentials file")
	}
	return machines, nil
}

func parseFleetCredentials(data []byte) ([]FleetToken, error) {
	var file fleetCredentialsFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	// A misspelt "disabled" or "expires" must not silently leave a token live.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("invalid fleet credentials file: %w", err)
	}
	if file.Tokens == nil {
		return nil, fmt.Errorf("invalid fleet credentials file: missing tokens list")
	}
	return file.Tokens, nil
}

// validateCredentialSet enforces the token rules across both files. Error
// texts name entries by machine ID or token name, never by token value.
func validateCredentialSet(machines map[string]string, fleet []FleetToken) (*credentialSet, error) {
	seen := make(map[string]string, len(machines)+len(fleet))
	ids := make([]string, 0, len(machines))
	for id := range machines {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		token := machines[id]
		if len(token) < minTokenLength {
			return nil, fmt.Errorf("client tokens must contain at least %d characters (machine %q)", minTokenLength, id)
		}
		if other, dup := seen[token]; dup {
			return nil, fmt.Errorf("token of machine %q duplicates %s", id, other)
		}
		seen[token] = "machine " + fmt.Sprintf("%q", id)
	}
	names := make(map[string]bool, len(fleet))
	for i, t := range fleet {
		if t.Name == "" || !fleetTokenName.MatchString(t.Name) {
			return nil, fmt.Errorf("fleet token %d: name must be 1-64 characters of letters, digits, '_', '.', '-'", i+1)
		}
		if names[t.Name] {
			return nil, fmt.Errorf("fleet token %q: duplicate name", t.Name)
		}
		names[t.Name] = true
		if len(t.Token) < minTokenLength {
			return nil, fmt.Errorf("fleet token %q: token must contain at least %d characters", t.Name, minTokenLength)
		}
		if other, dup := seen[t.Token]; dup {
			return nil, fmt.Errorf("fleet token %q duplicates %s", t.Name, other)
		}
		seen[t.Token] = fmt.Sprintf("fleet token %q", t.Name)
	}
	return &credentialSet{machines: machines, fleet: append([]FleetToken(nil), fleet...)}, nil
}

// load re-reads both files when either changed on disk, validates them as
// one set and swaps it in. A failure keeps the previous set and leaves the
// stamps untouched so the next poll retries.
func (c *Credentials) load() error {
	c.reloadMu.Lock()
	defer c.reloadMu.Unlock()
	machineStamp, err := stampFile(c.machinePath)
	if err != nil {
		return fmt.Errorf("client credentials: %w", err)
	}
	fleetStamp, err := stampFile(c.fleetPath)
	if err != nil {
		return fmt.Errorf("fleet credentials: %w", err)
	}
	if c.current.Load() != nil && machineStamp == c.machineStamp && fleetStamp == c.fleetStamp {
		return nil
	}
	machines := map[string]string{}
	if c.machinePath != "" {
		data, err := os.ReadFile(c.machinePath)
		if err != nil {
			return fmt.Errorf("cannot read client credentials: %w", err)
		}
		if machines, err = parseMachineCredentials(data); err != nil {
			return err
		}
	}
	var fleet []FleetToken
	if c.fleetPath != "" {
		data, err := os.ReadFile(c.fleetPath)
		if err != nil {
			return fmt.Errorf("cannot read fleet credentials: %w", err)
		}
		if fleet, err = parseFleetCredentials(data); err != nil {
			return err
		}
	}
	set, err := validateCredentialSet(machines, fleet)
	if err != nil {
		return err
	}
	c.publish(set)
	c.machineStamp, c.fleetStamp = machineStamp, fleetStamp
	return nil
}

func (c *Credentials) publish(set *credentialSet) {
	c.usageMu.Lock()
	for _, t := range set.fleet {
		if _, ok := c.usage[t.Name]; !ok {
			c.usage[t.Name] = &fleetUsage{}
		}
	}
	c.usageMu.Unlock()
	c.current.Store(set)
}

// Reload checks both files for changes and applies them.
func (c *Credentials) Reload() error {
	if c.machinePath == "" && c.fleetPath == "" {
		return nil
	}
	return c.load()
}

// Watch polls both credential files at the interval until ctx ends.
func (c *Credentials) Watch(ctx context.Context, interval time.Duration, onError func(error)) {
	pollReload(ctx, interval, c.Reload, onError)
}

// Authenticate checks the Authorization header for the URL machine ID. The
// per-machine token wins; otherwise any enabled, unexpired fleet token is
// accepted. Every candidate is compared in constant time before deciding.
func (c *Credentials) Authenticate(machineID, authorization string) (AuthMethod, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) {
		return "", false
	}
	supplied := []byte(strings.TrimPrefix(authorization, prefix))
	set := c.current.Load()
	if set == nil {
		return "", false
	}
	machineMatch := 0
	if expected, ok := set.machines[machineID]; ok {
		machineMatch = subtle.ConstantTimeCompare([]byte(expected), supplied)
	}
	now := time.Now()
	fleetIndex := -1
	for i, t := range set.fleet {
		usable := 0
		if t.usable(now) {
			usable = 1
		}
		equal := subtle.ConstantTimeCompare([]byte(t.Token), supplied)
		unmatched := 0
		if fleetIndex < 0 {
			unmatched = 1
		}
		fleetIndex = subtle.ConstantTimeSelect(equal&usable&unmatched, i, fleetIndex)
	}
	if machineMatch == 1 {
		return AuthMachine, true
	}
	if fleetIndex >= 0 {
		name := set.fleet[fleetIndex].Name
		c.recordUse(name, now)
		return fleetAuth(name), true
	}
	return "", false
}

func (c *Credentials) recordUse(name string, now time.Time) {
	c.usageMu.Lock()
	u, ok := c.usage[name]
	if !ok {
		u = &fleetUsage{}
		c.usage[name] = u
	}
	c.usageMu.Unlock()
	u.uses.Add(1)
	u.lastUsed.Store(now.UnixNano())
}

// MachineTokens returns the number of per-machine tokens in the current set.
func (c *Credentials) MachineTokens() int {
	if set := c.current.Load(); set != nil {
		return len(set.machines)
	}
	return 0
}

// FleetStatus lists the current fleet tokens with their in-memory usage
// counters. Token values are never included.
func (c *Credentials) FleetStatus(now time.Time) []FleetTokenStatus {
	status := []FleetTokenStatus{}
	set := c.current.Load()
	if set == nil {
		return status
	}
	c.usageMu.Lock()
	defer c.usageMu.Unlock()
	for _, t := range set.fleet {
		s := FleetTokenStatus{Name: t.Name, Enabled: t.usable(now)}
		if u, ok := c.usage[t.Name]; ok {
			s.Uses = u.uses.Load()
			if last := u.lastUsed.Load(); last != 0 {
				when := time.Unix(0, last).UTC()
				s.LastUsed = &when
			}
		}
		status = append(status, s)
	}
	return status
}
