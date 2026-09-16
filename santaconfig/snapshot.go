package santaconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/groob/moroz/santa"
)

type snapshot struct {
	version string
	// generation is the manifest's generation id (the directory under
	// generations/); empty for legacy directories without current.json.
	generation string
	configs    map[string]santa.Config
}

type manifest struct {
	Version    int      `json:"version"`
	Generation string   `json:"generation"`
	Files      []string `json:"files"`
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func validName(name string) bool {
	return safeName.MatchString(name) && !strings.Contains(name, "..")
}

// configSource returns the snapshot version, the manifest generation id
// (empty for legacy directories) and the policy files to load.
func configSource(root string) (string, string, []string, error) {
	content, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err == nil {
		var m manifest
		if err := json.Unmarshal(content, &m); err != nil {
			return "", "", nil, err
		}
		if m.Version != 1 || !validName(m.Generation) {
			return "", "", nil, fmt.Errorf("invalid policy manifest")
		}
		paths := make([]string, 0, len(m.Files))
		for _, name := range m.Files {
			if !strings.HasSuffix(name, ".toml") || !validName(strings.TrimSuffix(name, ".toml")) {
				return "", "", nil, fmt.Errorf("invalid policy filename %q", name)
			}
			paths = append(paths, filepath.Join(root, "generations", m.Generation, name))
		}
		return fmt.Sprintf("manifest:%x", sha256.Sum256(content)), m.Generation, paths, nil
	}
	if !os.IsNotExist(err) {
		return "", "", nil, err
	}
	// Legacy, manually maintained config directories remain supported. Metadata is
	// checked only by the reload worker, never on the request path.
	paths, err := filepath.Glob(filepath.Join(root, "*.toml"))
	if err != nil {
		return "", "", nil, err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return "", "", nil, err
		}
		fmt.Fprintf(h, "%s:%d:%d\n", path, stat.Size(), stat.ModTime().UnixNano())
	}
	return fmt.Sprintf("legacy:%x", h.Sum(nil)), "", paths, nil
}

var (
	sha256Hex   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	cdhashHex   = regexp.MustCompile(`^[a-f0-9]{40}$`)
	teamIDForm  = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	signingForm = regexp.MustCompile(`^(?:[A-Z0-9]{10}|platform):[^\s:]+$`)
)

// validateRules rejects rules Santa would ignore or misapply. Hex identifiers
// are normalised to lowercase in place.
func validateRules(rules []santa.Rule) error {
	for i := range rules {
		rule := &rules[i]
		if rule.RuleType == santa.RuleTypeUnknown {
			return fmt.Errorf("rule %d: rule_type is required", i+1)
		}
		if rule.Policy == santa.PolicyUnknown {
			return fmt.Errorf("rule %d: policy is required", i+1)
		}
		var format *regexp.Regexp
		var expected string
		switch rule.RuleType {
		case santa.Binary, santa.Certificate:
			rule.Identifier = strings.ToLower(rule.Identifier)
			format, expected = sha256Hex, "a 64-character hex SHA-256"
		case santa.CdHash:
			rule.Identifier = strings.ToLower(rule.Identifier)
			format, expected = cdhashHex, "a 40-character hex code directory hash"
		case santa.TeamID:
			format, expected = teamIDForm, "a 10-character Apple team ID"
		case santa.SigningID:
			format, expected = signingForm, "TEAMID:signing.id or platform:signing.id"
		default:
			return fmt.Errorf("rule %d: unsupported rule_type %d", i+1, rule.RuleType)
		}
		if !format.MatchString(rule.Identifier) {
			ruleType, _ := rule.RuleType.MarshalText()
			return fmt.Errorf("rule %d (%s): identifier %q must be %s", i+1, ruleType, rule.Identifier, expected)
		}
		if err := santa.ValidateRule(*rule); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

// loadConfigFile parses and validates one policy file. Unknown keys are an
// error: a misspelt key would otherwise be dropped silently, for example a
// rule with "sha256" instead of "identifier" yields an empty identifier.
func loadConfigFile(path string) (santa.Config, error) {
	var config santa.Config
	stat, err := os.Lstat(path)
	if err != nil {
		return config, err
	}
	if !stat.Mode().IsRegular() {
		return config, fmt.Errorf("policy is not a regular file: %s", path)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}
	metadata, err := toml.Decode(string(content), &config)
	if err != nil {
		return config, fmt.Errorf("decode %s: %w", path, err)
	}
	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, key := range undecoded {
			keys[i] = key.String()
		}
		return config, fmt.Errorf("decode %s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if err := config.Preflight.Validate(); err != nil {
		return config, fmt.Errorf("validate %s: %w", path, err)
	}
	if err := validateRules(config.Rules); err != nil {
		return config, fmt.Errorf("validate %s: %w", path, err)
	}
	config.MachineID = strings.TrimSuffix(filepath.Base(path), ".toml")
	if !validName(config.MachineID) {
		return config, fmt.Errorf("invalid machine ID %q", config.MachineID)
	}
	return config, nil
}

// Reload builds a new snapshot separately, then publishes it in one atomic swap.
// Errors preserve the last valid snapshot. Unchanged sources are not reparsed.
func (f *FileRepo) Reload(ctx context.Context) error {
	f.reloadMu.Lock()
	defer f.reloadMu.Unlock()
	version, generation, paths, err := configSource(f.configPath)
	if err != nil {
		return err
	}
	if old := f.current.Load(); old != nil && old.version == version {
		return nil
	}
	next := &snapshot{version: version, generation: generation, configs: make(map[string]santa.Config, len(paths))}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		config, err := loadConfigFile(path)
		if err != nil {
			return err
		}
		if _, exists := next.configs[config.MachineID]; exists {
			return fmt.Errorf("duplicate config %q", config.MachineID)
		}
		next.configs[config.MachineID] = config
	}
	if _, ok := next.configs["global"]; !ok {
		return fmt.Errorf("policy snapshot has no global.toml")
	}
	f.current.Store(next)
	return nil
}

// Watch checks the small publication manifest at the configured interval.
func (f *FileRepo) Watch(ctx context.Context, interval time.Duration, onError func(error)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := f.Reload(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// ThrottleErrors returns an error callback that forwards to log only when the
// error text differs from the previous one or interval has passed since the
// last forwarded error. repeats counts the suppressed calls in between.
func ThrottleErrors(interval time.Duration, log func(err error, repeats int)) func(error) {
	return throttleErrors(interval, log, time.Now)
}

func throttleErrors(interval time.Duration, log func(err error, repeats int), now func() time.Time) func(error) {
	var (
		mu       sync.Mutex
		last     string
		loggedAt time.Time
		repeats  int
	)
	return func(err error) {
		mu.Lock()
		defer mu.Unlock()
		text := err.Error()
		t := now()
		if text == last && t.Sub(loggedAt) < interval {
			repeats++
			return
		}
		log(err, repeats)
		last, loggedAt, repeats = text, t, 0
	}
}
