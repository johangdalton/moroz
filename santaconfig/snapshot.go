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
	"time"

	"github.com/BurntSushi/toml"
	"github.com/groob/moroz/santa"
)

type snapshot struct {
	version string
	configs map[string]santa.Config
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

func configSource(root string) (string, []string, error) {
	content, err := os.ReadFile(filepath.Join(root, "current.json"))
	if err == nil {
		var m manifest
		if err := json.Unmarshal(content, &m); err != nil {
			return "", nil, err
		}
		if m.Version != 1 || !validName(m.Generation) {
			return "", nil, fmt.Errorf("invalid policy manifest")
		}
		paths := make([]string, 0, len(m.Files))
		for _, name := range m.Files {
			if !strings.HasSuffix(name, ".toml") || !validName(strings.TrimSuffix(name, ".toml")) {
				return "", nil, fmt.Errorf("invalid policy filename %q", name)
			}
			paths = append(paths, filepath.Join(root, "generations", m.Generation, name))
		}
		return fmt.Sprintf("manifest:%x", sha256.Sum256(content)), paths, nil
	}
	if !os.IsNotExist(err) {
		return "", nil, err
	}
	// Legacy, manually maintained config directories remain supported. Metadata is
	// checked only by the reload worker, never on the request path.
	paths, err := filepath.Glob(filepath.Join(root, "*.toml"))
	if err != nil {
		return "", nil, err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		stat, err := os.Stat(path)
		if err != nil {
			return "", nil, err
		}
		fmt.Fprintf(h, "%s:%d:%d\n", path, stat.Size(), stat.ModTime().UnixNano())
	}
	return fmt.Sprintf("legacy:%x", h.Sum(nil)), paths, nil
}

// Reload builds a new snapshot separately, then publishes it in one atomic swap.
// Errors preserve the last valid snapshot. Unchanged sources are not reparsed.
func (f *FileRepo) Reload(ctx context.Context) error {
	f.reloadMu.Lock()
	defer f.reloadMu.Unlock()
	version, paths, err := configSource(f.configPath)
	if err != nil {
		return err
	}
	if old := f.current.Load(); old != nil && old.version == version {
		return nil
	}
	next := &snapshot{version: version, configs: make(map[string]santa.Config, len(paths))}
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return err
		}
		stat, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !stat.Mode().IsRegular() {
			return fmt.Errorf("policy is not a regular file: %s", path)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var config santa.Config
		if err := toml.Unmarshal(content, &config); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
		config.MachineID = strings.TrimSuffix(filepath.Base(path), ".toml")
		if !validName(config.MachineID) {
			return fmt.Errorf("invalid machine ID %q", config.MachineID)
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
