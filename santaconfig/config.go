package santaconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/groob/moroz/santa"
)

func NewFileRepo(path string) *FileRepo {
	return &FileRepo{configPath: path, historic: make(map[string]map[string]santa.Config)}
}

type FileRepo struct {
	reloadMu   sync.Mutex
	current    atomic.Pointer[snapshot]
	configPath string
	// historic caches configs parsed from earlier generations for the
	// incremental sync diff, keyed by generation then machine ID.
	historicMu sync.Mutex
	historic   map[string]map[string]santa.Config
}

// maxHistoricGenerations bounds the diff cache; it is emptied when full.
const maxHistoricGenerations = 8

func (f *FileRepo) loaded(ctx context.Context) (*snapshot, error) {
	if s := f.current.Load(); s != nil {
		return s, nil
	}
	if err := f.Reload(ctx); err != nil {
		return nil, err
	}
	return f.current.Load(), nil
}

func (f *FileRepo) AllConfigs(ctx context.Context) ([]santa.Config, error) {
	s, err := f.loaded(ctx)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(s.configs))
	for name := range s.configs {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]santa.Config, 0, len(names))
	for _, name := range names {
		result = append(result, s.configs[name])
	}
	return result, nil
}

// Config returns an immutable snapshot value. Callers must not mutate its slices
// or pointer fields. No disk access or global write lock is needed after startup.
func (f *FileRepo) Config(ctx context.Context, machineID string) (santa.Config, error) {
	s, err := f.loaded(ctx)
	if err != nil {
		return santa.Config{}, err
	}
	c, ok := s.configs[machineID]
	if !ok {
		return c, fmt.Errorf("configuration %q not found", machineID)
	}
	return c, nil
}

// Generation reports the version of the loaded snapshot for health checks.
func (f *FileRepo) Generation() (string, bool) {
	s := f.current.Load()
	if s == nil {
		return "", false
	}
	return s.version, true
}

// EffectiveConfig returns the config Santa should receive for machineID (its
// own file, otherwise global.toml) and the manifest generation it came from,
// both read from the same snapshot. The generation is empty for legacy
// directories without current.json.
func (f *FileRepo) EffectiveConfig(ctx context.Context, machineID string) (santa.Config, string, error) {
	s, err := f.loaded(ctx)
	if err != nil {
		return santa.Config{}, "", err
	}
	if c, ok := s.configs[machineID]; ok {
		return c, s.generation, nil
	}
	c, ok := s.configs["global"]
	if !ok {
		return santa.Config{}, s.generation, fmt.Errorf("configuration %q not found", "global")
	}
	return c, s.generation, nil
}

// HistoricConfig loads the effective config machineID had in an earlier
// generation from generations/<generation>/ on disk: the machine's own file if
// it existed, otherwise that generation's global.toml. It fails when the
// generation directory was pruned or the file no longer validates.
func (f *FileRepo) HistoricConfig(ctx context.Context, generation, machineID string) (santa.Config, error) {
	if !validName(generation) || !validName(machineID) {
		return santa.Config{}, fmt.Errorf("invalid generation or machine ID")
	}
	f.historicMu.Lock()
	if byMachine, ok := f.historic[generation]; ok {
		if c, ok := byMachine[machineID]; ok {
			f.historicMu.Unlock()
			return c, nil
		}
	}
	f.historicMu.Unlock()
	if err := ctx.Err(); err != nil {
		return santa.Config{}, err
	}
	dir := filepath.Join(f.configPath, "generations", generation)
	path := filepath.Join(dir, machineID+".toml")
	if _, err := os.Lstat(path); err != nil {
		if !os.IsNotExist(err) {
			return santa.Config{}, err
		}
		path = filepath.Join(dir, "global.toml")
	}
	config, err := loadConfigFile(path)
	if err != nil {
		return santa.Config{}, err
	}
	f.historicMu.Lock()
	defer f.historicMu.Unlock()
	if _, ok := f.historic[generation]; !ok {
		if len(f.historic) >= maxHistoricGenerations {
			f.historic = make(map[string]map[string]santa.Config)
		}
		f.historic[generation] = make(map[string]santa.Config)
	}
	f.historic[generation][machineID] = config
	return config, nil
}
