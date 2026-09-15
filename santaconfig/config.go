package santaconfig

import (
	"context"
	"fmt"
	"github.com/groob/moroz/santa"
	"sort"
	"sync"
	"sync/atomic"
)

func NewFileRepo(path string) *FileRepo { return &FileRepo{configPath: path} }

type FileRepo struct {
	reloadMu   sync.Mutex
	current    atomic.Pointer[snapshot]
	configPath string
}

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
