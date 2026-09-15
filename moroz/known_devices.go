package moroz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// KnownDevice is one entry of the manager-written known-devices file.
type KnownDevice struct {
	Serial string `json:"serial"`
	Name   string `json:"name"`
}

// ErrKnownDevicesMissing is returned once when the file is absent, at
// startup and again after it disappears. Gating is off while it is missing.
var ErrKnownDevicesMissing = errors.New("known-devices file is missing; known-device gating is off until it appears")

// KnownDevices is the optional allowlist of machine IDs (and their serials)
// that may authenticate with a fleet token. The file is read-only for this
// process and reloaded when it changes.
type KnownDevices struct {
	path     string
	current  atomic.Pointer[map[string]KnownDevice] // nil while not loaded
	reloadMu sync.Mutex
	stamp    fileStamp
	reported bool
}

func NewKnownDevices(path string) *KnownDevices {
	return &KnownDevices{path: path}
}

func parseKnownDevices(data []byte) (map[string]KnownDevice, error) {
	var devices map[string]KnownDevice
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&devices); err != nil || devices == nil {
		return nil, fmt.Errorf("invalid known-devices file: %v", err)
	}
	for id := range devices {
		if !validMachine(id) {
			return nil, fmt.Errorf("invalid known-devices entry %q", id)
		}
	}
	return devices, nil
}

// Reload re-reads the file when it changed. A missing file unloads the
// allowlist and returns ErrKnownDevicesMissing once per disappearance; an
// invalid file keeps the previous allowlist.
func (k *KnownDevices) Reload() error {
	k.reloadMu.Lock()
	defer k.reloadMu.Unlock()
	stamp, err := stampFile(k.path)
	if err != nil {
		return fmt.Errorf("known-devices: %w", err)
	}
	if !stamp.exists {
		k.current.Store(nil)
		k.stamp = stamp
		if k.reported {
			return nil
		}
		k.reported = true
		return ErrKnownDevicesMissing
	}
	if k.current.Load() != nil && stamp == k.stamp {
		return nil
	}
	data, err := os.ReadFile(k.path)
	if err != nil {
		return fmt.Errorf("cannot read known-devices: %w", err)
	}
	devices, err := parseKnownDevices(data)
	if err != nil {
		return err
	}
	k.current.Store(&devices)
	k.stamp = stamp
	k.reported = false
	return nil
}

// Watch polls the file at the interval until ctx ends.
func (k *KnownDevices) Watch(ctx context.Context, interval time.Duration, onError func(error)) {
	pollReload(ctx, interval, k.Reload, onError)
}

// Loaded reports whether an allowlist is in effect.
func (k *KnownDevices) Loaded() bool { return k != nil && k.current.Load() != nil }

// Lookup returns the entry for a machine ID from the loaded allowlist.
func (k *KnownDevices) Lookup(id string) (KnownDevice, bool) {
	if k == nil {
		return KnownDevice{}, false
	}
	devices := k.current.Load()
	if devices == nil {
		return KnownDevice{}, false
	}
	d, ok := (*devices)[id]
	return d, ok
}

// Count returns the number of entries, or -1 when no allowlist is loaded.
func (k *KnownDevices) Count() int {
	if !k.Loaded() {
		return -1
	}
	return len(*k.current.Load())
}
