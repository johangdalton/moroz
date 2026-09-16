package moroz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// IdentityRecord binds a machine ID to the serial number it first reported
// (trust on first use). Operators reset a binding by deleting the entry.
type IdentityRecord struct {
	MachineID string    `json:"machine_id"`
	SerialNum string    `json:"serial_num"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	LastAuth  string    `json:"last_auth"`
}

type identityFile struct {
	Version  int                       `json:"version"`
	Machines map[string]IdentityRecord `json:"machines"`
}

// identityFlushInterval bounds how often the store is written; tests shorten it.
var identityFlushInterval = time.Second

// IdentityStore keeps the bindings in memory and persists them with the
// temp+fsync+rename pattern, coalescing changes into at most one write per
// flush interval. External edits to the file are picked up on the next tick.
type IdentityStore struct {
	path       string
	mu         sync.Mutex
	records    map[string]IdentityRecord
	dirty      bool
	stamp      fileStamp
	mismatches atomic.Int64
	warnings   []string
}

// identityMismatchError is returned to Santa as 403 without the serials; the
// service logs them separately.
type identityMismatchError struct {
	machineID, bound, reported string
}

func (e identityMismatchError) Error() string   { return "identity mismatch" }
func (e identityMismatchError) StatusCode() int { return http.StatusForbidden }

// OpenIdentityStore loads the store at path. It never fails: a corrupt file
// is moved to <path>.corrupt-<timestamp> and reported through Warnings, and
// a fresh store starts empty.
func OpenIdentityStore(path string) *IdentityStore {
	s := &IdentityStore{path: path, records: make(map[string]IdentityRecord)}
	stamp, err := stampFile(path)
	if err != nil {
		s.warnings = append(s.warnings, fmt.Sprintf("cannot stat identity store: %v", err))
		return s
	}
	s.stamp = stamp
	if !stamp.exists {
		return s
	}
	records, err := readIdentityFile(path)
	if err != nil {
		quarantine := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405.000000000Z"))
		if renameErr := os.Rename(path, quarantine); renameErr != nil {
			s.warnings = append(s.warnings, fmt.Sprintf("corrupt identity store %s (%v) could not be quarantined: %v; it will be overwritten", path, err, renameErr))
		} else {
			s.warnings = append(s.warnings, fmt.Sprintf("corrupt identity store quarantined to %s: %v", quarantine, err))
		}
		s.stamp = fileStamp{}
		return s
	}
	s.records = records
	return s
}

func readIdentityFile(path string) (map[string]IdentityRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file identityFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version != 1 || file.Machines == nil {
		return nil, fmt.Errorf("unsupported identity store format")
	}
	for id, rec := range file.Machines {
		if !validMachine(id) || rec.MachineID != id {
			return nil, fmt.Errorf("invalid identity entry %q", id)
		}
	}
	return file.Machines, nil
}

// Warnings lists startup problems for the caller to log.
func (s *IdentityStore) Warnings() []string { return append([]string(nil), s.warnings...) }

// Bind creates the binding on first sight or checks it afterwards. An empty
// serial is accepted without binding. A different serial returns an
// identityMismatchError and increments the counter.
func (s *IdentityStore) Bind(machineID, serial string, auth AuthMethod, now time.Time) error {
	if serial == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[machineID]
	if !ok {
		s.records[machineID] = IdentityRecord{MachineID: machineID, SerialNum: serial, FirstSeen: now.UTC(), LastSeen: now.UTC(), LastAuth: string(auth)}
		s.dirty = true
		return nil
	}
	if rec.SerialNum != serial {
		s.mismatches.Add(1)
		return identityMismatchError{machineID: machineID, bound: rec.SerialNum, reported: serial}
	}
	rec.LastSeen, rec.LastAuth = now.UTC(), string(auth)
	s.records[machineID] = rec
	s.dirty = true
	return nil
}

// Count returns the number of bound machines.
func (s *IdentityStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Mismatches returns how many preflights were refused since startup.
func (s *IdentityStore) Mismatches() int64 { return s.mismatches.Load() }

// Flush writes the store if it changed since the last write.
func (s *IdentityStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	data, err := json.MarshalIndent(identityFile{Version: 1, Machines: s.records}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, ".identities-", append(data, '\n'), 0600); err != nil {
		return err
	}
	s.dirty = false
	if stamp, err := stampFile(s.path); err == nil {
		s.stamp = stamp
	}
	return nil
}

// reloadIfChanged adopts an operator's edit of the file (for example a
// deleted entry). Unflushed changes from the last interval are dropped in
// favour of the edited file; an unreadable edit is reported and ignored.
func (s *IdentityStore) reloadIfChanged() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp, err := stampFile(s.path)
	if err != nil || stamp == s.stamp {
		return err
	}
	if !stamp.exists {
		s.records = make(map[string]IdentityRecord)
		s.stamp = stamp
		s.dirty = false
		return nil
	}
	records, err := readIdentityFile(s.path)
	if err != nil {
		s.stamp = stamp
		return fmt.Errorf("identity store edited on disk but unreadable; keeping in-memory bindings: %w", err)
	}
	s.records = records
	s.stamp = stamp
	s.dirty = false
	return nil
}

// Run flushes coalesced changes once per interval and adopts external edits.
// It performs a final flush when ctx ends.
func (s *IdentityStore) Run(ctx context.Context, onError func(error)) {
	report := func(err error) {
		if err != nil && onError != nil {
			onError(err)
		}
	}
	ticker := time.NewTicker(identityFlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			report(s.Flush())
			return
		case <-ticker.C:
			report(s.reloadIfChanged())
			report(s.Flush())
		}
	}
}
