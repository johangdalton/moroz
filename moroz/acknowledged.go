package moroz

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/groob/moroz/santa"
)

// Acknowledgement records the policy a machine confirmed at postflight: the
// manifest generation and per-machine config digest it received, and when it
// last completed a CLEAN sync. The server uses it to decide between a CLEAN
// and a NORMAL (incremental) sync at the next preflight.
type Acknowledgement struct {
	MachineID      string         `json:"machine_id"`
	Generation     string         `json:"generation,omitempty"`
	ConfigDigest   string         `json:"config_digest"`
	SyncType       santa.SyncType `json:"sync_type,omitempty"`
	RulesHash      string         `json:"rules_hash,omitempty"`
	AcknowledgedAt time.Time      `json:"acknowledged_at"`
	LastCleanAt    time.Time      `json:"last_clean_at,omitempty"`
}

type acknowledgementFile struct {
	Version  int                        `json:"version"`
	Machines map[string]Acknowledgement `json:"machines"`
}

// AckStore keeps acknowledgements in memory and, when a path is set,
// persists them like the identity store: temp+fsync+rename, coalesced into at
// most one write per flush interval, corrupt files quarantined at startup.
// An empty path keeps the store in memory only (lost on restart).
type AckStore struct {
	path     string
	mu       sync.Mutex
	records  map[string]Acknowledgement
	dirty    bool
	stamp    fileStamp
	warnings []string
}

// OpenAckStore loads the store at path, or returns an in-memory store for an
// empty path. It never fails: a corrupt file is moved to
// <path>.corrupt-<timestamp>, reported through Warnings, and every machine
// falls back to a CLEAN sync on its next preflight.
func OpenAckStore(path string) *AckStore {
	s := &AckStore{path: path, records: make(map[string]Acknowledgement)}
	if path == "" {
		return s
	}
	stamp, err := stampFile(path)
	if err != nil {
		s.warnings = append(s.warnings, fmt.Sprintf("cannot stat acknowledgement store: %v", err))
		return s
	}
	s.stamp = stamp
	if !stamp.exists {
		return s
	}
	records, err := readAckFile(path)
	if err != nil {
		quarantine := fmt.Sprintf("%s.corrupt-%s", path, time.Now().UTC().Format("20060102T150405.000000000Z"))
		if renameErr := os.Rename(path, quarantine); renameErr != nil {
			s.warnings = append(s.warnings, fmt.Sprintf("corrupt acknowledgement store %s (%v) could not be quarantined: %v; it will be overwritten", path, err, renameErr))
		} else {
			s.warnings = append(s.warnings, fmt.Sprintf("corrupt acknowledgement store quarantined to %s: %v", quarantine, err))
		}
		s.stamp = fileStamp{}
		return s
	}
	s.records = records
	return s
}

func readAckFile(path string) (map[string]Acknowledgement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var file acknowledgementFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, err
	}
	if file.Version != 1 || file.Machines == nil {
		return nil, fmt.Errorf("unsupported acknowledgement store format")
	}
	for id, rec := range file.Machines {
		if !validMachine(id) || rec.MachineID != id || rec.ConfigDigest == "" {
			return nil, fmt.Errorf("invalid acknowledgement entry %q", id)
		}
	}
	return file.Machines, nil
}

// Warnings lists startup problems for the caller to log.
func (s *AckStore) Warnings() []string { return append([]string(nil), s.warnings...) }

// Get returns the machine's last acknowledgement.
func (s *AckStore) Get(machineID string) (Acknowledgement, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.records[machineID]
	return rec, ok
}

// Put records an acknowledgement. When clean is set the sync that completed
// was a CLEAN sync and the periodic clean clock restarts; otherwise the
// previous LastCleanAt is carried over.
func (s *AckStore) Put(rec Acknowledgement, clean bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous, ok := s.records[rec.MachineID]; ok && !clean {
		rec.LastCleanAt = previous.LastCleanAt
	}
	if clean {
		rec.LastCleanAt = rec.AcknowledgedAt
	}
	s.records[rec.MachineID] = rec
	s.dirty = true
}

// Count returns the number of machines with an acknowledgement.
func (s *AckStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// Flush writes the store if it changed since the last write.
func (s *AckStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty || s.path == "" {
		s.dirty = false
		return nil
	}
	data, err := json.MarshalIndent(acknowledgementFile{Version: 1, Machines: s.records}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, ".acknowledged-", append(data, '\n'), 0600); err != nil {
		return err
	}
	s.dirty = false
	if stamp, err := stampFile(s.path); err == nil {
		s.stamp = stamp
	}
	return nil
}

// reloadIfChanged adopts an operator's edit (for example a deleted entry to
// force one machine's next sync to be CLEAN). Unflushed changes from the last
// interval are dropped in favour of the edited file.
func (s *AckStore) reloadIfChanged() error {
	if s.path == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stamp, err := stampFile(s.path)
	if err != nil || stamp == s.stamp {
		return err
	}
	if !stamp.exists {
		s.records = make(map[string]Acknowledgement)
		s.stamp = stamp
		s.dirty = false
		return nil
	}
	records, err := readAckFile(s.path)
	if err != nil {
		s.stamp = stamp
		return fmt.Errorf("acknowledgement store edited on disk but unreadable; keeping in-memory state: %w", err)
	}
	s.records = records
	s.stamp = stamp
	s.dirty = false
	return nil
}

// Run flushes coalesced changes once per interval (shared with the identity
// store) and adopts external edits. It performs a final flush when ctx ends.
func (s *AckStore) Run(ctx context.Context, onError func(error)) {
	if s.path == "" {
		<-ctx.Done()
		return
	}
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

// Periodic CLEAN safety net: a machine is forced through a CLEAN sync when its
// last one is older than cleanBaseDays plus a per-machine dither of up to
// cleanDitherDays-1 days, so a fleet does not clean on the same day.
const (
	cleanBaseDays   = 7
	cleanDitherDays = 11
)

// cleanInterval returns the machine's dithered CLEAN period:
// 7 + (sha256(machine_id) mod 11) days.
func cleanInterval(machineID string) time.Duration {
	sum := sha256.Sum256([]byte(machineID))
	var value uint64
	for _, b := range sum[:8] {
		value = value<<8 | uint64(b)
	}
	days := cleanBaseDays + int(value%cleanDitherDays)
	return time.Duration(days) * 24 * time.Hour
}

// cleanDue reports whether the periodic CLEAN is due for the acknowledgement
// at now. A machine that never completed a CLEAN sync is always due.
func cleanDue(rec Acknowledgement, now time.Time) bool {
	if rec.LastCleanAt.IsZero() {
		return true
	}
	return now.Sub(rec.LastCleanAt) >= cleanInterval(rec.MachineID)
}
