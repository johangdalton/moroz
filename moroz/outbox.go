package moroz

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/groob/moroz/santa"
)

// TelemetryBatch is persisted before a successful Santa response. Its ID stays
// unchanged across retries, including a lost acknowledgement or process restart.
type TelemetryBatch struct {
	Version    int                      `json:"version"`
	ID         string                   `json:"id"`
	Kind       string                   `json:"kind"`
	MachineID  string                   `json:"machine_id"`
	ReceivedAt string                   `json:"received_at"`
	Events     []santa.EventUploadEvent `json:"events,omitempty"`
	Preflight  *santa.PreflightPayload  `json:"preflight,omitempty"`
}

type queuedBatch struct {
	name string
	size int64
}
type Outbox struct {
	mu                   sync.Mutex
	dir, endpoint, token string
	lock                 *os.File
	pending              []queuedBatch
	bytes, maxBytes      int64
	dead                 int
	quarantined          []string
	headName             string
	headFailures         int
	client               *http.Client
	wake                 chan struct{}
	closed               bool
}

// OutboxStats is a point-in-time view of the queue for the health endpoint.
type OutboxStats struct {
	Pending      int
	PendingBytes int64
	MaxPending   int
	MaxBytes     int64
	Dead         int
}

var pendingFile = regexp.MustCompile(`^\.pending-[0-9]+$`)

var batchFile = regexp.MustCompile(`^[0-9]{20}-[a-f0-9]{32}\.json$`)

const maxPendingBatches = 50000

// Re-encoding an accepted upload adds every event field name, so a stored
// batch can exceed the decoded request size, but never by more than a factor
// of two for the bounded number of events per batch.
const maxBatchBytes = 2 * maxDecodedBytes

// Consecutive read or decode failures of the head batch before it is
// dead-lettered so that later batches can be delivered.
const deadLetterAfterFailures = 20

// Subdirectories of the outbox. Files are moved there, never deleted.
const (
	deadDir    = "dead"    // rejected by the manager or unreadable during delivery
	corruptDir = "corrupt" // unparseable at startup
)

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// Sync each parent entry when creating the queue, including nested paths.
func durableMkdir(path string) error {
	path = filepath.Clean(path)
	if info, err := os.Stat(path); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("outbox parent is not a directory")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	if err := durableMkdir(parent); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0750); err != nil && !os.IsExist(err) {
		return err
	}
	return syncDirectory(parent)
}

// validateBatch checks that a stored file is a batch this writer produced.
func validateBatch(data []byte, name string) (TelemetryBatch, error) {
	var batch TelemetryBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		return batch, err
	}
	if batch.Version != 1 || batch.ID != strings.TrimSuffix(name[21:], ".json") || !validMachine(batch.MachineID) || (batch.Kind != "events" && batch.Kind != "preflight") {
		return batch, fmt.Errorf("batch metadata does not match file name")
	}
	return batch, nil
}

func NewOutbox(directory, endpoint, token string, maxBytes int64) (*Outbox, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid manager ingestion URL")
	}
	if len(token) < 32 || maxBytes < 1 {
		return nil, fmt.Errorf("ingestion token must have at least 32 characters and outbox size must be positive")
	}
	if err := durableMkdir(directory); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(directory, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("outbox already in use: %w", err)
	}
	q := &Outbox{dir: directory, endpoint: endpoint, token: token, maxBytes: maxBytes, lock: lock, wake: make(chan struct{}, 1), client: &http.Client{
		Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
	entries, err := os.ReadDir(directory)
	if err != nil {
		q.Close()
		return nil, err
	}
	for _, entry := range entries {
		// These temporary writes never reached the rename/acknowledgement boundary.
		if pendingFile.MatchString(entry.Name()) && entry.Type().IsRegular() {
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				q.Close()
				return nil, err
			}
			continue
		}
		if !batchFile.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			q.Close()
			return nil, err
		}
		// A corrupt file is quarantined, not fatal: exiting here would take the
		// sync endpoint down for the whole fleet on every restart.
		var reason string
		if !info.Mode().IsRegular() || info.Size() > maxBatchBytes {
			reason = "not a regular file within the batch size limit"
		} else if data, err := os.ReadFile(filepath.Join(directory, entry.Name())); err != nil {
			reason = err.Error()
		} else if _, err := validateBatch(data, entry.Name()); err != nil {
			reason = err.Error()
		}
		if reason != "" {
			if err := q.moveTo(entry.Name(), corruptDir); err != nil {
				q.Close()
				return nil, fmt.Errorf("cannot quarantine corrupt outbox file %s: %w", entry.Name(), err)
			}
			q.quarantined = append(q.quarantined, entry.Name()+": "+reason)
			continue
		}
		q.pending = append(q.pending, queuedBatch{entry.Name(), info.Size()})
		q.bytes += info.Size()
	}
	if dead, err := os.ReadDir(filepath.Join(directory, deadDir)); err == nil {
		q.dead = len(dead)
	} else if !os.IsNotExist(err) {
		q.Close()
		return nil, err
	}
	if err := syncDirectory(directory); err != nil {
		q.Close()
		return nil, err
	}
	return q, nil
}

// Quarantined lists the files moved to the corrupt directory at startup, each
// with the reason, so the caller can log them.
func (q *Outbox) Quarantined() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.quarantined...)
}

// moveTo relocates a batch file into a subdirectory of the outbox, durably.
func (q *Outbox) moveTo(name, sub string) error {
	target := filepath.Join(q.dir, sub)
	if err := durableMkdir(target); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(q.dir, name), filepath.Join(target, name)); err != nil {
		return err
	}
	if err := syncDirectory(target); err != nil {
		return err
	}
	return syncDirectory(q.dir)
}

// Close must be called after Run has stopped.
func (q *Outbox) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	q.client.CloseIdleConnections()
	return q.lock.Close()
}
func (q *Outbox) Pending() (int, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending), q.bytes
}
func (q *Outbox) Stats() OutboxStats {
	q.mu.Lock()
	defer q.mu.Unlock()
	return OutboxStats{Pending: len(q.pending), PendingBytes: q.bytes, MaxPending: maxPendingBatches, MaxBytes: q.maxBytes, Dead: q.dead}
}

func (q *Outbox) enqueue(ctx context.Context, batch TelemetryBatch) error {
	if !validMachine(batch.MachineID) {
		return fmt.Errorf("invalid machine ID")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	batch.Version = 1
	batch.ID = hex.EncodeToString(random[:])
	batch.ReceivedAt = time.Now().UTC().Format(time.RFC3339Nano)
	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(data) > maxBatchBytes {
		return fmt.Errorf("telemetry batch exceeds limit")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return fmt.Errorf("outbox is closed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(q.pending) >= maxPendingBatches || q.bytes+int64(len(data)) > q.maxBytes {
		return fmt.Errorf("outbox is full; retain events on the client and retry")
	}
	// One file per uploaded batch, never one per execution. A directory fsync
	// makes the committed filename durable before Santa receives its response.
	file, err := os.CreateTemp(q.dir, ".pending-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	name := fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), batch.ID)
	if err := os.Rename(temporary, filepath.Join(q.dir, name)); err != nil {
		return err
	}
	err = syncDirectory(q.dir)
	// Even on a directory sync error retain the visible batch; the client may
	// retry and the manager's stable event keys make that replay idempotent.
	q.pending = append(q.pending, queuedBatch{name, int64(len(data))})
	q.bytes += int64(len(data))
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return err
}
func (q *Outbox) Events(ctx context.Context, machine string, events []santa.EventPayload) error {
	if len(events) == 0 {
		return nil
	}
	if len(events) > 1000 {
		return fmt.Errorf("telemetry batch exceeds 1000 events")
	}
	records := make([]santa.EventUploadEvent, len(events))
	for i, event := range events {
		records[i] = event.EventInfo
	}
	return q.enqueue(ctx, TelemetryBatch{Kind: "events", MachineID: machine, Events: records})
}
func (q *Outbox) Preflight(ctx context.Context, machine string, p santa.PreflightPayload) error {
	// Push tokens are unrelated to telemetry and are not retained in this queue.
	p.PushNotificationToken = ""
	return q.enqueue(ctx, TelemetryBatch{Kind: "preflight", MachineID: machine, Preflight: &p})
}

// deadLettered reports a batch that was moved aside so delivery can continue.
type deadLettered struct {
	name, reason string
}

func (e deadLettered) Error() string {
	return fmt.Sprintf("batch %s moved to %s: %s", e.name, deadDir, e.reason)
}

// deadLetter moves the head batch out of the queue. The file is preserved in
// the dead directory for the operator; only a vanished file is dropped.
func (q *Outbox) deadLetter(head queuedBatch, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 || q.pending[0].name != head.name {
		return nil
	}
	if err := q.moveTo(head.name, deadDir); err != nil && !os.IsNotExist(err) {
		return err
	} else if err != nil {
		reason += " (file no longer exists)"
	} else {
		q.dead++
	}
	q.pending[0] = queuedBatch{}
	q.pending = q.pending[1:]
	q.bytes -= head.size
	q.headName, q.headFailures = "", 0
	return deadLettered{head.name, reason}
}

// headFailure counts consecutive local failures for the same head batch and
// dead-letters it once the limit is reached; the returned error is what Run
// should report.
func (q *Outbox) headFailure(head queuedBatch, err error) error {
	q.mu.Lock()
	if q.headName != head.name {
		q.headName, q.headFailures = head.name, 0
	}
	q.headFailures++
	failures := q.headFailures
	q.mu.Unlock()
	if failures < deadLetterAfterFailures {
		return err
	}
	return q.deadLetter(head, fmt.Sprintf("%d consecutive failures, last: %v", failures, err))
}

// deliverNext has a single consumer (Run). Producers never wait for HTTP I/O.
func (q *Outbox) deliverNext(ctx context.Context) (bool, error) {
	q.mu.Lock()
	if q.closed || len(q.pending) == 0 {
		q.mu.Unlock()
		return false, nil
	}
	pending := q.pending[0]
	q.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(q.dir, pending.name))
	if err != nil {
		return true, q.headFailure(pending, err)
	}
	batch, err := validateBatch(data, pending.name)
	if err != nil {
		return true, q.headFailure(pending, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, q.endpoint, bytes.NewReader(data))
	if err != nil {
		return true, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+q.token)
	response, err := q.client.Do(request)
	if err != nil {
		return true, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// A client error is specific to this batch and will not succeed on
		// retry. Timeouts, throttling and our own credentials being rejected
		// are not about the batch and keep the retry-with-backoff behaviour.
		switch code := response.StatusCode; {
		case code >= 400 && code < 500 && code != http.StatusRequestTimeout && code != http.StatusTooManyRequests && code != http.StatusUnauthorized && code != http.StatusForbidden:
			return true, q.deadLetter(pending, fmt.Sprintf("manager ingestion returned HTTP %d", code))
		}
		return true, fmt.Errorf("manager ingestion returned HTTP %d; batch retained", response.StatusCode)
	}
	var ack struct {
		Accepted bool   `json:"accepted"`
		ID       string `json:"batch_id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&ack); err != nil || !ack.Accepted || ack.ID != batch.ID {
		return true, fmt.Errorf("manager acknowledgement is invalid; batch retained")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := os.Remove(filepath.Join(q.dir, pending.name)); err != nil {
		return true, err
	}
	q.pending[0] = queuedBatch{}
	q.pending = q.pending[1:]
	q.bytes -= pending.size
	q.headName, q.headFailures = "", 0
	return true, syncDirectory(q.dir)
}
func (q *Outbox) Run(ctx context.Context, report func(error)) {
	delay := time.Second
	for ctx.Err() == nil {
		found, err := q.deliverNext(ctx)
		if err == nil && found {
			delay = time.Second
			continue
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if report != nil {
				report(err)
			}
			// A dead-lettered batch is out of the way; move on without backoff.
			if errors.As(err, new(deadLettered)) {
				delay = time.Second
				continue
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if delay < time.Minute {
				delay *= 2
				if delay > time.Minute {
					delay = time.Minute
				}
			}
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		}
	}
}

type telemetryUnavailable struct{ err error }

func (e telemetryUnavailable) Error() string {
	return "telemetry temporarily unavailable: " + strings.TrimSpace(e.err.Error())
}
func (e telemetryUnavailable) StatusCode() int { return http.StatusServiceUnavailable }
