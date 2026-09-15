package moroz

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	client               *http.Client
	wake                 chan struct{}
	closed               bool
}

var pendingFile = regexp.MustCompile(`^\.pending-[0-9]+$`)

var batchFile = regexp.MustCompile(`^[0-9]{20}-[a-f0-9]{32}\.json$`)

const maxPendingBatches = 50000

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
		if !info.Mode().IsRegular() || info.Size() > 20<<20 {
			q.Close()
			return nil, fmt.Errorf("invalid outbox file %s", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			q.Close()
			return nil, err
		}
		var batch TelemetryBatch
		if err := json.Unmarshal(data, &batch); err != nil || batch.Version != 1 || batch.ID != strings.TrimSuffix(entry.Name()[21:], ".json") || !validMachine(batch.MachineID) || (batch.Kind != "events" && batch.Kind != "preflight") {
			q.Close()
			return nil, fmt.Errorf("corrupt outbox file %s; preserve it for recovery", entry.Name())
		}
		q.pending = append(q.pending, queuedBatch{entry.Name(), info.Size()})
		q.bytes += info.Size()
	}
	if err := syncDirectory(directory); err != nil {
		q.Close()
		return nil, err
	}
	return q, nil
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
	if len(data) > 20<<20 {
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
		return true, err
	}
	var batch TelemetryBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		return true, err
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
