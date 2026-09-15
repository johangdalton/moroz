package moroz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/groob/moroz/santa"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// One durable append per accepted batch replaces one file per event. The JSONL
// format includes machine identity and is suitable for a file log collector.
func (svc *SantaService) persistBatch(ctx context.Context, machine string, events []santa.EventPayload) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	for _, event := range events {
		row := struct {
			MachineID string `json:"machine_id"`
			EventType string `json:"event_type"`
			santa.EventUploadEvent
		}{machine, "execution", event.EventInfo}
		if err := encoder.Encode(row); err != nil {
			return err
		}
	}
	if buffer.Len() == 0 {
		return nil
	}
	svc.eventMu.Lock()
	defer svc.eventMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(svc.eventDir, 0750); err != nil {
		return err
	}
	day := time.Now().UTC().Format("2006-01-02")
	file, err := os.OpenFile(filepath.Join(svc.eventDir, day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(buffer.Bytes())
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if svc.eventLogDay != day {
		if err := svc.pruneEventLogs(time.Now().UTC()); err != nil {
			return err
		}
		svc.eventLogDay = day
	}
	return nil
}

func (svc *SantaService) pruneEventLogs(now time.Time) error {
	entries, err := os.ReadDir(svc.eventDir)
	if err != nil {
		return err
	}
	cutoff := now.AddDate(0, 0, -svc.eventRetentionDays).Format("2006-01-02")
	for _, entry := range entries {
		// Only delete this writer's dated JSONL files; preserve legacy data/directories.
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(name, ".jsonl")
		if _, err := time.Parse("2006-01-02", day); err != nil {
			continue
		}
		if day < cutoff {
			if err := os.Remove(filepath.Join(svc.eventDir, name)); err != nil {
				return fmt.Errorf("prune event log: %w", err)
			}
		}
	}
	return nil
}

func (svc *SantaService) SetEventRetentionDays(days int) { svc.eventRetentionDays = days }
