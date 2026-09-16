package moroz

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log/level"
	"github.com/pkg/errors"

	"github.com/groob/moroz/santa"
)

// Per-event limits applied before an event is stored or forwarded. Santa's
// own values are far smaller; these bound what a local user can make the
// server retain.
const (
	maxEventString       = 1024
	maxSigningChain      = 10
	maxEventList         = 32
	maxEntitlementBytes  = 16 << 10
	entitlementsTooLarge = `{"entitlements_filtered":true}`
)

// truncate cuts s to at most maxEventString bytes on a UTF-8 boundary.
func truncate(s string) string {
	if len(s) <= maxEventString {
		return s
	}
	cut := maxEventString
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func truncateList(list []string) []string {
	if len(list) > maxEventList {
		list = list[:maxEventList]
	}
	for i := range list {
		list[i] = truncate(list[i])
	}
	return list
}

// sanitizeEvent bounds every free-form field of an uploaded event in place.
// Field names and values otherwise stay exactly as Santa sent them.
func sanitizeEvent(ev *santa.EventUploadEvent) {
	for _, field := range []*string{&ev.Decision, &ev.ExecutingUser, &ev.FileBundleExecutableRelPath, &ev.FileBundleHash, &ev.FileBundleID,
		&ev.FileBundleName, &ev.FileBundlePath, &ev.FileBundleShortVersionString, &ev.FileBundleVersion, &ev.FileName, &ev.FilePath,
		&ev.FileSHA256, &ev.ParentName, &ev.QuarantineAgentBundleID, &ev.QuarantineDataUrl, &ev.QuarantineRefererUrl, &ev.SigningID,
		&ev.TeamID, &ev.CdHash, &ev.SigningStatus} {
		*field = truncate(*field)
	}
	ev.LoggedInUsers = truncateList(ev.LoggedInUsers)
	ev.CurrentSessions = truncateList(ev.CurrentSessions)
	if len(ev.SigningChain) > maxSigningChain {
		ev.SigningChain = ev.SigningChain[:maxSigningChain]
	}
	for i := range ev.SigningChain {
		entry := &ev.SigningChain[i]
		entry.CertificateName, entry.Organization, entry.OrganizationalUnit, entry.SHA256 = truncate(entry.CertificateName), truncate(entry.Organization), truncate(entry.OrganizationalUnit), truncate(entry.SHA256)
	}
	if len(ev.EntitlementInfo) > maxEntitlementBytes {
		ev.EntitlementInfo = json.RawMessage(entitlementsTooLarge)
	}
}

// UploadEvent forwards a batch. Events whose file_sha256 is malformed are
// skipped and counted (invalid_events_skipped on /healthz) instead of failing
// the batch, so one bad event cannot make Santa retry the other 99 forever.
func (svc *SantaService) UploadEvent(ctx context.Context, machineID string, events []santa.EventPayload) error {
	if !validMachine(machineID) {
		return fmt.Errorf("invalid machine ID")
	}
	valid := make([]santa.EventPayload, 0, len(events))
	for _, ev := range events {
		if !fileHash.MatchString(ev.FileSHA) {
			svc.invalidEvents.Add(1)
			continue
		}
		valid = append(valid, ev)
	}
	if skipped := len(events) - len(valid); skipped > 0 {
		level.Warn(svc.logger).Log("msg", "events with malformed file_sha256 skipped", "machine_id", machineID, "skipped", skipped, "accepted", len(valid))
	}
	events = valid
	if len(events) == 0 {
		return nil
	}
	if svc.outbox != nil {
		if err := svc.outbox.Events(ctx, machineID, events); err != nil {
			return telemetryUnavailable{err}
		}
		return nil
	}
	if !svc.flPersistEvents {
		return nil
	}
	return svc.persistBatch(ctx, machineID, events)
}

type eventRequest struct {
	MachineID string
	events    []santa.EventPayload
}

type eventResponse struct {
	*santa.EventUploadResponse
	Err error `json:"error,omitempty"`
}

func (r eventResponse) Failed() error { return r.Err }

func makeEventUploadEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(eventRequest)
		err := svc.UploadEvent(ctx, req.MachineID, req.events)
		return eventResponse{
			EventUploadResponse: &santa.EventUploadResponse{},
			Err:                 err,
		}, nil
	}
}

func decodeEventUpload(ctx context.Context, r *http.Request) (interface{}, error) {
	id, err := machineIDFromRequest(r)
	if err != nil {
		return nil, errors.Wrap(err, "get machine ID from event upload URL")
	}

	// decode the JSON into individual log events.
	var eventPayload santa.EventUploadRequest

	if err := decodeJSON(r, &eventPayload); err != nil {
		return nil, errors.Wrap(err, "decoding event upload request json")
	}

	if len(eventPayload.Events) > maxBatchEvents {
		return nil, fmt.Errorf("event batch exceeds limit")
	}
	if err := validatePayloadID(id, eventPayload.MachineID); err != nil {
		return nil, err
	}
	var events []santa.EventPayload
	for _, ev := range eventPayload.Events {
		sanitizeEvent(&ev)
		var payload santa.EventPayload
		payload.EventInfo = ev
		payload.FileSHA = ev.FileSHA256
		payload.UnixTime = ev.ExecutionTime
		events = append(events, payload)
	}

	reqID := id
	if eventPayload.MachineID != "" {
		reqID = eventPayload.MachineID
	}

	req := eventRequest{MachineID: reqID, events: events}
	return req, nil
}

func (mw logmw) UploadEvent(ctx context.Context, machineID string, events []santa.EventPayload) (err error) {
	defer func(begin time.Time) {
		_ = mw.logger.Log("method", "UploadEvent", "machine_id", machineID, "auth", AuthFromContext(ctx),
			"event_count", len(events), "err", err, "took", time.Since(begin))
	}(time.Now())

	err = mw.next.UploadEvent(ctx, machineID, events)
	return
}
