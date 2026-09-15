package moroz

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/pkg/errors"

	"github.com/groob/moroz/santa"
)

func (svc *SantaService) UploadEvent(ctx context.Context, machineID string, events []santa.EventPayload) error {
	if !validMachine(machineID) {
		return fmt.Errorf("invalid machine ID")
	}
	for _, ev := range events {
		if !fileHash.MatchString(ev.FileSHA) {
			return fmt.Errorf("invalid event file hash")
		}
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
		if !fileHash.MatchString(ev.FileSHA256) {
			return nil, fmt.Errorf("invalid event file hash")
		}
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
		_ = mw.logger.Log("method", "UploadEvent", "machine_id", machineID,
			"event_count", len(events), "err", err, "took", time.Since(begin))
	}(time.Now())

	err = mw.next.UploadEvent(ctx, machineID, events)
	return
}
