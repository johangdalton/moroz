package moroz

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) Preflight(ctx context.Context, machineID string, p santa.PreflightPayload) (*santa.Preflight, error) {
	config, err := svc.config(ctx, machineID)
	if err != nil {
		return nil, err
	}
	if svc.outbox != nil {
		if err := svc.outbox.Preflight(ctx, machineID, p); err != nil {
			return nil, telemetryUnavailable{err}
		}
	}
	pre := svc.beginSync(machineID, config, p.RequestCleanSync)
	return &pre, nil
}

type preflightRequest struct {
	MachineID string
	payload   santa.PreflightPayload
}

type preflightResponse struct {
	*santa.Preflight
	Err error `json:"error,omitempty"`
}

func (r preflightResponse) Failed() error { return r.Err }

func makePreflightEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(preflightRequest)
		preflight, err := svc.Preflight(ctx, req.MachineID, req.payload)
		if err != nil {
			return preflightResponse{Err: err}, nil
		}
		return preflightResponse{Preflight: preflight}, nil
	}
}

func decodePreflightRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	id, err := machineIDFromRequest(r)
	if err != nil {
		return nil, err
	}
	req := preflightRequest{MachineID: id}
	if err := decodeJSON(r, &req.payload); err != nil {
		return nil, err
	}
	if err := validatePayloadID(id, req.payload.MachineID); err != nil {
		return nil, err
	}
	return req, nil
}

func (mw logmw) Preflight(ctx context.Context, machineID string, p santa.PreflightPayload) (pf *santa.Preflight, err error) {
	defer func(begin time.Time) {
		// Original go-kit logging
		_ = mw.logger.Log(
			"method", "Preflight",
			"machine_id", machineID,
			"preflight_payload", p,
			"err", err,
			"took", time.Since(begin),
		)

	}(time.Now())

	pf, err = mw.next.Preflight(ctx, machineID, p)
	return
}
