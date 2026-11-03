package moroz

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log/level"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) Postflight(ctx context.Context, machineID string, p santa.PostflightPayload) (*santa.Postflight, error) {
	session, acknowledged := svc.finishSync(machineID, p)
	if acknowledged {
		svc.checkCleanHash(machineID, session, p)
	}
	if !acknowledged {
		level.Warn(svc.logger).Log("msg", "postflight without acknowledgement; next sync will be CLEAN", "machine_id", machineID,
			"session", session.decision != "", "rules_received", p.RulesReceived, "rules_processed", p.RulesProcessed)
	}
	if svc.outbox != nil {
		// Best-effort like preflight telemetry: an outbox problem never fails
		// the postflight, which would make Santa treat the whole sync as failed.
		report := PostflightTelemetry{
			RulesReceived:  p.RulesReceived,
			RulesProcessed: p.RulesProcessed,
			SyncType:       p.SyncType,
			RulesHash:      p.RulesHash,
			Complete:       p.RulesReceived == p.RulesProcessed,
			Acknowledged:   acknowledged,
		}
		if report.RulesHash != "" {
			report.RulesHashSource = "postflight"
		} else if session.rulesHash != "" {
			report.RulesHash, report.RulesHashSource = session.rulesHash, "preflight"
		}
		if session.decision != "" {
			report.SyncDecision = session.decision
			report.RulesServed = len(session.rules)
			report.ServedSyncType = santa.SyncTypeNormal
			if session.clean {
				report.ServedSyncType = santa.SyncTypeClean
			}
			report.AcknowledgedGeneration = &AcknowledgedGeneration{ManifestGeneration: session.generation, ConfigDigest: session.digest}
		}
		if err := svc.outbox.Postflight(ctx, machineID, report); err != nil {
			level.Warn(svc.logger).Log("msg", "postflight telemetry dropped", "machine_id", machineID, "err", err)
		}
	}
	return &santa.Postflight{}, nil
}

type postflightRequest struct {
	MachineID string
	payload   santa.PostflightPayload
}

type postflightResponse struct {
	*santa.Postflight
	Err error `json:"error,omitempty"`
}

func (r postflightResponse) Failed() error { return r.Err }

func makePostflightEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(postflightRequest)
		postflight, err := svc.Postflight(ctx, req.MachineID, req.payload)
		if err != nil {
			return postflightResponse{Err: err}, nil
		}
		return postflightResponse{Postflight: postflight}, nil
	}
}

func decodePostflightRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	id, err := machineIDFromRequest(r)
	if err != nil {
		return nil, err
	}
	req := postflightRequest{MachineID: id}
	if err := decodeJSON(r, &req.payload); err != nil {
		return nil, err
	}
	if err := validatePayloadID(id, req.payload.MachineID); err != nil {
		return nil, err
	}
	return req, nil
}

func (mw logmw) Postflight(ctx context.Context, machineID string, p santa.PostflightPayload) (pf *santa.Postflight, err error) {
	defer func(begin time.Time) {
		keyvals := []interface{}{
			"method", "Postflight",
			"machine_id", machineID,
			"auth", AuthFromContext(ctx),
			"sync_type", textOf(p.SyncType),
			"rules_received", p.RulesReceived,
			"rules_processed", p.RulesProcessed,
			"rules_hash", p.RulesHash,
		}
		if mw.logPayloads {
			keyvals = append(keyvals, "postflight_payload", p)
		}
		_ = mw.logger.Log(append(keyvals, "err", err, "took", time.Since(begin))...)
	}(time.Now())

	pf, err = mw.next.Postflight(ctx, machineID, p)
	return
}
