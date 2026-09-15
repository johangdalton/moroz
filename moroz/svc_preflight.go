package moroz

import (
	"context"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log/level"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) Preflight(ctx context.Context, machineID string, p santa.PreflightPayload) (*santa.Preflight, error) {
	config, err := svc.config(ctx, machineID)
	if err != nil {
		return nil, err
	}
	if svc.outbox != nil {
		// Telemetry is best-effort here. Santa aborts the whole sync when the
		// preflight fails, so a full or closed queue must never block rules.
		if err := svc.outbox.Preflight(ctx, machineID, p); err != nil {
			level.Warn(svc.logger).Log("msg", "preflight telemetry dropped; rule delivery continues", "machine_id", machineID, "err", err)
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
		// Hostname, serial number and primary user are personal data and are
		// only logged when payload logging is explicitly enabled.
		keyvals := []interface{}{
			"method", "Preflight",
			"machine_id", machineID,
			"santa_version", p.SantaVersion,
			"client_mode", textOf(p.ClientMode),
			"request_clean_sync", p.RequestCleanSync,
			"binary_rules", p.BinaryRuleCount,
			"certificate_rules", p.CertificateRuleCount,
			"compiler_rules", p.CompilerRuleCount,
			"transitive_rules", p.TransitiveRuleCount,
			"teamid_rules", p.TeamIDRuleCount,
			"signingid_rules", p.SigningIDRuleCount,
			"cdhash_rules", p.CdHashRuleCount,
		}
		if mw.logPayloads {
			keyvals = append(keyvals, "preflight_payload", p)
		}
		_ = mw.logger.Log(append(keyvals, "err", err, "took", time.Since(begin))...)
	}(time.Now())

	pf, err = mw.next.Preflight(ctx, machineID, p)
	return
}
