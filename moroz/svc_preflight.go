package moroz

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log/level"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) Preflight(ctx context.Context, machineID string, p santa.PreflightPayload) (*santa.Preflight, error) {
	if err := svc.checkIdentity(ctx, machineID, p.SerialNumber); err != nil {
		// No session, no telemetry: nothing this client reports is trusted.
		return nil, err
	}
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

// checkIdentity applies the known-devices serial check to fleet-authenticated
// machines and then the trust-on-first-use serial binding. The refusal
// details, including both serials, go to the throttled auth error log only.
func (svc *SantaService) checkIdentity(ctx context.Context, machineID, serial string) error {
	auth := AuthFromContext(ctx)
	if svc.requireKnown && auth.IsFleet() && svc.known.Loaded() {
		device, ok := svc.known.Lookup(machineID)
		if !ok {
			svc.reportAuthError(fmt.Errorf("machine %s authenticated with %s but is not in known-devices", machineID, auth))
			return unknownDeviceError{}
		}
		if device.Serial != "" && device.Serial != serial {
			svc.reportAuthError(fmt.Errorf("machine %s (%s) reported serial %q but known-devices lists %q", machineID, auth, serial, device.Serial))
			return unknownDeviceError{}
		}
	}
	if svc.identities != nil {
		if err := svc.identities.Bind(machineID, serial, auth, time.Now()); err != nil {
			if mismatch, ok := err.(identityMismatchError); ok {
				svc.reportAuthError(fmt.Errorf("identity mismatch for machine %s (%s): bound serial %q, preflight serial %q; delete its entry from the identity store to rebind", machineID, auth, mismatch.bound, mismatch.reported))
			}
			return err
		}
	}
	return nil
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
			"auth", AuthFromContext(ctx),
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
