package moroz

import (
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) Preflight(ctx context.Context, machineID string, p santa.PreflightPayload) (*santa.Preflight, error) {
	config, err := svc.config(ctx, machineID)
	if err != nil {
		return nil, err
	}
	pre := config.Preflight
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
	zr, err := zlib.NewReader(r.Body)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	defer r.Body.Close()
	id, err := machineIDFromRequest(r)
	if err != nil {
		return nil, err
	}
	req := preflightRequest{MachineID: id}
	if err := json.NewDecoder(zr).Decode(&req.payload); err != nil {
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

		// Structured JSON logging for Loki ingestion
		preflightLog := map[string]interface{}{
			"event_type":             "preflight",
			"machine_id":             machineID,
			"hostname":               p.Hostname,
			"os_version":             p.OSVersion,
			"os_build":               p.OSBuild,
			"model_identifier":       p.ModelIdentifier,
			"santa_version":          p.SantaVersion,
			"client_mode":            p.ClientMode,
			"serial_number":          p.SerialNumber,
			"primary_user":           p.PrimaryUser,
			"binary_rule_count":      p.BinaryRuleCount,
			"certificate_rule_count": p.CertificateRuleCount,
			"compiler_rule_count":    p.CompilerRuleCount,
			"transitive_rule_count":  p.TransitiveRuleCount,
			"teamid_rule_count":      p.TeamIDRuleCount,
			"signingid_rule_count":   p.SigningIDRuleCount,
			"cdhash_rule_count":      p.CdHashRuleCount,
			"request_clean_sync":     p.RequestCleanSync,
			"timestamp":              time.Now().Format(time.RFC3339),
			"took_ms":                time.Since(begin).Milliseconds(),
		}

		if err != nil {
			preflightLog["error"] = err.Error()
		}

		if logJSON, jsonErr := json.Marshal(preflightLog); jsonErr == nil {
			fmt.Fprintln(os.Stdout, string(logJSON))
		}
	}(time.Now())

	pf, err = mw.next.Preflight(ctx, machineID, p)
	return
}
