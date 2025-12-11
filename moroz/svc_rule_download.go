package moroz

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"compress/zlib"

	"github.com/go-kit/kit/endpoint"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) RuleDownload(ctx context.Context, machineID string) ([]santa.Rule, error) {
	config, err := svc.config(ctx, machineID)
	return config.Rules, err
}

func (svc *SantaService) config(ctx context.Context, machineID string) (santa.Config, error) {
	// try the machine ID config first, and if that fails return the global config instead
	if config, err := svc.repo.Config(ctx, machineID); err == nil {
		return config, nil
	}
	config, err := svc.repo.Config(ctx, "global")
	return config, err
}

type ruleRequest struct {
	MachineID string
	Cursor    string
}

type rulesResponse struct {
	Rules  []santa.Rule `json:"rules"`
	Cursor string       `json:"cursor,omitempty"`
	Err    error        `json:"error,omitempty"`
}

func (r rulesResponse) Failed() error { return r.Err }

func makeRuleDownloadEndpoint(svc Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(ruleRequest)
		rules, err := svc.RuleDownload(ctx, req.MachineID)
		if err != nil {
			return rulesResponse{Err: err}, nil
		}
		return rulesResponse{Rules: rules, Cursor: ""}, nil
	}
}

func decodeRuleRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	defer r.Body.Close()

	id, err := machineIDFromRequest(r)
	if err != nil {
		return nil, err
	}

	req := ruleRequest{MachineID: id}

	// Optional JSON payload (may be zlib-compressed) that carries cursor/machine_id.
	// We accept empty bodies for backward compatibility.
	bodyBytes, _ := io.ReadAll(r.Body)
	if len(bodyBytes) == 0 {
		return req, nil
	}

	payload := bodyBytes
	if zr, zerr := zlib.NewReader(bytes.NewReader(bodyBytes)); zerr == nil {
		defer zr.Close()
		if decompressed, derr := io.ReadAll(zr); derr == nil {
			payload = decompressed
		}
	}

	var body struct {
		Cursor    string `json:"cursor"`
		MachineID string `json:"machine_id"`
	}
	if jerr := json.Unmarshal(payload, &body); jerr == nil {
		if body.Cursor != "" {
			req.Cursor = body.Cursor
		}
		if body.MachineID != "" {
			req.MachineID = body.MachineID
		}
	}

	return req, nil
}

func (mw logmw) RuleDownload(ctx context.Context, machineID string) (rules []santa.Rule, err error) {
	defer func(begin time.Time) {
		_ = mw.logger.Log(
			"method", "RuleDownload",
			"machine_id", machineID,
			"err", err,
			"took", time.Since(begin),
		)
	}(time.Now())

	rules, err = mw.next.RuleDownload(ctx, machineID)
	return
}
