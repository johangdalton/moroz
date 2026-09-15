package moroz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/groob/moroz/santa"
)

func (svc *SantaService) RuleDownload(ctx context.Context, machineID string) ([]santa.Rule, error) {
	if config, ok := svc.sessionConfig(machineID); ok {
		return config.Rules, nil
	}
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
		if rules == nil {
			rules = []santa.Rule{}
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

	// Empty requests are accepted for legacy clients; nonempty requests must
	// be valid JSON using a supported content encoding.
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(bodyBytes) > maxRequestBytes {
		return nil, fmt.Errorf("invalid or oversized rule request")
	}
	if len(bodyBytes) == 0 {
		return req, nil
	}
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if r.Header.Get("Content-Encoding") == "" && json.Valid(bodyBytes) {
		r.Header.Set("Content-Encoding", "identity")
	}
	var body struct {
		Cursor    string `json:"cursor"`
		MachineID string `json:"machine_id"`
	}
	if err := decodeJSON(r, &body); err != nil {
		return nil, err
	}
	if err := validatePayloadID(id, body.MachineID); err != nil {
		return nil, err
	}
	req.Cursor = body.Cursor

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
