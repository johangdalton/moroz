package moroz

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/groob/moroz/santa"
)

type ConfigStore interface {
	AllConfigs(ctx context.Context) ([]santa.Config, error)
	Config(ctx context.Context, machineID string) (santa.Config, error)
}

type SantaService struct {
	outbox             *Outbox
	logger             log.Logger
	eventMu            sync.Mutex
	eventLogDay        string
	eventRetentionDays int
	sessionMu          sync.Mutex
	sessions           map[string]syncSession
	acks               *AckStore
	incremental        bool
	now                func() time.Time
	decisions          syncCounters
	invalidEvents      atomic.Int64
	hashes             hashFindings
	global             santa.Config
	repo               ConfigStore
	eventDir           string
	flPersistEvents    bool
	identities         *IdentityStore
	known              *KnownDevices
	requireKnown       bool
	authError          func(error)
}

// SetIdentityStore enables machine ID to serial binding at preflight. Called
// during startup before serving requests.
func (svc *SantaService) SetIdentityStore(s *IdentityStore) { svc.identities = s }

// SetKnownDevices enables the preflight serial check of fleet-authenticated
// machines against the allowlist when require is set.
func (svc *SantaService) SetKnownDevices(k *KnownDevices, require bool) {
	svc.known, svc.requireKnown = k, require
}

// SetAuthErrorLogger receives identity and allowlist refusals; the caller
// throttles them. Called during startup before serving requests.
func (svc *SantaService) SetAuthErrorLogger(fn func(error)) { svc.authError = fn }

func (svc *SantaService) reportAuthError(err error) {
	if svc.authError != nil {
		svc.authError(err)
	}
}

// unknownDeviceError refuses a fleet-authenticated preflight whose machine
// is not in the known-devices allowlist or reports another serial.
type unknownDeviceError struct{}

func (e unknownDeviceError) Error() string   { return "unknown device" }
func (e unknownDeviceError) StatusCode() int { return http.StatusForbidden }

func NewService(ds ConfigStore, eventDir string, flPersistEvents bool) (*SantaService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	global, err := ds.Config(ctx, "global")
	if err != nil {
		return nil, err
	}
	return &SantaService{
		logger:             log.NewNopLogger(),
		eventRetentionDays: 90,
		global:             global,
		sessions:           make(map[string]syncSession),
		acks:               OpenAckStore(""),
		now:                time.Now,
		repo:               ds,
		eventDir:           eventDir,
		flPersistEvents:    flPersistEvents,
	}, nil
}

type Service interface {
	Preflight(ctx context.Context, machineID string, p santa.PreflightPayload) (*santa.Preflight, error)
	RuleDownload(ctx context.Context, machineID string) ([]santa.Rule, error)
	UploadEvent(ctx context.Context, machineID string, events []santa.EventPayload) error
	Postflight(ctx context.Context, machineID string, p santa.PostflightPayload) (*santa.Postflight, error)
}

type Endpoints struct {
	PreflightEndpoint    endpoint.Endpoint
	RuleDownloadEndpoint endpoint.Endpoint
	EventUploadEndpoint  endpoint.Endpoint
	PostflightEndpoint   endpoint.Endpoint
}

func MakeServerEndpoints(svc Service) Endpoints {
	return Endpoints{
		PreflightEndpoint:    makePreflightEndpoint(svc),
		RuleDownloadEndpoint: makeRuleDownloadEndpoint(svc),
		EventUploadEndpoint:  makeEventUploadEndpoint(svc),
		PostflightEndpoint:   makePostflightEndpoint(svc),
	}
}

// SetAckStore replaces the in-memory acknowledgement store with a persistent
// one. Called during startup before serving requests.
func (svc *SantaService) SetAckStore(s *AckStore) {
	if s != nil {
		svc.acks = s
	}
}

// SetIncrementalSync enables NORMAL syncs carrying only the rule diff between
// the acknowledged and the current generation. Called during startup.
func (svc *SantaService) SetIncrementalSync(enabled bool) { svc.incremental = enabled }

// syncCounters are the in-memory decision counters reported on /healthz.
type syncCounters struct {
	clean, normalDiff, normalUnchanged atomic.Int64
	last                               atomic.Pointer[string]
}

func (svc *SantaService) countDecision(mode string) {
	switch mode {
	case decisionClean:
		svc.decisions.clean.Add(1)
	case decisionNormalDiff:
		svc.decisions.normalDiff.Add(1)
	case decisionNormalUnchanged:
		svc.decisions.normalUnchanged.Add(1)
	}
	svc.decisions.last.Store(&mode)
}

// SyncStats is the /healthz view of acknowledgements and sync decisions.
type SyncStats struct {
	Acknowledgements     int    `json:"acknowledgements"`
	IncrementalSync      bool   `json:"incremental_sync"`
	Clean                int64  `json:"clean"`
	NormalDiff           int64  `json:"normal_diff"`
	NormalUnchanged      int64  `json:"normal_unchanged"`
	LastDecision         string `json:"last_decision,omitempty"`
	InvalidEventsSkipped int64  `json:"invalid_events_skipped"`
	// RulesHashVerified counts CLEAN syncs whose reported hash matched the
	// served rules; RulesHashFindings lists machines that failed a check.
	RulesHashVerified int64         `json:"rules_hash_verified"`
	RulesHashFindings []HashFinding `json:"rules_hash_findings"`
}

// SyncStats returns the current counters; they reset on restart except the
// acknowledgement count, which comes from the store.
func (svc *SantaService) SyncStats() SyncStats {
	stats := SyncStats{
		Acknowledgements:     svc.acks.Count(),
		IncrementalSync:      svc.incremental,
		Clean:                svc.decisions.clean.Load(),
		NormalDiff:           svc.decisions.normalDiff.Load(),
		NormalUnchanged:      svc.decisions.normalUnchanged.Load(),
		InvalidEventsSkipped: svc.invalidEvents.Load(),
	}
	if last := svc.decisions.last.Load(); last != nil {
		stats.LastDecision = *last
	}
	stats.RulesHashFindings, stats.RulesHashVerified = svc.hashes.snapshot()
	return stats
}

// SetOutbox is called during startup before serving requests.
func (svc *SantaService) SetOutbox(q *Outbox) { svc.outbox = q }

// SetLogger is called during startup before serving requests.
func (svc *SantaService) SetLogger(logger log.Logger) {
	if logger != nil {
		svc.logger = logger
	}
}
