package moroz

import (
	"context"
	"net/http"
	"sync"
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
	acknowledged       map[string][32]byte
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
		acknowledged:       make(map[string][32]byte),
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

// SetOutbox is called during startup before serving requests.
func (svc *SantaService) SetOutbox(q *Outbox) { svc.outbox = q }

// SetLogger is called during startup before serving requests.
func (svc *SantaService) SetLogger(logger log.Logger) {
	if logger != nil {
		svc.logger = logger
	}
}
