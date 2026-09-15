package moroz

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/groob/moroz/santa"
)

type ConfigStore interface {
	AllConfigs(ctx context.Context) ([]santa.Config, error)
	Config(ctx context.Context, machineID string) (santa.Config, error)
}

type SantaService struct {
	outbox             *Outbox
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
}

func NewService(ds ConfigStore, eventDir string, flPersistEvents bool) (*SantaService, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	global, err := ds.Config(ctx, "global")
	if err != nil {
		return nil, err
	}
	return &SantaService{
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
