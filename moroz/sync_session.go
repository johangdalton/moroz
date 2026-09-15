package moroz

import (
	"crypto/sha256"
	"encoding/json"
	"github.com/groob/moroz/santa"
	"time"
)

type syncSession struct {
	config  santa.Config
	digest  [32]byte
	expires time.Time
}

func (svc *SantaService) beginSync(machine string, config santa.Config, requestClean bool) santa.Preflight {
	encoded, _ := json.Marshal(config)
	digest := sha256.Sum256(encoded)
	svc.sessionMu.Lock()
	defer svc.sessionMu.Unlock()
	for id, session := range svc.sessions {
		if time.Now().After(session.expires) {
			delete(svc.sessions, id)
		}
	}
	svc.sessions[machine] = syncSession{config: config, digest: digest, expires: time.Now().Add(15 * time.Minute)}
	pre := config.Preflight
	if previous, ok := svc.acknowledged[machine]; ok && previous == digest && !requestClean {
		pre.SyncType = santa.SyncTypeNormal
		pre.CleanSync = false
	} else if requestClean {
		pre.SyncType = santa.SyncTypeClean
		pre.CleanSync = true
	}
	return pre
}

func (svc *SantaService) sessionConfig(machine string) (santa.Config, bool) {
	svc.sessionMu.Lock()
	defer svc.sessionMu.Unlock()
	s, ok := svc.sessions[machine]
	if ok && time.Now().Before(s.expires) {
		return s.config, true
	}
	delete(svc.sessions, machine)
	return santa.Config{}, false
}

func (svc *SantaService) finishSync(machine string) {
	svc.sessionMu.Lock()
	defer svc.sessionMu.Unlock()
	if s, ok := svc.sessions[machine]; ok && time.Now().Before(s.expires) {
		svc.acknowledged[machine] = s.digest
	}
	delete(svc.sessions, machine)
}
