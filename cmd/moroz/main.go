package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-kit/kit/log/level"
	"github.com/gorilla/mux"
	"github.com/kolide/kit/env"
	"github.com/kolide/kit/httputil"
	"github.com/kolide/kit/logutil"
	"github.com/kolide/kit/version"
	"github.com/oklog/run"

	"github.com/groob/moroz/moroz"
	"github.com/groob/moroz/santaconfig"
)

const openSSLBash = `
Looks like you're missing a TLS certificate and private key. You can quickly generate one 
by using the commands below:

	./tools/dev/certificate/create

Add the santa hostname to your hosts file.

	sudo echo "127.0.0.1 santa" >> /etc/hosts

And then, add the cert to roots.

	./tools/dev/certificate/add-trusted-cert


The latest version of santa is available on the github repo page:
	https://github.com/google/santa/releases
`

// How long a shutdown waits for in-flight Santa requests. Reload errors are
// repeated in the log at most this often while the text stays the same.
// Credential, known-devices and identity files are polled for changes at
// credentialPollInterval.
const (
	shutdownGrace          = 15 * time.Second
	reloadErrorInterval    = 5 * time.Minute
	credentialPollInterval = 2 * time.Second
	defaultIdentityStore   = "<outbox-dir>/../identities.json"
)

func main() {
	os.Exit(serve())
}

// serve returns the process exit code so deferred cleanup (outbox lock, reload
// worker) executes on the way out instead of being skipped by os.Exit.
func serve() int {
	var (
		flManagerURL           = flag.String("manager-url", env.String("MOROZ_MANAGER_URL", ""), "Manager internal telemetry endpoint URL")
		flIngestToken          = flag.String("ingest-token-file", env.String("MOROZ_INGEST_TOKEN_FILE", ""), "File containing the manager service token")
		flOutbox               = flag.String("outbox-dir", env.String("MOROZ_OUTBOX_DIR", "/var/log/moroz/outbox"), "Durable telemetry queue directory (one writer)")
		flOutboxBytes          = flag.Int64("outbox-max-bytes", 1<<30, "Maximum queued telemetry bytes; a full queue returns 503 to event uploads only")
		flStandalone           = flag.Bool("standalone", false, "Explicitly serve without manager telemetry (local tests or standalone use)")
		flEventRetention       = flag.Int("event-retention-days", 90, "Retention for dated event JSONL files")
		flClientCredentials    = flag.String("client-credentials", env.String("MOROZ_CLIENT_CREDENTIALS", ""), "JSON file mapping allowed machine IDs to individual bearer tokens")
		flFleetCredentials     = flag.String("fleet-credentials", env.String("MOROZ_FLEET_CREDENTIALS", ""), "JSON file with named fleet-wide bearer tokens accepted for any machine ID; empty disables")
		flIdentityStore        = flag.String("identity-store", env.String("MOROZ_IDENTITY_STORE", defaultIdentityStore), "JSON file binding each machine ID to the serial number it first reported; empty disables")
		flKnownDevices         = flag.String("known-devices", env.String("MOROZ_KNOWN_DEVICES", ""), "JSON allowlist of machine IDs (with optional serial) written by the manager; empty disables")
		flRequireKnownDevices  = flag.Bool("require-known-devices", false, "Accept fleet tokens only for machine IDs in the known-devices file while it is loaded")
		flAllowUnauthenticated = flag.Bool("allow-unauthenticated", false, "allow unauthenticated requests for isolated synthetic tests only")
		flRateBurst            = flag.Int("client-rate-burst", 30, "Requests a machine may make at once before the per-machine limit returns 429; 0 disables")
		flRateRefill           = flag.Duration("client-rate-refill", 20*time.Second, "Interval at which each machine earns one more request")
		flMaxConcurrent        = flag.Int("max-concurrent-requests", 8, "Authenticated requests decoded concurrently; others wait briefly, then receive 503; 0 disables")
		flTLSCert              = flag.String("tls-cert", env.String("MOROZ_TLS_CERT", "server.crt"), "path to TLS certificate")
		flTLSKey               = flag.String("tls-key", env.String("MOROZ_TLS_KEY", "server.key"), "path to TLS private key")
		flAddr                 = flag.String("http-addr", env.String("MOROZ_HTTP_ADDRESS", ":8080"), "http address ex: -http-addr=:8080")
		flConfigs              = flag.String("configs", env.String("MOROZ_CONFIGS", "../../configs"), "path to config folder")
		flEvents               = flag.String("event-dir", env.String("MOROZ_EVENT_DIR", "/tmp/santa_events"), "Path to root directory where events will be stored.")
		flPersistEvents        = flag.Bool("persist-events", env.Bool("MOROZ_WRITE_EVENTS", true), "Write JSONL events in standalone mode; direct delivery always uses the durable outbox")
		flLogPayloads          = flag.Bool("log-payloads", false, "Log full preflight/postflight payloads (contains hostname, serial number and primary user)")
		flVersion              = flag.Bool("version", false, "print version information")
		flDebug                = flag.Bool("debug", false, "log at a debug level by default.")
		flUseTLS               = flag.Bool("use-tls", true, "I promise I terminated TLS elsewhere when changing this")
	)
	flag.Parse()
	if *flEventRetention < 1 {
		fmt.Fprintln(os.Stderr, "event retention must be positive")
		return 2
	}
	var credentials *moroz.Credentials
	if *flClientCredentials != "" || *flFleetCredentials != "" {
		// Both files must exist and validate at startup; later reloads keep
		// the previous set on error.
		var err error
		if credentials, err = moroz.LoadCredentials(*flClientCredentials, *flFleetCredentials); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	} else if !*flAllowUnauthenticated && !*flVersion {
		fmt.Fprintln(os.Stderr, "client credentials are required; development mode must be explicitly enabled for isolated tests")
		return 2
	}
	if *flRequireKnownDevices && *flKnownDevices == "" {
		fmt.Fprintln(os.Stderr, "require-known-devices needs a known-devices file")
		return 2
	}
	identityPath := *flIdentityStore
	if identityPath == defaultIdentityStore {
		identityPath = filepath.Clean(filepath.Join(*flOutbox, "..", "identities.json"))
	}

	if *flVersion {
		version.PrintFull()
		return 0
	}

	if _, err := os.Stat(*flTLSCert); *flUseTLS && os.IsNotExist(err) {
		fmt.Printf(openSSLBash)
		return 2
	}

	if _, err := os.Stat(*flConfigs); err != nil {
		fmt.Println("you need to provide at least a 'global.toml' configuration file in the configs folder. See the configs folder in the git repo for an example")
		return 2
	}

	if *flManagerURL == "" && !*flStandalone && !*flAllowUnauthenticated {
		fmt.Fprintln(os.Stderr, "manager-url is required; use standalone explicitly to disable manager telemetry")
		return 2
	}
	logger := logutil.NewServerLogger(*flDebug)
	var outbox *moroz.Outbox
	if *flManagerURL != "" {
		// Token and outbox errors are configuration errors and stay fatal.
		raw, err := os.ReadFile(*flIngestToken)
		if err != nil {
			level.Error(logger).Log("msg", "cannot read ingestion token", "err", err)
			return 1
		}
		outbox, err = moroz.NewOutbox(*flOutbox, *flManagerURL, strings.TrimSpace(string(raw)), *flOutboxBytes)
		if err != nil {
			level.Error(logger).Log("msg", "cannot open telemetry outbox", "err", err)
			return 1
		}
		defer outbox.Close()
		for _, file := range outbox.Quarantined() {
			level.Error(logger).Log("msg", "CORRUPT OUTBOX FILE QUARANTINED; telemetry in it was not delivered", "dir", *flOutbox+"/corrupt", "file", file)
		}
	}

	repo := santaconfig.NewFileRepo(*flConfigs)
	reloadCtx, stopReload := context.WithCancel(context.Background())
	defer stopReload()
	go repo.Watch(reloadCtx, time.Second, santaconfig.ThrottleErrors(reloadErrorInterval, func(err error, repeats int) {
		level.Error(logger).Log("msg", "policy reload failed; retaining previous snapshot", "err", err, "repeats_suppressed", repeats)
	}))
	if credentials != nil {
		go credentials.Watch(reloadCtx, credentialPollInterval, santaconfig.ThrottleErrors(reloadErrorInterval, func(err error, repeats int) {
			level.Error(logger).Log("msg", "credential reload failed; retaining previous set", "err", err, "repeats_suppressed", repeats)
		}))
	}
	var identities *moroz.IdentityStore
	if identityPath != "" {
		// Never fatal: losing bindings must not take rule delivery down.
		identities = moroz.OpenIdentityStore(identityPath)
		for _, warning := range identities.Warnings() {
			level.Error(logger).Log("msg", "CORRUPT IDENTITY STORE; all machines will rebind on their next preflight", "path", identityPath, "detail", warning)
		}
	}
	var knownDevices *moroz.KnownDevices
	if *flKnownDevices != "" {
		knownDevices = moroz.NewKnownDevices(*flKnownDevices)
		if err := knownDevices.Reload(); err != nil {
			level.Warn(logger).Log("msg", "known-devices not loaded", "path", *flKnownDevices, "err", err)
		}
		go knownDevices.Watch(reloadCtx, credentialPollInterval, santaconfig.ThrottleErrors(reloadErrorInterval, func(err error, repeats int) {
			level.Error(logger).Log("msg", "known-devices reload failed", "err", err, "repeats_suppressed", repeats)
		}))
	}
	var svc moroz.Service
	{
		s, err := moroz.NewService(repo, *flEvents, *flPersistEvents)
		if err != nil {
			level.Error(logger).Log("msg", "cannot load policy", "err", err)
			return 1
		}
		s.SetOutbox(outbox)
		s.SetLogger(logger)
		s.SetEventRetentionDays(*flEventRetention)
		s.SetIdentityStore(identities)
		s.SetKnownDevices(knownDevices, *flRequireKnownDevices)
		s.SetAuthErrorLogger(santaconfig.ThrottleErrors(reloadErrorInterval, func(err error, repeats int) {
			level.Error(logger).Log("msg", "preflight refused", "err", err, "repeats_suppressed", repeats)
		}))
		svc = s
		svc = moroz.LoggingMiddleware(logger, *flLogPayloads)(svc)
	}

	endpoints := moroz.MakeServerEndpoints(svc)

	var limiter *moroz.RateLimiter
	if *flRateBurst > 0 || *flMaxConcurrent > 0 {
		limiter = moroz.NewRateLimiter(*flRateBurst, *flRateRefill, *flMaxConcurrent)
	}
	r := mux.NewRouter()
	r.Use(moroz.Guard(moroz.GuardOptions{Credentials: credentials, Limiter: limiter, KnownDevices: knownDevices, RequireKnownDevices: *flRequireKnownDevices}))
	moroz.AddHTTPRoutes(r, endpoints, logger)
	// The health route sits outside ClientGuard: no credentials, no body, no
	// rate limit. The ingress only forwards the Santa POST routes.
	root := http.NewServeMux()
	root.Handle("/healthz", moroz.HealthHandler(repo, outbox, moroz.AuthStatus{Credentials: credentials, Identities: identities, KnownDevices: knownDevices}))
	root.Handle("/", r)

	var g run.Group
	if identities != nil {
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			identities.Run(ctx, santaconfig.ThrottleErrors(reloadErrorInterval, func(err error, repeats int) {
				level.Error(logger).Log("msg", "identity store", "err", err, "repeats_suppressed", repeats)
			}))
			return nil
		}, func(error) { cancel() })
	}
	if outbox != nil {
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			outbox.Run(ctx, func(err error) { level.Error(logger).Log("msg", "telemetry delivery", "err", err) })
			return nil
		}, func(error) { cancel() })
	}
	{
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-c:
				return fmt.Errorf("received signal %s", sig)
			case <-ctx.Done():
				return ctx.Err()
			}
		}, func(error) {
			cancel()
		})
	}

	{
		srv := httputil.NewServer(*flAddr, root)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "serve http", "tls", *flUseTLS, "addr", *flAddr)
			if *flUseTLS {
				return srv.ListenAndServeTLS(*flTLSCert, *flTLSKey)
			} else {
				return srv.ListenAndServe()
			}
		}, func(error) {
			ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
			defer cancel()
			srv.Shutdown(ctx)
		})
	}

	err := g.Run()
	level.Info(logger).Log("msg", "terminated", "err", err)
	if err != nil && !strings.HasPrefix(err.Error(), "received signal") {
		return 1
	}
	return 0
}

func validateConfigExists(configsPath string) bool {
	var hasConfig = true
	if _, err := os.Stat(configsPath); os.IsNotExist(err) {
		hasConfig = false
	}
	if _, err := os.Stat(configsPath + "/global.toml"); os.IsNotExist(err) {
		hasConfig = false
	}
	if !hasConfig {
	}
	return hasConfig
}
