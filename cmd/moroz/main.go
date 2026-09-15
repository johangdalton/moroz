package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
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
const (
	shutdownGrace       = 15 * time.Second
	reloadErrorInterval = 5 * time.Minute
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
	var credentials map[string]string
	if *flClientCredentials != "" {
		data, err := os.ReadFile(*flClientCredentials)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read client credentials:", err)
			return 2
		}
		if err := json.Unmarshal(data, &credentials); err != nil || credentials == nil {
			fmt.Fprintln(os.Stderr, "invalid client credentials file")
			return 2
		}
		for _, token := range credentials {
			if len(token) < 32 {
				fmt.Fprintln(os.Stderr, "client tokens must contain at least 32 characters")
				return 2
			}
		}
	} else if !*flAllowUnauthenticated && !*flVersion {
		fmt.Fprintln(os.Stderr, "client credentials are required; development mode must be explicitly enabled for isolated tests")
		return 2
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
		svc = s
		svc = moroz.LoggingMiddleware(logger, *flLogPayloads)(svc)
	}

	endpoints := moroz.MakeServerEndpoints(svc)

	var limiter *moroz.RateLimiter
	if *flRateBurst > 0 || *flMaxConcurrent > 0 {
		limiter = moroz.NewRateLimiter(*flRateBurst, *flRateRefill, *flMaxConcurrent)
	}
	r := mux.NewRouter()
	r.Use(moroz.ClientGuard(credentials, limiter))
	moroz.AddHTTPRoutes(r, endpoints, logger)
	// The health route sits outside ClientGuard: no credentials, no body, no
	// rate limit. The ingress only forwards the Santa POST routes.
	root := http.NewServeMux()
	root.Handle("/healthz", moroz.HealthHandler(repo, outbox))
	root.Handle("/", r)

	var g run.Group
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
