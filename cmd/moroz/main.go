package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
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

func main() {
	var (
		flManagerURL           = flag.String("manager-url", env.String("MOROZ_MANAGER_URL", ""), "Manager internal telemetry endpoint URL")
		flIngestToken          = flag.String("ingest-token-file", env.String("MOROZ_INGEST_TOKEN_FILE", ""), "File containing the manager service token")
		flOutbox               = flag.String("outbox-dir", env.String("MOROZ_OUTBOX_DIR", "/var/log/moroz/outbox"), "Durable telemetry queue directory (one writer)")
		flOutboxBytes          = flag.Int64("outbox-max-bytes", 1<<30, "Maximum queued telemetry bytes; full queues return 503")
		flStandalone           = flag.Bool("standalone", false, "Explicitly serve without manager telemetry (local tests or standalone use)")
		flEventRetention       = flag.Int("event-retention-days", 90, "Retention for dated event JSONL files")
		flClientCredentials    = flag.String("client-credentials", env.String("MOROZ_CLIENT_CREDENTIALS", ""), "JSON file mapping allowed machine IDs to individual bearer tokens")
		flAllowUnauthenticated = flag.Bool("allow-unauthenticated", false, "allow unauthenticated requests for isolated synthetic tests only")
		flTLSCert              = flag.String("tls-cert", env.String("MOROZ_TLS_CERT", "server.crt"), "path to TLS certificate")
		flTLSKey               = flag.String("tls-key", env.String("MOROZ_TLS_KEY", "server.key"), "path to TLS private key")
		flAddr                 = flag.String("http-addr", env.String("MOROZ_HTTP_ADDRESS", ":8080"), "http address ex: -http-addr=:8080")
		flConfigs              = flag.String("configs", env.String("MOROZ_CONFIGS", "../../configs"), "path to config folder")
		flEvents               = flag.String("event-dir", env.String("MOROZ_EVENT_DIR", "/tmp/santa_events"), "Path to root directory where events will be stored.")
		flPersistEvents        = flag.Bool("persist-events", env.Bool("MOROZ_WRITE_EVENTS", true), "Write JSONL events in standalone mode; direct delivery always uses the durable outbox")
		flVersion              = flag.Bool("version", false, "print version information")
		flDebug                = flag.Bool("debug", false, "log at a debug level by default.")
		flUseTLS               = flag.Bool("use-tls", true, "I promise I terminated TLS elsewhere when changing this")
	)
	flag.Parse()
	if *flEventRetention < 1 {
		fmt.Fprintln(os.Stderr, "event retention must be positive")
		os.Exit(2)
	}
	var credentials map[string]string
	if *flClientCredentials != "" {
		data, err := os.ReadFile(*flClientCredentials)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read client credentials:", err)
			os.Exit(2)
		}
		if err := json.Unmarshal(data, &credentials); err != nil || credentials == nil {
			fmt.Fprintln(os.Stderr, "invalid client credentials file")
			os.Exit(2)
		}
		for _, token := range credentials {
			if len(token) < 32 {
				fmt.Fprintln(os.Stderr, "client tokens must contain at least 32 characters")
				os.Exit(2)
			}
		}
	} else if !*flAllowUnauthenticated && !*flVersion {
		fmt.Fprintln(os.Stderr, "client credentials are required; development mode must be explicitly enabled for isolated tests")
		os.Exit(2)
	}

	if *flVersion {
		version.PrintFull()
		return
	}

	if _, err := os.Stat(*flTLSCert); *flUseTLS && os.IsNotExist(err) {
		fmt.Printf(openSSLBash)
		os.Exit(2)
	}

	if _, err := os.Stat(*flConfigs); err != nil {
		fmt.Println("you need to provide at least a 'global.toml' configuration file in the configs folder. See the configs folder in the git repo for an example")
		os.Exit(2)
	}

	if *flManagerURL == "" && !*flStandalone && !*flAllowUnauthenticated {
		fmt.Fprintln(os.Stderr, "manager-url is required; use standalone explicitly to disable manager telemetry")
		os.Exit(2)
	}
	logger := logutil.NewServerLogger(*flDebug)
	var outbox *moroz.Outbox
	if *flManagerURL != "" {
		raw, err := os.ReadFile(*flIngestToken)
		if err != nil {
			logutil.Fatal(logger, "cannot read ingestion token:", err)
		}
		outbox, err = moroz.NewOutbox(*flOutbox, *flManagerURL, strings.TrimSpace(string(raw)), *flOutboxBytes)
		if err != nil {
			logutil.Fatal(logger, "cannot open telemetry outbox:", err)
		}
		defer outbox.Close()
	}

	repo := santaconfig.NewFileRepo(*flConfigs)
	reloadCtx, stopReload := context.WithCancel(context.Background())
	defer stopReload()
	go repo.Watch(reloadCtx, time.Second, func(err error) {
		level.Error(logger).Log("msg", "policy reload failed; retaining previous snapshot", "err", err)
	})
	var svc moroz.Service
	{
		s, err := moroz.NewService(repo, *flEvents, *flPersistEvents)
		if err != nil {
			logutil.Fatal(logger, err)
		}
		s.SetOutbox(outbox)
		s.SetEventRetentionDays(*flEventRetention)
		svc = s
		svc = moroz.LoggingMiddleware(logger)(svc)
	}

	endpoints := moroz.MakeServerEndpoints(svc)

	r := mux.NewRouter()
	r.Use(moroz.ClientGuard(credentials))
	moroz.AddHTTPRoutes(r, endpoints, logger)

	var g run.Group
	if outbox != nil {
		ctx, cancel := context.WithCancel(context.Background())
		g.Add(func() error {
			outbox.Run(ctx, func(err error) { level.Error(logger).Log("msg", "telemetry delivery retry", "err", err) })
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
		srv := httputil.NewServer(*flAddr, r)
		g.Add(func() error {
			level.Debug(logger).Log("msg", "serve http", "tls", *flUseTLS, "addr", *flAddr)
			if *flUseTLS {
				return srv.ListenAndServeTLS(*flTLSCert, *flTLSKey)
			} else {
				return srv.ListenAndServe()
			}
		}, func(error) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			srv.Shutdown(ctx)
		})
	}

	logutil.Fatal(logger, "msg", "terminated", "err", g.Run())
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
