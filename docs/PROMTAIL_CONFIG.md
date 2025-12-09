# Promtail Configuration for Moroz

## Overview

Promtail is the log shipping agent that sends Moroz logs to Loki. This guide shows how to configure Promtail to collect Moroz structured JSON logs.

## Installation

### Linux (systemd)

```bash
# Download Promtail
curl -O -L "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"
unzip promtail-linux-amd64.zip
chmod +x promtail-linux-amd64
sudo mv promtail-linux-amd64 /usr/local/bin/promtail

# Create config directory
sudo mkdir -p /etc/promtail

# Create the config file (see configuration below)
sudo nano /etc/promtail/config.yml
```

### Docker

```bash
docker run -d \
  --name promtail \
  -v /etc/promtail/config.yml:/etc/promtail/config.yml \
  -v /var/log:/var/log \
  grafana/promtail:2.9.3 \
  -config.file=/etc/promtail/config.yml
```

### macOS (Homebrew)

```bash
brew install promtail

# Config location: /opt/homebrew/etc/promtail-config.yaml
```

## Configuration

### Option 1: Moroz Running as Systemd Service

If Moroz is running as a systemd service and logging to journald:

```yaml
# /etc/promtail/config.yml

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push
    # If Loki requires auth:
    # basic_auth:
    #   username: your-username
    #   password: your-password

scrape_configs:
  # Moroz preflight events from journald
  - job_name: moroz-preflight
    journal:
      json: true
      max_age: 12h
      path: /var/log/journal
      labels:
        job: moroz-preflight
    pipeline_stages:
      # Only process lines with event_type field (structured logs)
      - match:
          selector: '{job="moroz-preflight"}'
          stages:
            - json:
                expressions:
                  event_type: event_type
            - labels:
                event_type:
            # Drop non-preflight events
            - match:
                selector: '{event_type!="preflight"}'
                action: drop
    relabel_configs:
      # Only capture logs from the moroz service
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'
      - source_labels: ['__journal__systemd_unit']
        regex: 'moroz.service'
        action: keep
```

### Option 2: Moroz Running in Docker

If Moroz is running in Docker:

```yaml
# /etc/promtail/config.yml

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  # Moroz preflight events from Docker logs
  - job_name: moroz-preflight
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      # Only capture logs from moroz container
      - source_labels: ['__meta_docker_container_name']
        regex: '.*moroz.*'
        action: keep
      - source_labels: ['__meta_docker_container_name']
        target_label: 'container'
    pipeline_stages:
      # Parse JSON logs
      - json:
          expressions:
            event_type: event_type
            machine_id: machine_id
            hostname: hostname
            os_version: os_version
            santa_version: santa_version
      # Only keep preflight events
      - match:
          selector: '{container=~".*moroz.*"}'
          stages:
            - labels:
                event_type:
            - match:
                selector: '{event_type!="preflight"}'
                action: drop
```

### Option 3: Moroz Writing to Log File

If Moroz is writing to a log file (e.g., redirected stdout):

```yaml
# /etc/promtail/config.yml

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  # Moroz preflight events from log file
  - job_name: moroz-preflight
    static_configs:
      - targets:
          - localhost
        labels:
          job: moroz-preflight
          __path__: /var/log/moroz/*.log
    pipeline_stages:
      # Parse JSON log lines
      - json:
          expressions:
            event_type: event_type
            machine_id: machine_id
            hostname: hostname
            os_version: os_version
            os_build: os_build
            santa_version: santa_version
            client_mode: client_mode
            serial_number: serial_number
            primary_user: primary_user
      # Add extracted fields as labels for easier querying
      - labels:
          event_type:
      # Drop non-preflight events
      - match:
          selector: '{job="moroz-preflight"}'
          stages:
            - match:
                selector: '{event_type!="preflight"}'
                action: drop
      # Optional: add timestamp from log
      - timestamp:
          source: timestamp
          format: RFC3339
```

### Option 4: Multiple Moroz Instances

If you're running multiple Moroz instances (e.g., in Kubernetes or multiple servers):

```yaml
# /etc/promtail/config.yml

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki-server:3100/loki/api/v1/push

scrape_configs:
  # Moroz preflight events from multiple sources
  - job_name: moroz-preflight
    static_configs:
      - targets:
          - localhost
        labels:
          job: moroz-preflight
          instance: server-01
          __path__: /var/log/moroz/*.log
      - targets:
          - localhost
        labels:
          job: moroz-preflight
          instance: server-02
          __path__: /var/log/moroz2/*.log
    pipeline_stages:
      - json:
          expressions:
            event_type: event_type
            machine_id: machine_id
      - labels:
          event_type:
      - match:
          selector: '{event_type!="preflight"}'
          action: drop
```

## Systemd Service Configuration

Create a systemd service for Promtail:

```ini
# /etc/systemd/system/promtail.service

[Unit]
Description=Promtail service
After=network.target

[Service]
Type=simple
User=promtail
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/config.yml
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
# Create promtail user
sudo useradd -r -s /bin/false promtail

# Set permissions
sudo chown -R promtail:promtail /etc/promtail
sudo chmod 640 /etc/promtail/config.yml

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable promtail
sudo systemctl start promtail

# Check status
sudo systemctl status promtail
```

## Docker Compose Setup

Complete Docker Compose setup with Moroz, Loki, Promtail, and Grafana:

```yaml
# docker-compose.yml

version: '3.8'

services:
  moroz:
    build: .
    container_name: moroz
    ports:
      - "8080:8080"
    volumes:
      - ./configs:/configs
      - ./certs:/certs
    command: [
      "-configs", "/configs",
      "-tls-cert", "/certs/server.crt",
      "-tls-key", "/certs/server.key"
    ]
    networks:
      - logging

  loki:
    image: grafana/loki:2.9.3
    container_name: loki
    ports:
      - "3100:3100"
    volumes:
      - ./loki-config.yml:/etc/loki/config.yml
      - loki-data:/loki
    command: -config.file=/etc/loki/config.yml
    networks:
      - logging

  promtail:
    image: grafana/promtail:2.9.3
    container_name: promtail
    volumes:
      - ./promtail-config.yml:/etc/promtail/config.yml
      - /var/run/docker.sock:/var/run/docker.sock
    command: -config.file=/etc/promtail/config.yml
    depends_on:
      - loki
    networks:
      - logging

  grafana:
    image: grafana/grafana:10.2.0
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana-datasources.yml:/etc/grafana/provisioning/datasources/datasources.yml
    depends_on:
      - loki
    networks:
      - logging

networks:
  logging:
    driver: bridge

volumes:
  loki-data:
  grafana-data:
```

```yaml
# promtail-config.yml (for Docker Compose)

server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: moroz-preflight
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/moroz'
        action: keep
      - source_labels: ['__meta_docker_container_name']
        target_label: 'container'
    pipeline_stages:
      - json:
          expressions:
            event_type: event_type
      - labels:
          event_type:
      - match:
          selector: '{event_type!="preflight"}'
          action: drop
```

## Verification

### Check Promtail is Running

```bash
# Systemd
sudo systemctl status promtail

# Docker
docker logs promtail

# Check Promtail metrics
curl http://localhost:9080/metrics
```

### Verify Logs are Being Sent to Loki

```bash
# Check Loki labels
curl -s "http://localhost:3100/loki/api/v1/labels" | jq

# Check for moroz-preflight job
curl -s "http://localhost:3100/loki/api/v1/label/job/values" | jq

# Query recent preflight events
curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="moroz-preflight"}' \
  --data-urlencode "start=$(date -u -d '5 minutes ago' +%s)000000000" \
  --data-urlencode "end=$(date -u +%s)000000000" \
  | jq '.data.result[0].values[-5:]'
```

### Troubleshooting

**Promtail not starting:**
```bash
# Check config syntax
promtail -config.file=/etc/promtail/config.yml -dry-run

# Check logs
journalctl -u promtail -f
```

**No logs appearing in Loki:**
```bash
# Check Promtail targets
curl -s http://localhost:9080/targets | jq

# Check Promtail is discovering log files
curl -s http://localhost:9080/ready

# Verify Promtail can reach Loki
curl -v http://localhost:3100/ready
```

**Permission errors:**
```bash
# Ensure promtail user can read logs
sudo usermod -a -G systemd-journal promtail
sudo systemctl restart promtail

# For Docker logs
sudo usermod -a -G docker promtail
```

## Performance Tuning

For high-volume Moroz deployments:

```yaml
scrape_configs:
  - job_name: moroz-preflight
    # ... existing config ...
    pipeline_stages:
      # Add batch processing
      - pack:
          labels:
            - event_type
          ingest_timestamp: false
      # Add rate limiting if needed
      - limit:
          rate: 10000
          burst: 20000
          drop: true
```

## Security Considerations

### TLS for Loki Connection

```yaml
clients:
  - url: https://loki-server:3100/loki/api/v1/push
    tls_config:
      ca_file: /etc/promtail/ca.crt
      cert_file: /etc/promtail/client.crt
      key_file: /etc/promtail/client.key
```

### Authentication

```yaml
clients:
  - url: http://loki-server:3100/loki/api/v1/push
    basic_auth:
      username: promtail
      password: ${LOKI_PASSWORD}
    # Or use bearer token
    # bearer_token_file: /etc/promtail/token
```

## Next Steps

1. Install and configure Promtail using one of the methods above
2. Verify logs are flowing to Loki with the verification commands
3. Set up PocketBase sync (see LOKI_POCKETBASE_INTEGRATION.md)
4. Create Grafana dashboards for Santa client monitoring
