# Moroz Integration Documentation

## Overview

This documentation describes how to integrate Moroz Santa server logs with Loki and your backend (PocketBase or other) to maintain real-time Santa client information in your host inventory.

## What's Implemented

### Structured JSON Logging in Moroz

Moroz now outputs structured JSON logs for every preflight request from Santa clients. These logs contain:

- Machine identification (serial number, machine ID, hostname)
- OS information (version, build, model)
- Santa client details (version, mode, primary user)
- Rule counts (binary, certificate, compiler, transitive, TeamID, SigningID, CDHash)
- Sync metadata (timestamp, request duration, sync status)

**Implementation:** `moroz/svc_preflight.go:66-112`

## Architecture

```
┌─────────────┐
│ Santa Client│
└──────┬──────┘
       │ Preflight Request
       ▼
┌─────────────┐
│   Moroz     │  Outputs structured JSON logs
└──────┬──────┘
       │
       ▼
┌─────────────┐
│  Promtail   │  Ships logs
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Loki     │  Stores & indexes logs
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ PocketBase  │  Queries Loki, updates hosts
│ (or other)  │
└─────────────┘
```

## Quick Start

### 1. Build and Deploy Updated Moroz

```bash
cd /Users/johang/Documents/Development/moroz
go build -o moroz ./cmd/moroz
```

Deploy the new binary and restart Moroz. You should immediately see structured JSON logs:

```json
{"event_type":"preflight","machine_id":"...","hostname":"...","santa_version":"2024.4",...}
```

### 2. Configure Promtail

See **[PROMTAIL_CONFIG.md](PROMTAIL_CONFIG.md)** for detailed configuration options.

Choose the configuration that matches your deployment:
- **Systemd service** - Use journald scraping
- **Docker** - Use Docker SD
- **Log files** - Use file scraping
- **Multiple instances** - Use multi-target configuration

### 3. Implement Backend Sync

See **[LOKI_POCKETBASE_INTEGRATION.md](LOKI_POCKETBASE_INTEGRATION.md)** for:
- PocketBase hook implementation
- Schema requirements
- Node.js/Express example
- Python/Django example
- Query examples
- Troubleshooting guide

## Documentation Structure

### [PROMTAIL_CONFIG.md](PROMTAIL_CONFIG.md)
Complete Promtail setup guide including:
- Installation methods (Linux, Docker, macOS)
- Configuration examples for different deployment scenarios
- Systemd service setup
- Docker Compose with full stack
- Verification and troubleshooting
- Security and performance tuning

### [LOKI_POCKETBASE_INTEGRATION.md](LOKI_POCKETBASE_INTEGRATION.md)
Backend integration guide including:
- PocketBase schema design
- Complete PocketBase hook implementation
- Alternative backend examples (Node.js, Python)
- Loki query patterns
- Monitoring and troubleshooting
- Architecture benefits

## Data Flow Example

1. **Santa Client** sends preflight request to Moroz every 10 minutes
2. **Moroz** processes the request and outputs a structured JSON log:
   ```json
   {
     "event_type": "preflight",
     "machine_id": "ABC123",
     "serial_number": "C02XYZ",
     "hostname": "johns-macbook.local",
     "santa_version": "2024.4",
     "client_mode": 1,
     "os_version": "14.1.1",
     ...
   }
   ```
3. **Promtail** reads the log and ships it to Loki with label `job="moroz-preflight"`
4. **Loki** stores and indexes the log for querying
5. **PocketBase** (or your backend):
   - Queries Loki every 5 minutes for recent preflight events
   - Parses the JSON data
   - Updates or creates host records with latest Santa client info

## Querying the Data

Once set up, you can query Loki for Santa client information:

```bash
# All preflight events in last hour
{job="moroz-preflight"} | json | event_type="preflight"

# Specific machine
{job="moroz-preflight"} | json | serial_number="C02XYZ"

# All machines in LOCKDOWN mode
{job="moroz-preflight"} | json | client_mode="2"

# Machines running old Santa versions
{job="moroz-preflight"} | json | santa_version!="2024.4"

# Machines with high rule counts
{job="moroz-preflight"} | json | binary_rule_count > 1000
```

## Benefits

1. **Separation of Concerns**: Moroz focuses on serving Santa, not database integration
2. **Reliability**: Loki stores all historical preflight data
3. **Flexibility**: Any backend can query Loki and consume the data
4. **Scalability**: Works with multiple Moroz instances without coordination
5. **Observability**: Full history of Santa client states for auditing
6. **No Database Changes**: Moroz doesn't need database access

## Monitoring

### Verify Moroz Logging

```bash
# Check logs contain structured JSON
journalctl -u moroz | grep event_type

# Or for Docker
docker logs moroz | grep event_type
```

### Verify Promtail

```bash
# Check Promtail status
systemctl status promtail

# Check targets
curl http://localhost:9080/targets
```

### Verify Loki

```bash
# Check labels
curl -s http://localhost:3100/loki/api/v1/labels | jq

# Query recent data
curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="moroz-preflight"}' \
  --data-urlencode "start=$(date -u -d '5 min ago' +%s)000000000" \
  --data-urlencode "end=$(date -u +%s)000000000" | jq
```

## Troubleshooting

### No Logs in Loki

1. **Check Moroz logs**: Ensure structured JSON is being output
2. **Check Promtail config**: Verify job name and path match
3. **Check Promtail targets**: `curl http://localhost:9080/targets`
4. **Check connectivity**: Promtail → Loki connection
5. **Check Promtail logs**: `journalctl -u promtail -f`

### Backend Not Syncing

1. **Test Loki query manually**: Use curl examples
2. **Check backend logs**: Look for sync errors
3. **Verify schema**: Ensure fields exist in database
4. **Check sync interval**: May need to wait for next run
5. **Verify timestamp parsing**: Ensure time range is correct

## Production Considerations

### High Availability

- Run multiple Moroz instances behind a load balancer
- Use Loki in clustered mode for redundancy
- Deploy Promtail on each Moroz host

### Security

- Enable TLS for Loki connections
- Use authentication for Loki API
- Restrict PocketBase/backend access to Loki
- Consider data retention policies for compliance

### Performance

- Adjust Promtail batch size for high-volume environments
- Set appropriate Loki retention period
- Index only necessary fields
- Use streaming aggregations for real-time stats

### Monitoring & Alerting

Create alerts in Grafana for:
- Machines not checking in (no preflight in X hours)
- Machines in unexpected client mode
- Old Santa versions
- Rule count anomalies
- Sync job failures

## Example Grafana Queries

```promql
# Count of active Santa clients (checked in last hour)
count(count_over_time({job="moroz-preflight"}[1h]))

# Breakdown by client mode
sum by (client_mode) (count_over_time({job="moroz-preflight"}[1h]))

# Average rule counts
avg_over_time({job="moroz-preflight"} | json | unwrap binary_rule_count [1h])

# Machines not seen in 24h
{job="moroz-preflight"} | json
  | __timestamp__ < now() - 24h
```

## Support

For issues or questions:
- Moroz issues: https://github.com/groob/moroz/issues
- Loki docs: https://grafana.com/docs/loki/
- Promtail docs: https://grafana.com/docs/loki/latest/send-data/promtail/
- PocketBase docs: https://pocketbase.io/docs/

## License

This integration documentation is provided as-is for use with the Moroz project.
