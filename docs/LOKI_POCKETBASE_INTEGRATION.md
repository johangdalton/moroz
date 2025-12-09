# Loki + PocketBase Integration for Moroz Preflight Data

## Overview

This document describes how to integrate Moroz preflight logs (now outputting structured JSON) with Loki and PocketBase to maintain up-to-date Santa client information in your host inventory.

## Architecture

```
Santa Client → Moroz → Structured JSON Logs → Promtail → Loki
                                                            ↓
                                              PocketBase ← Query Loki
                                                   ↓
                                            Update Host Records
```

## What's Already Implemented

### Moroz Structured Logging

The Moroz preflight endpoint now outputs structured JSON logs in the following format:

```json
{
  "event_type": "preflight",
  "machine_id": "12345678-1234-1234-1234-123456789012",
  "hostname": "macbook-pro.local",
  "os_version": "14.1.1",
  "os_build": "23B81",
  "model_identifier": "MacBookPro18,3",
  "santa_version": "2024.4",
  "client_mode": 1,
  "serial_number": "C02ABC123DEF",
  "primary_user": "username",
  "binary_rule_count": 150,
  "certificate_rule_count": 25,
  "compiler_rule_count": 5,
  "transitive_rule_count": 10,
  "teamid_rule_count": 8,
  "signingid_rule_count": 12,
  "cdhash_rule_count": 3,
  "request_clean_sync": false,
  "timestamp": "2025-12-09T12:00:00Z",
  "took_ms": 45
}
```

**Client Mode Values:**
- `1` = MONITOR mode
- `2` = LOCKDOWN mode

**Location:** `moroz/svc_preflight.go:78-107`

## PocketBase Integration Plan

### 1. PocketBase Host Collection Schema

Ensure your PocketBase `hosts` collection includes these fields for Santa client data:

```javascript
// Recommended schema additions for Santa client tracking
{
  // Existing fields (from Jamf or other sources)
  serial_number: "text",
  hostname: "text",

  // Santa-specific fields to add:
  santa_version: "text",
  santa_client_mode: "text", // "MONITOR" or "LOCKDOWN"
  santa_last_checkin: "date",
  santa_os_version: "text",
  santa_os_build: "text",
  santa_model_identifier: "text",
  santa_primary_user: "text",

  // Rule counts (useful for monitoring)
  santa_binary_rules: "number",
  santa_certificate_rules: "number",
  santa_compiler_rules: "number",
  santa_transitive_rules: "number",
  santa_teamid_rules: "number",
  santa_signingid_rules: "number",
  santa_cdhash_rules: "number",

  // Sync metadata
  santa_data_source: "text", // "loki"
  santa_last_sync: "date"
}
```

### 2. PocketBase Hook: Loki Sync Job

Create a PocketBase hook at `pb_hooks/moroz_loki_sync.pb.js`:

```javascript
// pb_hooks/moroz_loki_sync.pb.js
/// <reference path="../pb_data/types.d.ts" />

/**
 * Moroz Preflight Data Sync from Loki
 *
 * This hook queries Loki for Santa preflight events and updates
 * the PocketBase hosts collection with current Santa client information.
 */

onAfterBootstrap((e) => {
  const LOKI_URL = $os.getenv('LOKI_URL') || 'http://localhost:3100';
  const SYNC_INTERVAL = 5 * 60 * 1000; // 5 minutes

  console.log('[Moroz-Loki] Starting sync scheduler...');

  // Run immediately on startup, then every SYNC_INTERVAL
  syncMorozData();
  setInterval(() => {
    syncMorozData();
  }, SYNC_INTERVAL);
});

/**
 * Query Loki for recent preflight events and update host records
 */
function syncMorozData() {
  try {
    const lookbackMinutes = 10; // Query last 10 minutes of data
    const now = Date.now() * 1000000; // Loki uses nanoseconds
    const start = (Date.now() - (lookbackMinutes * 60 * 1000)) * 1000000;

    // Query Loki for preflight events
    const lokiQuery = encodeURIComponent('{job="moroz-preflight"} | json | event_type="preflight"');
    const lokiUrl = `${LOKI_URL}/loki/api/v1/query_range?query=${lokiQuery}&start=${start}&end=${now}`;

    console.log(`[Moroz-Loki] Querying Loki: ${lokiUrl}`);

    const response = $http.send({
      url: lokiUrl,
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      },
      timeout: 30
    });

    if (response.statusCode !== 200) {
      console.error(`[Moroz-Loki] Failed to query Loki: ${response.statusCode}`);
      return;
    }

    const data = response.json;

    if (!data.data || !data.data.result || data.data.result.length === 0) {
      console.log('[Moroz-Loki] No new preflight events found');
      return;
    }

    let updateCount = 0;
    let errorCount = 0;

    // Process each stream of results
    data.data.result.forEach((stream) => {
      stream.values.forEach((entry) => {
        try {
          const [timestamp, logLine] = entry;
          const preflightData = JSON.parse(logLine);

          // Update host record
          updateHostWithPreflightData(preflightData);
          updateCount++;
        } catch (err) {
          console.error(`[Moroz-Loki] Error processing entry: ${err}`);
          errorCount++;
        }
      });
    });

    console.log(`[Moroz-Loki] Sync complete: ${updateCount} updated, ${errorCount} errors`);

  } catch (err) {
    console.error(`[Moroz-Loki] Sync error: ${err}`);
  }
}

/**
 * Update or create host record with Santa preflight data
 */
function updateHostWithPreflightData(data) {
  try {
    const hostsCollection = $app.dao().findCollectionByNameOrId('hosts');

    // Find host by serial number or machine ID
    let host = null;
    try {
      host = $app.dao().findFirstRecordByFilter(
        'hosts',
        'serial_number = {:serial}',
        { serial: data.serial_number }
      );
    } catch (e) {
      // Host not found, will create new one
    }

    // Map client_mode integer to string
    const clientModeMap = {
      1: 'MONITOR',
      2: 'LOCKDOWN'
    };
    const clientMode = clientModeMap[data.client_mode] || 'UNKNOWN';

    const updateData = {
      serial_number: data.serial_number,
      hostname: data.hostname,
      santa_version: data.santa_version,
      santa_client_mode: clientMode,
      santa_last_checkin: new Date(data.timestamp),
      santa_os_version: data.os_version,
      santa_os_build: data.os_build,
      santa_model_identifier: data.model_identifier,
      santa_primary_user: data.primary_user,
      santa_binary_rules: data.binary_rule_count,
      santa_certificate_rules: data.certificate_rule_count,
      santa_compiler_rules: data.compiler_rule_count,
      santa_transitive_rules: data.transitive_rule_count,
      santa_teamid_rules: data.teamid_rule_count,
      santa_signingid_rules: data.signingid_rule_count,
      santa_cdhash_rules: data.cdhash_rule_count,
      santa_data_source: 'loki',
      santa_last_sync: new Date()
    };

    if (host) {
      // Update existing host
      host.load(updateData);
      $app.dao().saveRecord(host);
      console.log(`[Moroz-Loki] Updated host: ${data.serial_number}`);
    } else {
      // Create new host record
      const record = new Record(hostsCollection);
      record.load(updateData);
      $app.dao().saveRecord(record);
      console.log(`[Moroz-Loki] Created new host: ${data.serial_number}`);
    }

  } catch (err) {
    console.error(`[Moroz-Loki] Error updating host ${data.serial_number}: ${err}`);
    throw err;
  }
}
```

### 3. Environment Variables

Set these environment variables for your PocketBase instance:

```bash
# Loki endpoint
LOKI_URL=http://your-loki-server:3100
```

### 4. Query Examples for Manual Testing

You can manually query Loki to verify data ingestion:

**Get recent preflight events:**
```bash
curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="moroz-preflight"} | json | event_type="preflight"' \
  --data-urlencode 'start=1733756400000000000' \
  --data-urlencode 'end=1733760000000000000' | jq
```

**Get preflight events for specific machine:**
```bash
curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="moroz-preflight"} | json | machine_id="YOUR-MACHINE-ID"' \
  --data-urlencode 'start=1733756400000000000' \
  --data-urlencode 'end=1733760000000000000' | jq
```

**Get all hosts in LOCKDOWN mode:**
```bash
curl -G -s "http://localhost:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="moroz-preflight"} | json | client_mode="2"' \
  --data-urlencode 'start=1733756400000000000' \
  --data-urlencode 'end=1733760000000000000' | jq
```

## Alternative Backend Integration Options

If you're not using PocketBase, here are integration patterns for other backends:

### Node.js/Express Example

```javascript
const axios = require('axios');
const LOKI_URL = process.env.LOKI_URL || 'http://localhost:3100';

async function syncMorozData() {
  const lookbackMinutes = 10;
  const now = Date.now() * 1000000;
  const start = (Date.now() - (lookbackMinutes * 60 * 1000)) * 1000000;

  const query = encodeURIComponent('{job="moroz-preflight"} | json | event_type="preflight"');
  const url = `${LOKI_URL}/loki/api/v1/query_range?query=${query}&start=${start}&end=${now}`;

  const response = await axios.get(url);

  for (const stream of response.data.data.result) {
    for (const [timestamp, logLine] of stream.values) {
      const preflightData = JSON.parse(logLine);
      await updateHostInDatabase(preflightData);
    }
  }
}

// Run every 5 minutes
setInterval(syncMorozData, 5 * 60 * 1000);
```

### Python/Django Example

```python
import requests
import json
import time
from datetime import datetime, timedelta

LOKI_URL = os.getenv('LOKI_URL', 'http://localhost:3100')

def sync_moroz_data():
    lookback_minutes = 10
    now = int(time.time() * 1e9)
    start = int((time.time() - (lookback_minutes * 60)) * 1e9)

    query = '{job="moroz-preflight"} | json | event_type="preflight"'
    url = f"{LOKI_URL}/loki/api/v1/query_range"
    params = {
        'query': query,
        'start': start,
        'end': now
    }

    response = requests.get(url, params=params)
    data = response.json()

    for stream in data['data']['result']:
        for timestamp, log_line in stream['values']:
            preflight_data = json.loads(log_line)
            update_host_in_database(preflight_data)

# Schedule with celery beat or similar
```

## Monitoring & Troubleshooting

### Verify Moroz Logs

Check that Moroz is outputting structured JSON logs:

```bash
# If running with Docker
docker logs moroz | grep event_type

# If running as systemd service
journalctl -u moroz | grep event_type

# Should see lines like:
# {"event_type":"preflight","machine_id":"...","hostname":"..."}
```

### Verify Loki Ingestion

```bash
# Check Loki labels
curl -s "http://localhost:3100/loki/api/v1/labels" | jq

# Should include "job" label

# Check job values
curl -s "http://localhost:3100/loki/api/v1/label/job/values" | jq

# Should include "moroz-preflight"
```

### Common Issues

**No data in Loki:**
- Check Promtail configuration (see PROMTAIL_CONFIG.md)
- Verify Promtail is running and can reach Moroz logs
- Check Promtail logs: `journalctl -u promtail`

**PocketBase not updating:**
- Check PocketBase hook logs
- Verify `LOKI_URL` environment variable is set
- Test Loki query manually with curl
- Check PocketBase collection schema matches expected fields

**Stale data:**
- Adjust `SYNC_INTERVAL` in the PocketBase hook
- Consider reducing `lookbackMinutes` if you have high-volume logs

## Benefits of This Architecture

1. **Decoupled**: Moroz doesn't need to know about PocketBase
2. **Reliable**: Loki stores all historical preflight data
3. **Queryable**: Can query historical Santa client states
4. **Scalable**: Works with multiple Moroz instances
5. **Flexible**: Can add other log consumers without modifying Moroz

## Next Steps

1. Deploy the updated Moroz binary with structured logging
2. Configure Promtail to ship logs to Loki (see PROMTAIL_CONFIG.md)
3. Implement the PocketBase sync hook (or your backend equivalent)
4. Monitor logs to verify data flow
5. Create dashboards in Grafana for Santa client monitoring
