<p align="center">
<img src="moroz.png" alt="moroz"/><br/>
</p>

Moroz is a server for the [Santa](https://github.com/google/santa) project.

> Santa is a binary allowlisting/blocklisting system for macOS. It consists of a kernel extension that monitors for executions, a userland daemon that makes execution decisions based on the contents of a SQLite database, a GUI agent that notifies the user in case of a block decision and a command-line utility for managing the system and synchronizing the database with a server.
>
> Santa is a project of Google's Macintosh Operations Team.

See this [short video](https://www.youtube.com/watch?v=3w3_bcJYWj0) for a demo.

# Configurations

Moroz uses [TOML](https://github.com/toml-lang/toml#example) rule files to specify configuration for Santa.
The path to the folder with the configurations can be specified with `-configs /path/to/configs`.

Moroz expects a `global.toml` file which contains a list of rules. The `global` config can be overriden by providing a machine specific config. To do so, name the file for each host with the Santa `machine id` [configuration parameter](https://github.com/google/santa/wiki/Configuration#keys-to-be-used-with-a-tls-server). By default, this is the hardware UUID of the mac.

Below is a sample configuration file:

```toml
client_mode = "MONITOR"
#blocklist_regex = "^(?:/Users)/.*"
#allowlist_regex = "^(?:/Users)/.*"
batch_size = 100

[[rules]]
rule_type = "BINARY"
policy = "BLOCKLIST"
identifier = "2dc104631939b4bdf5d6bccab76e166e37fe5e1605340cf68dab919df58b8eda"
custom_msg = "blocklist firefox"

[[rules]]
rule_type = "CERTIFICATE"
policy = "BLOCKLIST"
identifier = "e7726cf87cba9e25139465df5bd1557c8a8feed5c7dd338342d8da0959b63c8d"
custom_msg = "blocklist dash app certificate"

[[rules]]
rule_type = "CDHASH"
policy = "SILENT_BLOCKLIST"
identifier = "935bc0fb5ca31ed7e508b9c5883630fb5b96793a"
custom_msg = "silently block one build of an app"

[[rules]]
rule_type = "TEAMID"
policy = "ALLOWLIST"
identifier = "EQHXZ8M8AV"
custom_msg = "allow google team id"

[[rules]]
rule_type = "SIGNINGID"
policy = "ALLOWLIST"
identifier = "EQHXZ8M8AV:com.google.Chrome"
custom_msg = "allow google chrome signing id"
```

# Creating rules

Acceptable values for client mode:
```
MONITOR | LOCKDOWN
```

Values for `rule_type`, with the `identifier` format each one requires:
```
BINARY      | 64 hex characters (SHA-256 of the file)
CERTIFICATE | 64 hex characters (SHA-256 of the leaf signing certificate)
CDHASH      | 40 hex characters (code directory hash)
TEAMID      | 10 uppercase letters or digits, e.g. EQHXZ8M8AV
SIGNINGID   | TEAMID:signing.id or platform:signing.id
```

Values for `policy`:
```
BLOCKLIST | SILENT_BLOCKLIST | ALLOWLIST | ALLOWLIST_COMPILER | REMOVE
```

Every rule needs `rule_type`, `policy` and `identifier`. A config file with an
unknown key (for example `sha256 =` instead of `identifier =`) or a malformed
identifier is rejected as a whole and the previously loaded policy stays active.

Use the `santactl` command to get the sha256 value: 
```bash
santactl fileinfo /Applications/Firefox.app
```

# Build

The commands below assume you have `$GOPATH/bin` in your path.

```bash
cd cmd/moroz; go build
```

# Run

This branch supports direct telemetry to the modified Moroz manager. A normal
startup requires the manager endpoint and a separate service token file:

```sh
moroz -configs=/config -client-credentials=/run/secrets/client_credentials \
  -manager-url=http://moroz-manager:8090/api/internal/telemetry \
  -ingest-token-file=/run/secrets/ingest_token \
  -outbox-dir=/var/log/moroz/outbox
```

Keep the outbox on persistent local storage. It synchronizes each batch before
acknowledging Santa, retries delivery until the manager commits it, and recovers
after restarts. The queue defaults to 1 GiB / 50,000 batches; full queues return
503, pending batches never expire, and only one process may use a queue directory.
An explicitly configured empty client-credentials JSON object starts with all
clients denied; null or malformed files fail startup. Add
`-fleet-credentials=/run/secrets/fleet_credentials` for shared fleet tokens,
`-known-devices=/config/known-devices.json -require-known-devices` to restrict
them to devices the manager knows, and `-identity-store=` (empty) to disable
serial binding; see "Client authentication" below. The internal service token must be random and at least 32 characters; it is not a
client credential. Use TLS for client access and cross-host manager connections.

# Client authentication

Every Santa route (`/v1/santa/*/{machine_id}`) requires a bearer token. Two
kinds are accepted, checked in this order:

1. **Per-machine token** from `-client-credentials` (JSON `{"<machine_id>":
   "<token>"}`): only valid for its own machine ID. Unchanged from earlier
   releases.
2. **Fleet token** from `-fleet-credentials` (optional): shared by every
   managed Mac through one MDM profile. Identity then comes from the machine
   ID in the URL plus the serial binding described below.

All candidates are compared in constant time. The method is written to each
request log line as `auth=machine` or `auth=fleet:<name>`; token values are
never logged. Both files are polled every 2 seconds for a size, mtime or
inode change (replace by rename or edit in place), validated and swapped in
atomically. Adding a device or rotating a token needs no restart. Invalid
content keeps the previous set and is logged (throttled to one line per five
minutes). At startup both files must exist and validate, or startup fails.

## Fleet credentials file

```json
{
  "tokens": [
    {"name": "pilot-2026", "token": "<random, at least 32 characters>",
     "disabled": false, "expires": "2027-08-31T00:00:00Z"}
  ]
}
```

`disabled` and `expires` (RFC 3339) are optional. Names are unique, 1-64
characters of letters, digits, `_`, `.` or `-`. Tokens are at least 32
characters and unique across fleet tokens and per-machine tokens. Unknown
keys (for example `disable`) reject the whole file. A fleet-only deployment
may omit `-client-credentials`.

### Rotation

1. Add a new entry (`pilot-2027`) next to the old one and replace the file.
   `/healthz` lists it within two seconds.
2. Push the MDM profile with the new token to the fleet.
3. Watch `auth.fleet_tokens[].last_used` and `uses` on `/healthz`: once the
   old token stops being used (allow for offline Macs), set `"disabled": true`
   on it.
4. After a grace period remove the entry. A disabled or expired token is
   refused with 401 like an unknown one.

## Machine identity binding

`-identity-store` (default `<outbox-dir>/../identities.json`, that is
`/var/log/moroz/identities.json` in the pilot; empty disables) binds each
machine ID to the serial number it reports in its first authenticated
preflight (trust on first use). Later preflights with the same serial update
`last_seen` and `last_auth`; a preflight with a different serial is refused
with `403 {"error":"identity mismatch"}`, starts no sync session, increments
`auth.identity_mismatches` on `/healthz` and is logged with both serials
(throttled). A preflight without a serial is accepted but not bound.

The store is written with temp+fsync+rename, at most once per second. At
startup a corrupt store is moved to `identities.json.corrupt-<timestamp>`,
logged loudly and a fresh store starts; this is never fatal. To reset a
binding (for example a logic board swap that kept the hardware UUID), remove
the machine's entry from the file and replace the file atomically:

```sh
jq 'del(.machines["<machine_id>"])' identities.json > identities.json.new \
  && mv identities.json.new identities.json
```

The server adopts the edited file within a second; the next preflight binds
the new serial. Edits within the same second as a server write may be
overwritten, so verify the entry is gone (or restart the server).

## Known-devices allowlist

`-known-devices=PATH` (optional) reads a manager-written JSON file
`{"<machine_id>": {"serial": "<serial>", "name": "<display name>"}}` from the
read-only `/config` volume, with the same hot reload. A missing file turns
the feature off (logged once); an invalid file keeps the previous list.
With `-require-known-devices`, fleet-token authentication is accepted only
for machine IDs in the loaded file (403 `unknown device` otherwise), and at
preflight an entry with a non-empty `serial` must equal the reported serial.
Rule download, postflight and event upload only need the machine to have
authenticated. Per-machine tokens are never subject to this check.

## Security model

A fleet token sits in an MDM profile and is readable by the local user of
any managed Mac, so it proves only that a request comes from a device that
received the profile. It does not identify the device: identity comes from
the machine ID in the URL bound to the serial number reported at first
preflight, optionally cross-checked against the manager's known-devices list.
A stolen fleet token lets an attacker impersonate an unenrolled machine ID
(which then receives the global policy) or replay the identity of a known
machine only if they also know its serial; it does not let them change rules.
Rotate fleet tokens on a schedule and immediately when a Mac leaves
management.

Everything a client reports (hostname, serial, rule counts, events) is
untrusted input from the same local user: the server validates shape and
size, binds the serial once, and forwards the rest as telemetry for operators
to read with that in mind. Per-machine tokens remain the stronger option for
high-value machines and keep working alongside fleet tokens.

## Health

`GET /healthz` (no credentials, not forwarded by the ingress) reports the
policy generation, outbox depth and an `auth` block:

```json
"auth": {"machine_tokens": 2,
         "fleet_tokens": [{"name": "pilot-2026", "enabled": true,
                           "last_used": "2026-09-15T18:00:00Z", "uses": 41}],
         "identities": 2, "identity_mismatches": 0, "known_devices": null}
```

`known_devices` is `null` while no allowlist is loaded. Counters are kept in
memory and reset on restart. Token values are never included.

Without a manager, explicitly select `-standalone`. In that mode `-persist-events`
(default true) writes dated JSONL files under `-event-dir`; it does not update the
console. `-allow-unauthenticated` is for isolated synthetic tests only. Run
`moroz -h` for all current flags. Earlier quickstart material below describes a
standalone demonstration and needs these new explicit flags and client credentials.

# Quickstart

Download the `moroz` binary from the [Releases](https://github.com/groob/moroz/releases) page.
Copy the `configs` folder from the repo somewhere locally. It must have the `global.toml` file.


Generate a self-signed certificate which will be used by Santa clients and the server for communication.

```
./tools/dev/certificate/create
```

Add the Santa CN to your hosts file.

```
sudo echo "127.0.0.1 santa" >> /etc/hosts
```

Add the self-signed cert to your system roots. 

```
./tools/dev/certificate/add-trusted-cert
```

## Install Santa:
The latest version of Santa is available on the GitHub repo page: https://github.com/google/santa/releases

## Configure Santa:
You will need to provide the `SyncBaseURL` settings. See the [Santa repo](https://github.com/google/santa/blob/01df4623c7c534568ca3d310129455ff71cc3eef/Docs/deployment/configuration.md#important) for a complete guide on all the client configuration options.

## Start moroz:
Assumes you have the `./server.crt` and `./server.key` files.

```
moroz -configs /path/to/configs/folder
```

---
moroz icon by [Souvik Bhattacharjee](https://thenounproject.com/souvik502/) from the [Noun Project](https://thenounproject.com/).
