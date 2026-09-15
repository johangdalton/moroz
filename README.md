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
sha256 = "2dc104631939b4bdf5d6bccab76e166e37fe5e1605340cf68dab919df58b8eda"
custom_msg = "blocklist firefox"

[[rules]]
rule_type = "CERTIFICATE"
policy = "BLOCKLIST"
sha256 = "e7726cf87cba9e25139465df5bd1557c8a8feed5c7dd338342d8da0959b63c8d"
custom_msg = "blocklist dash app certificate"

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

Values for `rule_type`:
```
BINARY | CERTIFICATE | TEAMID | SIGNINGID
```

Values for `policy`:
```
BLOCKLIST | ALLOWLIST | ALLOWLIST_COMPILER | REMOVE
```

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
clients denied; null or malformed files fail startup. The internal service token must be random and at least 32 characters; it is not a
client credential. Use TLS for client access and cross-host manager connections.

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
