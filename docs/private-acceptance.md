# Run private acceptance

Use this guide on the development box to verify generic database tools and OAuth
without deploying a service or exposing a public URL. The fixture uses networking-
disabled MariaDB, dedicated test databases/accounts, and loopback HTTP.

## Prepare an isolated MariaDB server

On Debian 13, download and extract these packages under /tmp. This does not
install host packages or a host database service:

```sh
mkdir -m 0700 -p /tmp/mcp-mariadb-packages /tmp/mcp-mariadb-server /tmp/mcp-mariadb-data
cd /tmp/mcp-mariadb-packages
apt-get download mariadb-server-core mariadb-client-core mariadb-common mariadb-server libaio1t64 liburing2 libfmt10 libncurses6
for package in *.deb; do dpkg-deb -x "$package" /tmp/mcp-mariadb-server; done
LD_LIBRARY_PATH=/tmp/mcp-mariadb-server/usr/lib/x86_64-linux-gnu /tmp/mcp-mariadb-server/usr/bin/mariadb-install-db --no-defaults --basedir=/tmp/mcp-mariadb-server/usr --datadir=/tmp/mcp-mariadb-data --auth-root-authentication-method=normal --skip-test-db
```

Initialize once; reuse the existing private fixture directory on later runs.
Start the server in a separate terminal:

```sh
LD_LIBRARY_PATH=/tmp/mcp-mariadb-server/usr/lib/x86_64-linux-gnu /tmp/mcp-mariadb-server/usr/sbin/mariadbd --no-defaults --basedir=/tmp/mcp-mariadb-server/usr --datadir=/tmp/mcp-mariadb-data --socket=/tmp/mcp-mariadb-data/test.sock --pid-file=/tmp/mcp-mariadb-data/test.pid --skip-networking --log-error=/tmp/mcp-mariadb-data/server.log --innodb-buffer-pool-size=64M --user="$(id -un)"
```

All data stays under /tmp. The development fixture's root account has no password
and is reachable only through that private socket. These settings are for this
isolated test instance only.

## Run Go and installer tests

From the MariaDB MCP project root, load its test schema and run the suite:

```sh
LD_LIBRARY_PATH=/tmp/mcp-mariadb-server/usr/lib/x86_64-linux-gnu /tmp/mcp-mariadb-server/usr/bin/mariadb --no-defaults --socket=/tmp/mcp-mariadb-data/test.sock -uroot < tests/fixtures/schema.sql
go test -race ./...
gofmt -l cmd internal
go vet ./...
python3 deploy/test_install.py
bash -n deploy/install.sh
```

The fixture SQL resets only its isolated tapo and inventory databases. Integration
tests verify actual grants, every datatype, query caps/warnings, row-bound rollback,
concurrent edits, dropped COMMIT acknowledgements, OAuth/PKCE/replay, private HTTP,
token restarts/reuse and file protections. Installer tests simulate account and
ownership operations in temporary directories while applying real file modes;
they do not create a development-host account.

## Verify the unchanged release binary and external Tapo definition

Build locally, then load Tapo's separate fixture immediately before acceptance.
Its timestamps are relative to fixture creation, so rerun that load when repeating
time-sensitive checks:

```sh
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w" -o dist/mariadb-mcp ./cmd/mariadb-mcp
LD_LIBRARY_PATH=/tmp/mcp-mariadb-server/usr/lib/x86_64-linux-gnu /tmp/mcp-mariadb-server/usr/bin/mariadb --no-defaults --socket=/tmp/mcp-mariadb-data/test.sock -uroot < ../Temp-MCP/mcp/fixtures/schema.sql
python3 tests/private_acceptance.py --binary dist/mariadb-mcp --tapo-app ../Temp-MCP/mcp/apps.d/tapo.json
```

The harness accepts only fixture sockets resolving under /tmp.
File arguments retain normal operating-system file-path semantics.

The harness prepares credentials through a terminal, initializes protected state,
checks startup metadata, and obtains tokens through the real login/consent/code
flow. It verifies the four Tapo tools, missing/future/stale readings, tie-breaking,
half-open ranges and truncation. It stops and restarts the same binary after
adding inventory JSON, verifies old grants retain only Tapo access, obtains fresh
read/write consent and performs an acknowledged inventory update. SIGTERM must
exit successfully. Tokens/passwords and row contents are not printed.

The official SDK test uses MCP 2026-07-28; this release harness also verifies
2025-11-25. The service uses stateless Streamable HTTP with current-token checks
on every request; tokens persist independently of HTTP transport lifetime.

Successful private acceptance does not establish deployment-host compatibility,
production reader provisioning, public nginx behavior or ChatGPT linking.

## Verify a language transition

To issue tokens with an earlier executable and verify them after starting the Go replacement, add --previous-binary PREVIOUS_BINARY to the same harness command. Replace PREVIOUS_BINARY with your saved executable path. Use fresh fixture SQL before the run. The harness retains the same files and state between implementations and verifies both access and refresh, consent isolation, and a new application.
