# MariaDB MCP

MariaDB MCP exposes configured database tools through the Model Context Protocol
(MCP). Define fixed SQL, inputs, results and a dedicated MariaDB account in JSON,
then restart the same executable to load the application. Read and write tools
use distinct OAuth scopes.

The Go service connects to MariaDB through local Unix sockets and serves plain
HTTP behind an external HTTPS proxy. It includes single-owner login and consent,
PKCE, and durable hashed token grants. Configuration and credentials belong under
/etc/mariadb-mcp/; state belongs under /var/lib/mariadb-mcp/.

Build and test on the development box:

```sh
export GOCACHE=/build/cache GOMODCACHE=/build/mod GOTMPDIR=/build/tmp
export TMPDIR=/build/tmp
go test -race ./...
gofmt -l cmd internal
go vet ./...
python3 deploy/test_install.py
python3 deploy/test_package.py
python3 deploy/package.py
```

The packaging script requires a mounted, writable `/build`. It builds a static
Linux amd64 executable and puts the finished archive and its `.sha256` sidecar
under ignored `dist/`. All archive contents share the `mariadb-mcp/` top-level
directory. See the [deployment guide](deploy/README.md) for verification and
extraction. Compiler output, caches and test scratch stay on `/build`.

Database and OAuth/MCP integration tests need the isolated socket fixture in
[Private acceptance](docs/private-acceptance.md). They fail when it is missing;
they do not substitute mock production data.

Use protected configuration for these commands:

```sh
mariadb-mcp prepare-auth --output CONFIG_DIR/oauth-credentials.json --username OWNER
mariadb-mcp init-state --config CONFIG_DIR/mcp.json
mariadb-mcp check --config CONFIG_DIR/mcp.json
mariadb-mcp serve --config CONFIG_DIR/mcp.json
```

Replace CONFIG_DIR with a prepared mode-0700 directory and OWNER with your login
name. Credential preparation prompts without echo, requires at least 12 password
characters, and writes a new mode-0600 file without replacement. Initialize an
empty state directory once. Reruns refuse existing state. The check command
starts no listener and executes no configured DML.

## Documentation and application examples

Use these guides to configure the service and define database tools:

| Document | Contents |
| --- | --- |
| [apps.d v1 specification](docs/mariadb-mcp-app-format.md) | Full application/connection/credential format, types, SQL policy, results, scopes and limits. |
| [Application examples and walkthrough](examples/README.md) | Read-only Tapo and read/write inventory apps, database schema/grants, private credentials and example tool calls. |
| [Deployment guide](deploy/README.md) | Compiled-binary installation, permissions, OAuth state and service configuration. |
| [Private acceptance](docs/private-acceptance.md) | Isolated database, protocol and persistence verification. |

Start with the [inventory example](examples/apps.d/inventory.example.json) for exact
numeric/JSON reads and a version-checked write, or the
[minimal Tapo reader](examples/apps.d/tapo.example.json) for a read-only app. Every example configuration uses a `.example.json` filename and placeholder
values. Follow [Create private working copies](examples/README.md#create-private-working-copies)
to prepare a bundle under ignored `config/`. Public templates and the format
reference belong in the repository; populated configuration, credentials, runtime
state and local agent documents remain ignored.

The Tapo collector project owns its full telemetry definition, schema and reader
provisioning. This service imports no collector or hub code; the bundled minimal
Tapo example demonstrates the application format independently.

Private verification covers MCP 2025-11-25 and the official SDK's 2026-07-28
flow, typed reads/writes, restart persistence and configuration-only app addition.
Public HTTPS sign-in and consent, PKCE token exchange, and Tapo reads have been
verified in Chromium. ChatGPT linking and telemetry reads are also confirmed.
Build locally and deploy compiled binaries only; the automation host needs no
Go or Rust toolchain. The Linux x86-64 release is statically linked. Deployment
addresses, personal identifiers and generated credentials are kept in ignored
local configuration.

Agent instructions, authoritative working specifications and plans remain
ignored local documents. The application-format reference is shareable.

The Go replacement accepts the existing version 1 app/connection/credential files and Rust-issued OAuth snapshots. Private transition acceptance verifies access and refresh after switching executables without resetting state.

During sign-in, consent lists every scope from enabled applications and tools.
Only scopes in the authorization URL are selected initially. Check additional
read or write scopes to approve them, or uncheck scopes you do not want to grant.
The issued token contains exactly the selected scopes; existing tokens and
refreshes keep their previous permissions. Restart after changing app files.

OAuth settings are grouped under `oauth` in `mcp.json`, with
`"provider": "builtin"` preserving the built-in login, consent, and token behavior.
Existing flat version-1 configurations remain supported. See
[Configure OAuth](docs/oauth-configuration.md) for fields and a migration that
preserves credentials and existing grants. External providers require additional
implementation; an unsupported provider is rejected.
