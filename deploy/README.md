# Prepare MariaDB MCP for deployment

Use this guide to prepare the automation host after local acceptance. MariaDB
stays socket-only. Application owners provision schemas and accounts; the
directory helper performs no database administration.

## Before you begin

Build locally using `python3 deploy/package.py` and the `/build` settings in the
[project README](../README.md). Transfer the printed archive and matching
`.sha256` file from `dist/` to the target. Verify and extract them there:

```sh
sha256sum -c ARCHIVE_NAME.tar.gz.sha256
tar -xzf ARCHIVE_NAME.tar.gz
cd mariadb-mcp
```

Replace ARCHIVE_NAME with the archive basename printed by the packaging script,
without its `.tar.gz` extension. Every archive entry is beneath `mariadb-mcp/`.
Use an empty extraction destination to preserve an existing installation bundle.
The package includes `bin/`, public examples, documentation and `deploy/` files.
The release is a stripped, statically linked Linux x86-64 executable. It requires
no glibc libraries. Check target architecture and execution before activation.
The directory helper needs Python 3 and standard Linux account utilities.
The target needs no Go or Rust toolchain or database development packages.

Stop the service before copying files or rerunning permissions. The helper
rejects symlinks, special files, hard links and filesystem roots, and preserves
the contents of credentials and tokens.

## Prepare files and verify

1. Run the helper as root:

```sh
sudo bash deploy/install.sh
```

It creates the unprivileged mcpagent account/group and mode-0700 directories:
 /etc/mariadb-mcp/, its apps.d/, connections/ and credentials/ children, and
 /var/lib/mariadb-mcp/. Existing files become mode 0600 with mcpagent ownership.

2. Install the compiled executable:

```sh
sudo install -m 0755 bin/mariadb-mcp /usr/local/bin/mariadb-mcp
```

3. Copy your configured files using this layout:

```text
/etc/mariadb-mcp/mcp.json
/etc/mariadb-mcp/oauth-credentials.json
/etc/mariadb-mcp/apps.d/APP.json
/etc/mariadb-mcp/connections/APP.json
/etc/mariadb-mcp/credentials/APP.json
```

Replace APP with the application ID. Put the actual HTTPS URL and exact callback
allowlist in `oauth.redirect_uris` in mcp.json. See
[Configure OAuth](../docs/oauth-configuration.md) for the supported provider and
legacy configuration migration. Keep the listener private. Examples contain placeholders
and private fixture callbacks.

4. Rerun permissions after copying. If you have not generated and transferred
   OAuth credentials from a protected development directory, create them:

```sh
sudo bash deploy/install.sh
sudo -u mcpagent /usr/local/bin/mariadb-mcp prepare-auth --output /etc/mariadb-mcp/oauth-credentials.json --username OWNER
```

Replace OWNER with your login name. Keep client credentials in the protected
file. Do not put passwords in command arguments. The credential example shows
the shape only; prepare-auth generates a valid Argon2id hash and secrets.

5. Initialize state once and check prerequisites:

```sh
sudo -u mcpagent /usr/local/bin/mariadb-mcp init-state
sudo -u mcpagent /usr/local/bin/mariadb-mcp check
```

Omit init-state if state exists; it refuses overwrite and nonempty directories.
Stop a running instance before check, which requires the state lock. Failed
checks return fixed codes; result metadata mismatches identify the field index
and expected/actual datatype. Checking never executes configured DML.

6. Install the unit after checks succeed:

```sh
sudo install -m 0644 deploy/mariadb-mcp.service /etc/systemd/system/mariadb-mcp.service
sudo systemctl daemon-reload
```

Service activation is a separate deployment action. The unit uses mcpagent,
preserves state, restricts writable system paths and allows ten seconds for
shutdown. Configuration errors prevent restart loops.

## Add an application

Give each app a distinct database username, connection file and credential file.
Grant exactly its declared table privileges. Global/schema/column grants, roles,
proxy grants and GRANT OPTION are rejected. App files neither grant database
privileges nor expand OAuth consent.

Copy files, stop the service, rerun permissions, run check, then restart it.
The executable needs no rebuild. Obtain new consent for new app or write scopes.
Fresh unauthenticated MCP requests advertise the enabled read scopes in the
`WWW-Authenticate` header. Clients that follow this hint can request the updated
read permissions without a manually maintained list. Existing tokens and tool
refreshes retain their approved scopes. After login, consent lists every enabled
read and write scope as a checkbox. Only scopes in the URL are checked by default;
select additional scopes explicitly before approving. You can also uncheck a
requested scope. At least one and at most 64 selections are required. An
insufficient-scope tool call advertises its exact required permission.
See [OAuth scopes and MCP calls](../docs/mariadb-mcp-app-format.md#oauth-scopes-and-mcp-calls)
for client compatibility limits. Confirm the installed binary supports these
challenges before relying on this workflow.

## Keep HTTP private until proxy acceptance

The later-use [nginx example](nginx.conf.example) is illustrative and is not
installed by the helper. Set the URL, destination and browser IP/VPN allowlist
before using it. Preserve Host and Authorization and disable streaming buffering.
Protect browser authorization/login/consent with your chosen source restrictions;
discovery, token and MCP endpoints follow their own authentication flows.

Public proxy compatibility, browser OAuth and ChatGPT telemetry reads have
been verified. Validate your own proxy and client configuration before exposing
the service. Forwarded headers do not authenticate clients.

## Replace the earlier Rust executable

Stop the service, replace the compiled executable, run the permission helper and check, then start the service. Keep your existing configuration, OAuth credentials, and state files. Do not run init-state again. Private transition acceptance verifies that existing access and refresh tokens remain usable.

## Deployment checks

Use /etc/mariadb-mcp/ for protected configuration and /var/lib/mariadb-mcp/ for
durable token state. Native check validates the application accounts, exact grants,
schemas and prepared metadata. The Tapo reader uses SELECT only on its four tables.

The default listener is loopback-only. If your HTTPS proxy runs on a different
host, configure listen with an interface and port reachable through your private
network, and restrict access appropriately. Set public_base_url to your public
HTTPS URL and `oauth.redirect_uris` to the exact callback supplied by your client.

Preserve the public Host and Authorization headers. For example, nginx can use
proxy_set_header Host $host. Requests with unrelated Host or Origin values are
rejected. Public-host login cookies require HTTPS in the browser.

Verify sign-in, explicit consent, tool discovery, a read-only query and token
persistence across restart. Stop the service before running check. Keep protected
configuration and token files unchanged when replacing the compiled executable;
never rerun init-state to troubleshoot a connection.
