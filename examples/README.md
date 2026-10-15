# Configure an application

Use this guide to adapt the example apps for your own MariaDB database and expose
fixed queries or controlled writes as MCP tools. The full
[apps.d v1 specification](../docs/mariadb-mcp-app-format.md) defines every field,
data type, SQL restriction and result envelope.

## Before you begin

Build the executable and prepare the service using the
[deployment guide](../deploy/README.md). MariaDB must be on the same host as the
agent and accessible through a Unix socket. You need database administrator
access to provision an application account; the MCP agent doesn't create tables
or grant privileges.

The examples contain placeholders and synthetic data. Create populated credential
files only in your protected configuration directory. Keep each application's
MariaDB username distinct.

## Create private working copies

Publish the `*.example.json` files in this directory. Keep your own populated
configuration under the ignored `config/` directory, or install it directly in
`/etc/mariadb-mcp/`. Use a fresh directory, such as `config/local/`, so you don't
replace an existing deployment bundle.

For an inventory-only bundle, copy and rename these templates:

| Repository template | Private working filename under `config/local/` |
| --- | --- |
| [Server configuration](mcp.example.json) | `mcp.json` |
| [Inventory app](apps.d/inventory.example.json) | `apps.d/inventory.json` |
| [Inventory connection](connections/inventory.example.json) | `connections/inventory.json` |
| [Inventory credentials](credentials/inventory.example.json) | `credentials/inventory.json` |

Create `config/local/`, `apps.d/`, `connections/` and `credentials/` as mode-0700
directories, then give the copied files mode 0600. Adapt the server URL, callback,
socket, database and password for your environment. Generate
`config/local/oauth-credentials.json` using `prepare-auth`; the
[OAuth credential template](oauth-credentials.example.json) only documents its
shape and doesn't contain a valid password hash or client secret.

App and connection references use working filenames without `.example`. Rename
all copied templates consistently rather than changing those references. The
same layout can hold the Tapo example instead of, or alongside, inventory.

Populated `.json` copies left under `examples/` are also ignored. Keep publishable
`*.example.json` files as placeholders; don't edit secrets into them.

## Choose an example

The repository includes these application definitions:

| Example | Database account | Tools | OAuth scopes |
| --- | --- | --- | --- |
| [Minimal Tapo reader](apps.d/tapo.example.json) | `mcpagent` | `tapo__list_sensor_names` | `tapo:read` |
| [Inventory reader and writer](apps.d/inventory.example.json) | `mcp_inventory` | `inventory__get_item`, `inventory__set_item_label` | `inventory:read`, `inventory:write` |

The Tapo example lists stored sensor IDs and names. It requires the collector's
`tapoagent` schema, including `sensors`, `measurements`, `collector_status` and
`schema_migrations`, with migration version 1. Grant its account SELECT on those
four tables. Use the Tapo collector project's provisioning scripts for that
schema. This minimal example differs from the collector-owned integration, which
provides four telemetry tools, including history and collection health.

The inventory example is independent of the collector. It reads exact decimal
prices and JSON attributes and updates one label with an optimistic version check.
Use it to learn the read/write contract or adapt it to another application.

## Prepare the inventory database

For a fresh example database, run this SQL as a MariaDB administrator on the
agent host. It creates an InnoDB table and an account with only the privileges
declared by [inventory.example.json](apps.d/inventory.example.json):

```sql
CREATE DATABASE inventory;
CREATE TABLE inventory.items (
    id BIGINT UNSIGNED PRIMARY KEY,
    label VARCHAR(128) NOT NULL,
    price DECIMAL(65,30) NOT NULL,
    attributes JSON,
    updated_at DATETIME(6) NOT NULL,
    version BIGINT NOT NULL
) ENGINE=InnoDB;

CREATE USER 'mcp_inventory'@'localhost'
    IDENTIFIED BY 'DATABASE_PASSWORD';
GRANT SELECT, UPDATE ON inventory.items TO 'mcp_inventory'@'localhost';

INSERT INTO inventory.items
    (id, label, price, attributes, updated_at, version)
VALUES
    (7, 'Original', 123.45,
     '{"exact":12345678901234567890.123456789}', UTC_TIMESTAMP(6), 1);
```

Replace `DATABASE_PASSWORD` with a unique private password. Run the populated
SQL from a protected local file, and keep it outside version control. The script
is for a fresh database/account; it refuses existing names rather than replacing
application data. Existing databases need their owner's schema and migrations.

The MCP account cannot insert or delete items. Schema changes and sample-row
creation use your administrator account. Don't load the destructive
`tests/fixtures/schema.sql` into an application database.

## Arrange configuration files

Each application has three files. For inventory, install them with these names:

| Source template | Protected destination |
| --- | --- |
| [App definition](apps.d/inventory.example.json) | `/etc/mariadb-mcp/apps.d/inventory.json` |
| [Connection settings](connections/inventory.example.json) | `/etc/mariadb-mcp/connections/inventory.json` |
| [Credential shape](credentials/inventory.example.json) | `/etc/mariadb-mcp/credentials/inventory.json` |

For Tapo, use the matching [app](apps.d/tapo.example.json),
[connection](connections/tapo.example.json) and
[credential template](credentials/tapo.example.json).

Edit the connection's socket and database for your host. In the protected
credential file, replace `DATABASE_PASSWORD` with that account's actual password.
The username must match `database_user` in the app definition. Keep directories
mode 0700 and files mode 0600, owned by the MCP service account. The
[deployment permission helper](../deploy/README.md#prepare-files-and-verify)
creates the standard directories and repairs their permissions.

References resolve from the file containing them. For example,
`apps.d/inventory.json` refers to `../connections/inventory.json`; that connection
refers to `../credentials/inventory.json`. Every `.example.json` filename marks a publication template: remove `.example`
when preparing its private working copy. Keep the JSON file references unchanged
so they point to the matching working filenames.
Never use the placeholder password as an actual credential.

Only install app definitions whose databases and accounts are ready. Copying both
apps into `apps.d` enables both by default, so both must pass startup checks.

The [server template](mcp.example.json) selects `apps.d` with `apps_directory`. Configure
your own public HTTPS URL, exact OAuth callback, listener and state directory;
create real OAuth credentials using `prepare-auth` in the deployment guide.
The [OAuth credential example](oauth-credentials.example.json) shows its shape
and contains no working password hash or client secret.

## Validate and load an app

For the first service installation, follow the deployment guide to initialize
state exactly once. When adding an app to an existing service, stop that service
and run the native check on the agent host:

```sh
sudo systemctl stop mariadb-mcp
sudo -u mcpagent /usr/local/bin/mariadb-mcp check
```

The check validates all enabled apps, credentials, actual grants, schema checks,
prepared SQL metadata and existing OAuth state. It opens no listener and executes
no configured query or write. If validation fails, fix the reported configuration
before starting the service.

After the check succeeds, start the service:

```sh
sudo systemctl start mariadb-mcp
```

Adding a compatible app requires configuration files and a restart, with no
rebuild. Obtain fresh OAuth consent for the new scopes. An old token doesn't gain
access merely because you installed another app.

## Call the inventory tools

After authorizing `inventory:read`, call `inventory__get_item` with these tool
arguments:

```json
{"id":"7"}
```

The result contains `rows`, field metadata, row counts and truncation information.
`id` and `price` are strings to preserve exact integers and decimals; `attributes`
is a JSON value and `updated_at` is a UTC timestamp. See
[query results](../docs/mariadb-mcp-app-format.md#query-execution-and-results).

Read the returned `version` before writing. With `inventory:write` consent, call
`inventory__set_item_label` using that version. For the initial sample row:

```json
{"id":"7","label":"Updated label","expected_version":1}
```

A successful write changes one row, increments its version and returns
`commit: "committed"`. A stale version or missing ID changes zero rows and fails
with `write_precondition_failed`; the transaction rolls back. Read permission and
write permission are separate: `inventory:write` doesn't imply `inventory:read`.
Confirm the changed row with another read using a token that has the read scope.
For an uncertain commit outcome, inspect the row before retrying. See
[write results](../docs/mariadb-mcp-app-format.md#write-execution-and-results).

## Adapt the contract to another application

Change the app ID, description, expected database user, connection, exact table
grants, schema checks and tools. Each tool declares its input JSON schema, fixed
SQL, placeholder bindings, output fields or affected-row bounds. Query tools use
`ORDER BY` and a final `LIMIT ?` bound to `runtime.fetch_limit`. Write tools require
`read_write` access and matching DML privileges; UPDATE and DELETE require WHERE.

The [data type reference](../docs/mariadb-mcp-app-format.md#data-types-and-conversion)
covers strings, integers, bigint, decimal, floating-point numbers, booleans,
dates, local datetimes, UTC timestamps, clock times, durations, JSON and binary.
The [OAuth/MCP section](../docs/mariadb-mcp-app-format.md#oauth-scopes-and-mcp-calls)
explains scoped tool discovery and calls.

Confirm that `tools/list` exposes only the expected tools and that representative
reads, missing rows, permission failures and any permitted writes behave as
documented. Use [private acceptance](../docs/private-acceptance.md) for isolated
fixture verification. Keep application schema migrations and account provisioning
under the application's ownership.
