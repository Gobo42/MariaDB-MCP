# MariaDB MCP application file reference

This reference is for administrators and application developers who define
database tools for the standalone MariaDB Model Context Protocol (MCP) agent.
It describes the implemented version 1 application format, including
typed reads, explicitly enabled writes, separate database identities, and
examples you can share without credentials.

**Status: version 1 is implemented in Go and verified with private socket/HTTP fixtures.**
The Tapo reader/schema and four tools pass production acceptance on the
automation host. Public browser OAuth/MCP and user-confirmed ChatGPT telemetry
reads are verified. Validate each application's own database and account before
deployment. See [Private acceptance](private-acceptance.md) for reproducing
configuration, read/write, datatype and restart verification.

For setup instructions, sample database SQL and tool-call arguments, start with
[Application examples](../examples/README.md). Downloadable definitions include a
[minimal read-only Tapo app](../examples/apps.d/tapo.example.json) and a
[read/write inventory app](../examples/apps.d/inventory.example.json).

## Contents

- [File layout and loading](#file-layout-and-loading)
- [Application object](#application-object)
- [Connection and credentials](#connection-and-credentials)
- [Database identity and permissions](#database-identity-and-permissions)
- [Schema checks](#schema-checks)
- [Tool objects](#tool-objects)
- [Input schemas and defaults](#input-schemas-and-defaults)
- [SQL bindings](#sql-bindings)
- [Data types and conversion](#data-types-and-conversion)
- [Returned field objects](#returned-field-objects)
- [Cross-argument constraints](#cross-argument-constraints)
- [Query execution and results](#query-execution-and-results)
- [Write execution and results](#write-execution-and-results)
- [OAuth scopes and MCP calls](#oauth-scopes-and-mcp-calls)
- [Validation, failures, and limits](#validation-failures-and-limits)
- [Read-only application example](#read-only-application-example)
- [Writable application example](#writable-application-example)
- [Verification coverage](#verification-coverage)

## File layout and loading

The deployment layout is:

```text
/etc/mariadb-mcp/
  mcp.json
  oauth-credentials.json
  apps.d/
    tapo.json
    inventory.json
  connections/
    tapo.json
    inventory.json
  credentials/
    tapo.json
    inventory.json
/var/lib/mariadb-mcp/
  oauth-state.json
```

One regular UTF-8 JSON file directly inside `apps.d/` defines one application.
Files load in filename order at startup. Comments, trailing commas, duplicate
JSON keys, symlinks, unsupported versions, and unknown configuration keys are
errors. Disabled files still undergo structural validation but their database
connections, tools, and scopes are not activated. IDs and database usernames
must be unique across all loaded application files, including disabled files.
An enabled application needs at least one enabled tool; an empty active registry
is an error. A malformed application prevents startup rather than being skipped.

Relative file references resolve against the file containing the reference.
Normalize directory paths using platform path utilities, including paths with
single or repeated trailing separators; preserve filesystem roots and symlink
refusal. Directories use mode 0700 and files use mode 0600, accessible to the MCP
service account. Passwords belong exclusively in protected credential files.
The application file must not contain passwords, bearer tokens, or client secrets.

Add files, validate the configuration, and restart the same executable to load
another application. Version 1 does not hot reload. Adding tables, columns,
queries, or tools supported by this contract requires no application-specific
code or rebuild. An operation outside this contract requires a future runtime
feature, not executable code embedded in configuration.

## Application object

The following keys are permitted at the root:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `version` | Yes | Integer; must be `1`. |
| `app_id` | Yes | Stable identifier matching `^[a-z][a-z0-9_]{0,31}$`. |
| `description` | Yes | Nonblank display description, at most 1024 characters. |
| `enabled` | No | Boolean; defaults to `true`. |
| `connection_file` | Yes | Nonblank path to this application's connection JSON. |
| `database_user` | Yes | Expected MariaDB username, using the same identifier pattern as `app_id`; unique across applications. |
| `access` | No | `read_only` or `read_write`; defaults to `read_only`. |
| `grants` | Yes | Nonempty array of table/view grants described in Database identity and permissions. |
| `constants` | No | Object of named, nonsecret JSON values; defaults to an empty object. |
| `schema_checks` | No | Array of required table/column checks; defaults to an empty array. |
| `schema_version` | No | Optional migration-version assertion described in Schema checks. |
| `tools` | Yes | Nonempty array of tool objects. |

Constant names use `^[a-z][a-z0-9_]{0,63}$`. Constant values undergo the
same binding conversion and size checks as caller arguments. Constants are
administrator settings, not replacements for a credentials file.

The filename need not match `app_id`, but matching names make configuration
easier to maintain. Changing `app_id` changes tool names and OAuth scopes.

## Connection and credentials

Each application has its own connection file and credentials file. Sharing a
username or connection/credential file between application definitions is
rejected. Multiple applications may use the same socket or database.

A connection file contains exactly these keys:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `socket` | Yes | Absolute path to a local MariaDB Unix socket; no TCP fallback. |
| `database` | Yes | ASCII database identifier, 1–64 letters, digits, or underscores. |
| `credentials_file` | Yes | Nonblank path to the protected credentials JSON, relative to this connection file when not absolute. |

For example, `connections/inventory.json` contains:

```json
{
  "socket": "/run/mysqld/mysqld.sock",
  "database": "inventory",
  "credentials_file": "../credentials/inventory.json"
}
```

The referenced credentials file contains exactly these keys:

```json
{
  "username": "mcp_inventory",
  "password": "DATABASE_PASSWORD"
}
```

`DATABASE_PASSWORD` is a placeholder for a nonblank private database password.
Do not share a populated credentials file. Its `username` must match the
application's `database_user` and the authenticated `CURRENT_USER()` must be
that account at `localhost`; proxy authentication or a different matched
account is rejected. The Linux service username is independent of these
MariaDB usernames.

## Database identity and permissions

Each entry in `grants` contains exactly:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `table` | Yes | Unqualified table or view name in the connection's database; 1–64 ASCII letters, digits, or underscores. |
| `privileges` | Yes | Nonempty array with unique values from `SELECT`, `INSERT`, `UPDATE`, `DELETE`. |

Table names are unique within `grants`. Wildcards and privileges on other
databases are not permitted. A read-only application permits only SELECT.
A writable application lists only the additional DML privileges it needs;
`read_write` does not automatically grant all four privileges.

At startup, effective table privileges must match the configured grant set.
Reject broad database grants, column grants, extra table grants, roles, PROXY,
grant options, and global privileges beyond USAGE. Reject CREATE, ALTER, DROP,
FILE, EXECUTE, account administration, and other privileges. Query access
through a granted view is permitted; the administrator must review its definer
and underlying access. SQL, views, triggers, and account provisioning remain
trusted administrator responsibilities.

The grant check uses MariaDB's effective privileges, not the application's
claim about them. See the
[MariaDB GRANT reference](https://mariadb.com/docs/server/reference/sql-statements/account-management-sql-statements/grant).

The database remains the enforcement boundary: setting `access` or changing
`grants` in JSON does not create users or grant privileges. An administrator
provisions each account separately, then configuration validation checks it.
No provisioning or privilege changes are exposed as MCP tools.

For Tapo, the MCP application uses `mcpagent` with SELECT on the four
telemetry tables. The existing collector's different `tapoagent` account needs
INSERT/UPDATE to store readings. This reference does not remove those collector
permissions. A second application uses another username, such as
`mcp_inventory`; do not reuse the Tapo reader.

## Schema checks

Each `schema_checks` entry contains a required `table` identifier and a
nonempty `columns` array of unique column identifiers. These checks verify
existence, not an exhaustive database schema. Each checked table must also be
listed in `grants`. Query preparation checks selected column metadata and
bindings; runtime conversions enforce declared result types.

`schema_version`, when present, contains `table`, `column`, and nonnegative integer
`expected`. The table must be granted SELECT. Validate that its column is an
integer and its nonempty maximum stored value equals `expected`. A missing
value or a later migration version fails validation. Applications without a
migration table omit this object.

Tapo's assertion is:

```json
{
  "table": "schema_migrations",
  "column": "version",
  "expected": 1
}
```

## Tool objects

Every enabled tool becomes `APP__TOOL`. Both parts are stable:
`inventory__set_item_label` belongs to the application `inventory`.

| Key | Required | Type and behavior |
| --- | --- | --- |
| `name` | Yes | Local name matching `^[a-z][a-z0-9_]{0,63}$`; unique within the application. |
| `description` | Yes | Nonblank description, at most 2048 characters, explaining inputs, results, and effects. |
| `enabled` | No | Boolean; defaults to `true`. |
| `kind` | Yes | `query` for SELECT; `execute` for a configured INSERT, UPDATE, or DELETE. |
| `input_schema` | Yes | JSON Schema object for the caller's argument object. |
| `sql` | Yes | One administrator-written SQL statement; no caller-provided SQL or identifiers. |
| `bindings` | Yes | Ordered array supplying one value for each SQL `?` placeholder; may be empty for parameter-free execute statements. |
| `constraints` | No | Array of cross-argument rules; defaults to an empty array. |
| `timeout_seconds` | No | Integer 1–5; defaults to 5, including pool wait, statement, and transaction completion. |

Only query tools permit these additional keys:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `fields` | Yes | Nonempty array of typed returned columns, in display order. |
| `max_rows` | No | Integer 1–1000; defaults to 1000. |
| `default_limit` | No | Integer 1–`max_rows`; defaults to the smaller of 500 and `max_rows`. |
| `limit_argument` | No | Name of a top-level integer input used as the requested limit. It may not also be bound directly to SQL. |
| `empty_result` | No | `empty` or `not_found`; defaults to `empty`. |

Only execute tools permit these additional keys:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `max_affected_rows` | No | Integer 1–1000; defaults to 1. |
| `min_affected_rows` | No | Integer 0–`max_affected_rows`; defaults to 0. |
| `return_last_insert_id` | No | Boolean; defaults to `false`; permitted only for INSERT. |
| `destructive` | No | Boolean MCP hint; defaults to `true`. Set false only for effects that do not overwrite/remove existing data. |
| `idempotent` | No | Boolean MCP hint; defaults to `false`. Set true only when repeating identical arguments cannot add another effect. |

Query tools cannot declare execute-only keys; execute tools cannot declare
query-only keys. An enabled execute tool in a read-only application is invalid.
Tool descriptions and annotations are public metadata for authorized clients,
so they must not contain secrets.

## Input schemas and defaults

The schema dialect is JSON Schema 2020-12, using the following supported subset.
The root must have `type: "object"`, `properties`, and
`additionalProperties: false`. A no-argument tool uses empty `properties`.
Top-level argument names use the constant-name pattern; nested JSON properties
retain their application-defined names.

| Area | Supported keywords |
| --- | --- |
| Types | `type`: object, array, string, integer, number, boolean, null; a two-item type array may combine one type with null. |
| Objects | `properties`, `required`, `additionalProperties` as a boolean or child schema, `minProperties`, `maxProperties`. |
| Arrays | `items` as one schema, `minItems`, `maxItems`, `uniqueItems`. |
| Strings | `minLength`, `maxLength`, `pattern`, `format` from date, time, date-time, uuid. |
| Numbers | `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`, `multipleOf`. |
| Any value | `enum`, `const`. |
| Annotations | `title`, `description`, `default`, `examples`, and optional `$schema` equal to `https://json-schema.org/draft/2020-12/schema`. |

Unsupported keywords, formats, external references, `$ref`, schema composition,
and tuple validation are configuration errors. Nested objects/arrays allow typed
JSON documents; explicitly permitted nested arbitrary properties represent data,
not additional tool arguments. Values and schemas have a maximum depth of 32. JSON number exponents must be
between -10000 and 10000 to bound exact-number validation work. Exact decimal
and bigint strings retain their separate datatype rules. Invalid UTF-8 or lone
escaped Unicode surrogates are rejected.
Schema patterns use the portable subset supported by Go RE2, without
implementation-specific extensions. Lookaround and backreferences are unsupported;
patterns that cannot compile fail configuration validation.

The agent explicitly inserts defaults for missing optional top-level arguments,
then validates the result. Defaults must themselves satisfy their schemas.
Required arguments must be supplied even when a default is documented. Do not
insert defaults recursively into arbitrary JSON payloads. Missing optional
arguments without defaults may bind SQL NULL only when their binding permits
NULL; otherwise validation fails. Explicit null also requires a nullable input
schema and binding. Unknown root arguments are rejected.

Formats are validated, not merely advertised. Date-time values require an
explicit timezone; timestamp bindings normalize offsets to UTC. Arrays and
objects bind as a single JSON value, not as interpolated SQL or an expanded
IN list. Use fixed SQL with database JSON functions for collection inputs.
See the [JSON Schema validation vocabulary](https://json-schema.org/draft/2020-12/json-schema-validation)
for keyword definitions; default insertion and the restricted subset are this
agent's version 1 contract.

## SQL bindings

Each binding contains exactly:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `source` | Yes | `argument`, `constant`, or `runtime`. |
| `name` | Yes | Top-level argument name, constant name, or reserved runtime name. |
| `db_type` | Yes | One of the type names in Data types and conversion. |
| `nullable` | No | Boolean; defaults to `false`. |

Bindings refer only to defined names and follow placeholder order. Reusing an
argument in several placeholders requires a binding for each occurrence.
Count placeholders using SQL parsing/prepared metadata, not raw question marks
inside literals or comments. No templating, substitution, identifier binding,
environment expansion, shell execution, or arbitrary expression evaluation is
supported.

Two runtime names are defined:

| Name | Type | Behavior |
| --- | --- | --- |
| `fetch_limit` | integer | Query-only; effective requested/default limit plus one, for truncation detection. |
| `now_utc` | timestamp | One UTC time captured for the call; reused bindings receive the same value. |

Both are nonnullable. Each query requires its final top-level `LIMIT ?` to bind
`fetch_limit`; callers cannot bypass the result cap by providing a larger SQL
limit. No OFFSET is accepted in version 1. Configured queries require a
deterministic ORDER BY, with a unique tie-breaker where needed. Callers use
narrower ranges or application-defined keyset arguments for further results.

## Data types and conversion

The following type names are permitted in `db_type` and returned `fields.type`.
They describe wire representation and conversion, not a requirement that every
application use the same MariaDB column types.

| Type | JSON representation | Database conversion |
| --- | --- | --- |
| `string` | String | UTF-8 CHAR/VARCHAR/TEXT/ENUM/SET or a textual SQL projection. Invalid UTF-8 is an error; use binary for raw bytes. |
| `integer` | Number with no fractional part | SQL integer constrained to the interoperable range −9007199254740991 through 9007199254740991. |
| `bigint` | Base-10 integer string | Exact signed/unsigned SQL integer, up to MariaDB BIGINT bounds. No float conversion. |
| `decimal` | Plain base-10 string, such as `"123.4500"` | Exact DECIMAL value; no exponent or rounding through floating point. |
| `number` | Finite JSON number | Approximate numeric use, including FLOAT/DOUBLE and deliberately numeric DECIMAL projections. Use decimal for exact financial values. |
| `boolean` | true or false | SQL integer 0/1 only; other stored numbers are errors. |
| `date` | `"YYYY-MM-DD"` | Valid SQL DATE; year 1000–9999. Zero/invalid dates are errors. |
| `datetime` | `"YYYY-MM-DDTHH:MM:SS[.ffffff]"` | DATETIME representing local wall time, without a timezone; no invented UTC suffix. |
| `timestamp` | RFC 3339 string with offset on input, Z on output | TIMESTAMP, or a DATETIME column explicitly known by its author to contain UTC. Sessions use UTC; offsets normalize to UTC. |
| `time` | `"HH:MM:SS[.ffffff]"` | TIME used as a clock time from 00:00:00 up to but excluding 24:00:00. |
| `duration` | Signed `"H+:MM:SS[.ffffff]"`, such as `"-125:05:06"` | TIME used as an interval, including negative values and hours above 23, within MariaDB's representable TIME range. |
| `json` | Any JSON value, including objects and arrays | Validate and serialize one JSON value for binding; parse returned JSON text to a JSON value. Invalid JSON is an error. |
| `binary` | Canonical padded RFC 4648 base64 string | Decode to bytes for BINARY/VARBINARY/BLOB binding; encode returned bytes. Images/documents remain JSON data, not automatic MCP image/resource content. |

Input schemas must match the listed representation. Non-JSON argument bindings
require an explicit compatible property type; nullable properties also require a
nullable binding. Constants are checked against their binding type at startup. SQL clock times and local
DATETIME strings use string patterns and typed bindings; JSON Schema's
timezone-bearing time/date-time formats do not describe those unzoned values.
SQL temporal ranges follow MariaDB's
[TIME](https://mariadb.com/docs/server/reference/data-types/date-and-time-data-types/time),
[DATETIME](https://mariadb.com/docs/server/reference/data-types/date-and-time-data-types/datetime),
and [TIMESTAMP](https://mariadb.com/docs/server/reference/data-types/date-and-time-data-types/timestamp)
definitions; this contract rejects zero/invalid dates and leap seconds.

Integer and numeric
conversions validate the destination's actual range and precision. BIGINT and
DECIMAL strings reject surrounding whitespace and exponent notation; the
database's signedness/precision/scale still apply. BIGINT uses canonical
`0` or `-?[1-9][0-9]*`; DECIMAL uses
`-?(0|[1-9][0-9]*)([.][0-9]+)?`, preserving its fractional digits.
Sessions use strict SQL mode. Any statement warning also fails the call and
rolls back a write, including conversion or fractional-truncation warnings that
MariaDB might report without raising an error.
Datetime values use up to six fractional digits; TIMESTAMP availability also
depends on the deployed MariaDB version. Unsupported values fail rather than
being clamped or silently rounded.

SQL NULL returns JSON null only for a nullable field. A nullable binding maps
JSON null to SQL NULL, including for `json`; to store the JSON literal null
instead, define a text binding carrying `"null"` into a JSON column. Returned
SQL NULL and a JSON literal null both appear as JSON null; add a projected
null-status column if an application needs to distinguish them. For nonnull SQL
JSON values, any configured JSON schema applies to the decoded value, including
a JSON literal null. The object key $serde_json::private::Number is reserved and rejected because
the exact-number parser would reinterpret such objects. Its use as a string
value is permitted.
Preserve nested JSON numbers without a floating-point
round-trip; use strings inside application JSON when clients need exact values.

UUIDs, URLs, labels, enums, spatial WKT, and application-specific values use a
validated string or JSON projection. BIT/spatial/vendor-specific values need
an explicit SQL conversion to one of the declared types. Unsupported or
ambiguous conversions fail; there is no silent stringification of arbitrary
driver values. MariaDB stores JSON as validated text; see its
[JSON type documentation](https://mariadb.com/docs/server/reference/data-types/string-data-types/json).

## Returned field objects

Each query field contains:

| Key | Required | Type and behavior |
| --- | --- | --- |
| `name` | Yes | Unique JSON field name, using the constant-name pattern. |
| `column` | No | SQL result column/alias, 1–64 ASCII letters, digits, or underscores; defaults to `name`. |
| `type` | Yes | Type from Data types and conversion. |
| `nullable` | No | Boolean; defaults to `false`. |
| `description` | No | Description, at most 1024 characters; defaults to an empty string. |
| `units` | No | Nonblank unit label, at most 64 characters. |
| `json_schema` | No | Schema using the supported subset, permitted only for `type: "json"`; omission permits any bounded JSON value. |

Prepared column types must support the declared conversion. Cast projected
parameters to an explicit SQL type when preparation otherwise reports unresolved
NULL metadata; for example, SELECT CAST(? AS CHAR) AS label. Nullable SQL NULL
projections remain supported.

Selected result aliases must be unique and correspond exactly to declared
columns. Extra, missing, or duplicate result columns fail validation; SELECT *
is rejected. Renaming uses `column` and `name`, without revealing undeclared
columns. Units describe values; the agent does not silently convert them.
Use fixed SQL for calculations and unit conversions. Each declared field is
present in every row, including nullable fields.

## Cross-argument constraints

Version 1 supports one rule kind:

```json
{
  "kind": "time_range",
  "start": "start",
  "end": "end",
  "max_seconds": 2678400
}
```

`start` and `end` name required, nonnullable date-time arguments. They must
parse with explicit timezones, and `start < end`. `max_seconds` is a positive
integer limiting the span; 2678400 represents 31 days. Validation happens before
querying. A tool accepting a range must describe and implement half-open
`[start, end)` boundaries in its fixed SQL. Constraint objects contain exactly
these four keys. Other business conditions belong in SQL predicates or database
constraints; arbitrary constraint scripts are not supported.

## Query execution and results

A query is one SELECT, optionally using a read-only WITH clause, joins,
aggregates, or granted views. Reject multiple statements, writes, locking reads,
file output, stored procedures, and user-defined/stored functions. Queries use
prepared parameters and a read-only transaction even when the application has
a writable account. Reject side-effecting functions, including lock acquisition,
sequence advancement, and variable assignment. Other fixed built-in functions
are accepted from the supported builtin set below; other function names fail
configuration validation. SQL table references are unqualified and resolve in
the configured database. Administrator SQL and least-privilege grants remain
separate boundaries.

Read at most the effective limit plus one. Remove the extra row and set
`truncated` when more data exists. Limit the complete serialized MCP tool result,
including structured and text representations, to 1 MiB; stop before a complete
row would exceed that cap and flag truncation. If a single row
cannot fit in an otherwise empty result, return `result_too_large` rather than
an empty truncated success. Zero rows return an empty rows array unless
`empty_result` is `not_found`. That policy means the configured query found
no rows; it does not independently prove an entity is absent. To distinguish
an unknown entity from a known entity without readings, project metadata and
explicit presence/status fields with a join, or provide a separate lookup tool.
The engine does not infer domain-specific absence semantics from an empty result.
An empty result is not a zero-valued measurement.

A query result's structured content follows this envelope:

```json
{
  "app_id": "tapo",
  "tool": "tapo__list_sensor_names",
  "kind": "query",
  "fields": [
    {"name": "id", "type": "string", "nullable": false},
    {"name": "name", "type": "string", "nullable": false}
  ],
  "rows": [{"id": "sensor_1", "name": "Room A"}],
  "row_count": 1,
  "limit": 100,
  "truncated": false,
  "ranges": []
}
```

`fields` reflects the configured field metadata, including optional units,
descriptions, and JSON schemas when supplied; it omits internal SQL column
names. `ranges` contains one object per time-range constraint with normalized
UTC `start` and `end` and their `start_argument`/`end_argument` names.
It is empty when there are no such constraints. Inputs/constants are not
otherwise echoed automatically.


The supported builtin names are case-insensitive:

```text
ABS ACOS ASIN ATAN ATAN2 CEIL CEILING COS COT DEGREES EXP FLOOR LN LOG LOG2
LOG10 MOD PI POW POWER RADIANS ROUND SIGN SIN SQRT TAN TRUNCATE AVG BIT_AND
BIT_OR BIT_XOR COUNT GROUP_CONCAT MAX MIN STD STDDEV STDDEV_POP STDDEV_SAMP SUM
VAR_POP VAR_SAMP VARIANCE COALESCE IF IFNULL NULLIF ASCII BIN CHAR CHAR_LENGTH
CHARACTER_LENGTH CONCAT CONCAT_WS ELT FIELD FIND_IN_SET FORMAT HEX INSTR LCASE
LEFT LENGTH LOCATE LOWER LPAD LTRIM OCT OCTET_LENGTH REPEAT REPLACE REVERSE
RIGHT RPAD RTRIM SPACE STRCMP SUBSTR SUBSTRING SUBSTRING_INDEX TRIM UCASE UNHEX
UPPER ADDDATE ADDTIME CONVERT_TZ CURDATE CURRENT_DATE CURRENT_TIME
CURRENT_TIMESTAMP CURTIME DATE DATEDIFF DATE_ADD DATE_FORMAT DATE_SUB DAY
DAYNAME DAYOFMONTH DAYOFWEEK DAYOFYEAR EXTRACT FROM_DAYS FROM_UNIXTIME HOUR
LAST_DAY MAKEDATE MAKETIME MICROSECOND MINUTE MONTH MONTHNAME NOW PERIOD_ADD
PERIOD_DIFF QUARTER SECOND SEC_TO_TIME STR_TO_DATE SUBDATE SUBTIME SYSDATE TIME
TIMEDIFF TIMESTAMP TIMESTAMPADD TIMESTAMPDIFF TIME_FORMAT TIME_TO_SEC TO_DAYS
TO_SECONDS UNIX_TIMESTAMP UTC_DATE UTC_TIME UTC_TIMESTAMP WEEK WEEKDAY
WEEKOFYEAR YEAR YEARWEEK JSON_ARRAY JSON_ARRAYAGG JSON_CONTAINS
JSON_CONTAINS_PATH JSON_DEPTH JSON_EXTRACT JSON_INSERT JSON_KEYS JSON_LENGTH
JSON_MERGE JSON_MERGE_PATCH JSON_MERGE_PRESERVE JSON_OBJECT JSON_OBJECTAGG
JSON_QUERY JSON_QUOTE JSON_REMOVE JSON_REPLACE JSON_SEARCH JSON_SET JSON_TYPE
JSON_UNQUOTE JSON_VALID JSON_VALUE JSON_COMPACT JSON_DETAILED JSON_EQUALS
JSON_EXISTS JSON_NORMALIZE JSON_PRETTY JSON_LOOSE JSON_OVERLAPS VALUES
ROW_NUMBER RANK DENSE_RANK LAG LEAD FIRST_VALUE LAST_VALUE NTH_VALUE NTILE
CUME_DIST PERCENT_RANK
```

## Write execution and results

An execute tool is one single-target INSERT, UPDATE, or DELETE statement, using a
`read_write` application and its dedicated account. Multi-statement batches,
REPLACE, DDL, account commands, CALL, arbitrary transactions supplied by a
caller, and DML RETURNING clauses are outside version 1. A single statement
may express an upsert; its update effects must be described and annotated.
UPDATE and DELETE require a WHERE predicate. This requirement and row bounds
supplement administrator review; a WHERE clause alone does not prove safety.

All directly modified tables must be explicitly granted for the operation and
use InnoDB. Validate this before serving the tool. Every call runs within a
transaction. Check the driver's changed/deleted/inserted affected-row count
against the inclusive minimum/maximum before COMMIT; otherwise ROLLBACK.
UPDATE does not request CLIENT_FOUND_ROWS. An unchanged matched row may count
as zero, and an upsert may count as two. Authors must account for those semantics.
Bounds cover directly affected rows, not hidden effects of triggers; triggers
and their transactional table dependencies require administrator review.
A rollback restores transactional row changes, not necessarily consumed
auto-increment values; gaps in generated IDs are possible.

There is no automatic retry of a write. An `idempotent` hint documents an
application/database guarantee, not a built-in deduplication service. Prefer a
business key with a uniqueness constraint or an expected-version predicate when
replays or concurrent edits matter. An explicit minimum of one supports
optimistic concurrency by treating zero changed rows as a failed precondition.

Only acknowledged COMMIT returns success. If the connection fails during
COMMIT, return `write_outcome_unknown`: it might have committed. The caller
must inspect the application state using a read tool and business key before
retrying. A lost HTTP response after successful COMMIT has the same retry risk.
Separate calls do not share transactions. Multi-step business transactions need
a future explicitly designed operation, not several calls assumed to be atomic.

A successful execute result follows this envelope:

```json
{
  "app_id": "inventory",
  "tool": "inventory__set_item_label",
  "kind": "execute",
  "affected_rows": 1,
  "last_insert_id": null,
  "commit": "committed"
}
```

`last_insert_id` is an exact base-10 string only when explicitly requested and
the INSERT reports a generated ID; otherwise it is null. The execute output
schema is fixed; execute tools do not declare `fields` or return arbitrary
result sets.

## OAuth scopes and MCP calls

Each application publishes `APP:read` when it has enabled query tools and
`APP:write` when it has enabled execute tools. The write scope is never
published for a read-only application. A token's write scope does not imply
read scope, and vice versa. Consent names the requested applications and read
or write access. After login, all enabled scopes are offered as checkboxes, with
only the authorization URL's scopes selected by default. Extra read and write
scopes require explicit selection; requested scopes can be unchecked. The token
response reports exactly the approved selection. At least one and at most 64
scopes can be approved. Adding an application or write scope never upgrades
existing persisted tokens.

An unauthenticated MCP request returns HTTP 401 with a `WWW-Authenticate`
challenge containing the protected-resource metadata URL and a sorted,
deduplicated `scope` hint for all enabled read apps. Disabled apps and disabled
tools contribute no scopes. Initial challenges omit write scopes; a service
with only execute tools omits the scope hint, and its client must explicitly
request a supported write scope. Both discovery documents continue advertising
all supported read and write scopes.

A call to an enabled tool without its required permission returns HTTP 403
before database dispatch. Its `WWW-Authenticate` challenge names that tool's
exact scope and includes `error="insufficient_scope"` and a fixed error
description. The JSON body remains `{"error":"insufficient_scope"}`. This does
not grant access or change a token. Clients decide when to reauthorize and
which additional scopes to request; permission expansion requires fresh consent.

After adding an app, restart to reload the JSON files, then reauthorize the client
using the advertised scopes. A client following the initial challenge can request
the enabled read apps without a manually maintained scope list. Refreshing tools
with an existing token still lists only its authorized tools. If ChatGPT retains
an earlier URL scope such as `tapo:read`, select the additional permissions on the
consent page; no authorization-URL edit is needed with the selectable-consent
build. The server does not silently add permissions. Clients receive the actual
selection in the OAuth token response's `scope` field. A tool-specific challenge
names only the required scope; retain previously granted scopes you still need
when approving a new grant. The list comes from applications loaded at service
startup; restart after changing app files. Multi-user roles are not implemented:
the authenticated owner can select all enabled scopes.

Tool listing exposes only tools authorized by the token's scopes; each call
checks its tool's required scope. OAuth consent is authorization for the scope,
not proof of a per-call client confirmation. MCP annotations describe effects;
they do not enforce database permissions or establish idempotency.

The generic dispatcher supports the standard MCP tool discovery/invocation
methods, `tools/list` and `tools/call`. Query tools advertise
`readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, and
`openWorldHint: false`. Execute tools advertise `readOnlyHint: false`, use
their configured destructive/idempotent hints, and use `openWorldHint: false`.
Application authors define input schemas and result fields; the agent derives
the MCP output schema and returns the envelope in structured content plus a
serialized text representation. See the
[MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

No additional MCP call family is needed for these database operations. Optional
[resources](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)
expose addressable context; optional
[prompts](https://modelcontextprotocol.io/specification/2025-11-25/server/prompts)
expose reusable prompt templates. Neither is required or configured by version 1.
Search, fetch-by-ID, lists, history, and aggregates can be named query tools.
INSERT, updates, and deletion can be named execute tools. Stored procedures,
scheduled polling, event subscriptions, external HTTP calls, scripts, and
application migrations are outside this format.

The selected published MCP SDK handles initialization, protocol negotiation,
transport sessions, and protocol errors. No application-specific JSON-RPC methods
are introduced. ChatGPT's exact write-tool interaction and approval behavior
require later client compatibility tests; none are claimed verified here.

## Validation, failures, and limits

Startup validation checks structural configuration, unique identities,
credential protection, effective grants, schema assertions, prepared SQL, and
result metadata without executing application query/DML statements. Metadata
checks may read information_schema and the configured migration column.
Only server startup serves tools; checking configuration never starts a listener
or grants access to a database.

Unknown tools and malformed protocol requests use protocol errors. Bad tool
inputs and database/business failures use an MCP tool result with
`isError: true` and a fixed error code/message. Codes include
`invalid_arguments`, `not_found`, `database_unavailable`, `query_timeout`,
`result_type_mismatch`, `result_too_large`, `statement_warning`,
`write_precondition_failed`, and
`write_outcome_unknown`. Authentication failures use OAuth HTTP challenges
or insufficient-scope responses before dispatch. Errors do not expose SQL,
driver messages, credentials, returned data, or unvalidated input text.

Database operations use UTC sessions, strict SQL mode, pools bounded to four
connections per application, and server-side statement timeouts. Discard failed
or timed-out connections and do not return them to a pool with a live transaction.
Bounds apply to preparation and metadata queries too. OAuth bodies and MCP
request bodies are capped at 16 KiB; encoded binary/JSON arguments share that
budget. Complete serialized MCP tool results are capped at 1 MiB. Input and decoded/parsed result
depth is capped at 32. Application files are capped at 1 MiB each.

Log application/tool identity, timing, error code, and write outcome rather than
credentials, tokens, SQL parameter values, or row contents. Config files are
trusted administrator input; client values and database rows remain validated
at conversion boundaries. Annotation values must not be used as access checks.

## Read-only application example

This minimal `apps.d/tapo.json` example uses the prepared Tapo MCP reader.
It demonstrates the format without including an actual device ID or password:

```json
{
  "version": 1,
  "app_id": "tapo",
  "description": "Stored Tapo environmental telemetry",
  "connection_file": "../connections/tapo.json",
  "database_user": "mcpagent",
  "access": "read_only",
  "grants": [
    {"table": "sensors", "privileges": ["SELECT"]},
    {"table": "measurements", "privileges": ["SELECT"]},
    {"table": "collector_status", "privileges": ["SELECT"]},
    {"table": "schema_migrations", "privileges": ["SELECT"]}
  ],
  "schema_checks": [
    {"table": "sensors", "columns": ["id", "name"]}
  ],
  "schema_version": {
    "table": "schema_migrations",
    "column": "version",
    "expected": 1
  },
  "tools": [
    {
      "name": "list_sensor_names",
      "description": "List stored sensor identifiers and display names",
      "kind": "query",
      "input_schema": {
        "type": "object",
        "properties": {},
        "additionalProperties": false
      },
      "sql": "SELECT id, name FROM sensors ORDER BY id LIMIT ?",
      "bindings": [
        {"source": "runtime", "name": "fetch_limit", "db_type": "integer"}
      ],
      "fields": [
        {"name": "id", "type": "string"},
        {"name": "name", "type": "string"}
      ],
      "max_rows": 1000,
      "default_limit": 100,
      "empty_result": "empty"
    }
  ]
}
```

The production Tapo application is intended to provide sensor listing, current
conditions, history, and collection health through the same generic dispatcher.
This illustrative tool is not an additional required production tool.

## Writable application example

This `apps.d/inventory.json` example reads mixed types and updates a label
using optimistic concurrency. It assumes an administrator-created InnoDB
`items` table with the listed fields and a unique `id`. The item ID uses
a string BIGINT representation, and prices retain exact decimal precision:

```json
{
  "version": 1,
  "app_id": "inventory",
  "description": "Inventory items and controlled label updates",
  "connection_file": "../connections/inventory.json",
  "database_user": "mcp_inventory",
  "access": "read_write",
  "grants": [
    {"table": "items", "privileges": ["SELECT", "UPDATE"]}
  ],
  "schema_checks": [
    {
      "table": "items",
      "columns": ["id", "label", "price", "attributes", "updated_at", "version"]
    }
  ],
  "tools": [
    {
      "name": "get_item",
      "description": "Read an item by ID with exact price and JSON attributes",
      "kind": "query",
      "input_schema": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string",
            "pattern": "^[1-9][0-9]{0,19}$",
            "maxLength": 20
          }
        },
        "required": ["id"],
        "additionalProperties": false
      },
      "sql": "SELECT id, label, price, attributes, updated_at, version FROM items WHERE id = ? ORDER BY id LIMIT ?",
      "bindings": [
        {"source": "argument", "name": "id", "db_type": "bigint"},
        {"source": "runtime", "name": "fetch_limit", "db_type": "integer"}
      ],
      "fields": [
        {"name": "id", "type": "bigint"},
        {"name": "label", "type": "string"},
        {"name": "price", "type": "decimal", "units": "USD"},
        {"name": "attributes", "type": "json", "nullable": true},
        {"name": "updated_at", "type": "timestamp"},
        {"name": "version", "type": "integer"}
      ],
      "max_rows": 1,
      "default_limit": 1,
      "empty_result": "not_found"
    },
    {
      "name": "set_item_label",
      "description": "Overwrite one item's label only if its version still matches; zero changed rows fails",
      "kind": "execute",
      "input_schema": {
        "type": "object",
        "properties": {
          "id": {
            "type": "string",
            "pattern": "^[1-9][0-9]{0,19}$",
            "maxLength": 20
          },
          "label": {"type": "string", "minLength": 1, "maxLength": 128},
          "expected_version": {
            "type": "integer",
            "minimum": 0,
            "maximum": 9007199254740990
          }
        },
        "required": ["id", "label", "expected_version"],
        "additionalProperties": false
      },
      "sql": "UPDATE items SET label = ?, version = version + 1, updated_at = ? WHERE id = ? AND version = ?",
      "bindings": [
        {"source": "argument", "name": "label", "db_type": "string"},
        {"source": "runtime", "name": "now_utc", "db_type": "timestamp"},
        {"source": "argument", "name": "id", "db_type": "bigint"},
        {"source": "argument", "name": "expected_version", "db_type": "integer"}
      ],
      "min_affected_rows": 1,
      "max_affected_rows": 1,
      "destructive": true,
      "idempotent": false
    }
  ]
}
```

Only the inventory account receives UPDATE; it has no INSERT or DELETE grant.
The timestamp field assumes `updated_at` stores UTC. The version predicate
prevents an identical successful update from applying a second time, but a
retry returns a failed precondition rather than the original success. The
example conservatively leaves the idempotency hint false.

## Verification coverage

The independent implementation verifies these behaviors with isolated
socket-only databases, loopback HTTP and the unchanged executable:

- Load two applications with distinct database users, fields, and tool sets
  using the unchanged executable; reject duplicate users and mismatched credentials.
- Verify the account's effective grants and that the Tapo reader cannot write.
- Validate every documented default/key and reject unsupported features.
- Round-trip each type, SQL NULL, JSON null, exact decimal/BIGINT boundaries,
  timezone offsets, durations, binary bytes, and nested JSON.
- Reject malformed inputs, ambiguous conversions, SQL injection attempts,
  multiple statements, ungranted targets, and unsupported operations.
- Verify deterministic query limits, truncation, type errors, no-data behavior,
  time-range constraints, timeouts, and socket outage errors.
- Require distinct read/write scopes and preserve existing grants across an
  application-config restart without expanding consent.
- Commit a permitted write and roll back failed row bounds/preconditions;
  test concurrent versioned updates and uncertain COMMIT outcomes.
- Preserve overwrite refusal and symlink boundaries for configuration/state
  paths with relative/absolute forms and trailing directory separators.

Examples are valid JSON and participate in configuration/database tests. Private
acceptance includes acknowledged writes, row-bound rollback, dropped COMMIT
replies and configuration-only app addition across a restart. Public ChatGPT
linking and external proxy behavior remain unverified deployment work.
