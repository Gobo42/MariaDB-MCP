# Private fixtures

The SQL resets isolated test databases under the development-only /tmp MariaDB socket. Never load it into production.

tapo-app.json is a nonsecret contract snapshot for parser/config tests, copied from the Tapo project. Refresh it when the Tapo integration changes. The binary acceptance harness takes --tapo-app explicitly and verifies the external, source-owned definition.
