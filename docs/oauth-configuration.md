# Configure OAuth

Use this reference to configure MariaDB MCP authentication or migrate an existing
configuration. Keep passwords, password hashes, and client secrets in the separate
protected credentials file.

## Server configuration

Put the OAuth settings in `mcp.json`:

```json
{
  "version": 1,
  "listen": "127.0.0.1:8810",
  "public_base_url": "https://mcp.example.invalid",
  "apps_directory": "apps.d",
  "oauth": {
    "provider": "builtin",
    "credentials_file": "oauth-credentials.json",
    "state_directory": "/var/lib/mariadb-mcp",
    "redirect_uris": ["http://127.0.0.1:9876/callback"]
  }
}
```

Replace the public URL with your HTTPS service URL and the callback with the exact
URI supplied by your MCP client. The loopback callback is a test example. See the
[complete example configuration](../examples/mcp.example.json).

| Setting | Requirement and behavior |
| --- | --- |
| `oauth.provider` | Required. Only `builtin` is supported. Other values are rejected at startup. |
| `oauth.credentials_file` | Required. Path to the existing protected OAuth credentials JSON. Relative paths resolve from the directory containing `mcp.json`. |
| `oauth.state_directory` | Optional. Defaults to `/var/lib/mariadb-mcp`. Relative paths resolve from the directory containing `mcp.json`; directory separators are normalized. |
| `oauth.redirect_uris` | Required, nonempty list of distinct exact callback URLs. HTTPS is accepted; HTTP requires a literal loopback IP. |

`public_base_url` remains a server setting. For the built-in provider, it determines
the OAuth issuer, authorization and token endpoints, and the `/mcp` resource URL.
OAuth scopes continue to come from enabled apps and tools.

The built-in provider retains password login, PKCE, selectable consent, refresh,
and durable token state. Access-token and token-family lifetimes are unchanged.
The provider setting establishes an explicit configuration boundary; selecting an
external OAuth system also requires implementing support for that provider.
Adding an issuer URL or choosing `oidc` does not enable an external provider.

## Preserve credentials and token state

The credentials file retains `username`, `password_hash`, `client_id`, and
`client_secret`. Use mode 0600 for protected files and mode 0700 for their parent
directories. Keep the same service ownership. See the
[deployment guide](../deploy/README.md#prepare-files-and-verify) for credential
creation and directory permissions.

Configuration loading does not initialize, move, replace, or erase token state.
The service uses the existing state directory and its exclusive process lock.
Changing the owner, client ID, public resource URL, or state path is a separate
identity/state migration.

## Migrate a flat version-1 configuration

Existing version-1 files with root-level `oauth_credentials_file`,
`state_directory`, and `redirect_uris` remain supported. Their effective provider
is `builtin`. A file must use either the legacy fields or the nested block; mixing
them is rejected even when the legacy values are empty or null. Unknown fields,
duplicate JSON keys, typed nulls, and unsupported providers are rejected.

To adopt the nested form:

1. Install a binary that supports the `oauth` block before changing configuration.
2. Stop the MCP service and back up its protected configuration and token state.
3. Move `oauth_credentials_file` to `oauth.credentials_file`,
   `state_directory` to `oauth.state_directory`, and `redirect_uris` to
   `oauth.redirect_uris`. Add `oauth.provider` with value `builtin` and remove the
   three legacy root-level keys.
4. Keep the same credential file, state path, public URL, and callback values.
   If `state_directory` was omitted, keep it omitted or use its existing default.
5. Run the configuration check as the service account:

   ```sh
   sudo -u mcpagent /usr/local/bin/mariadb-mcp check --config /etc/mariadb-mcp/mcp.json
   ```

6. Start the MCP service after the check succeeds.

Do not regenerate credentials or run `init-state` for this migration. Existing
grants and refresh tokens keep their permissions and expiry when the identity
and state path remain the same. For rollback to an older binary, restore the
legacy configuration shape; older binaries do not accept the nested block.
