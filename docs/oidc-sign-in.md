# Configure external OIDC sign-in

Use this guide to sign in through an OpenID Connect identity provider while
MariaDB MCP keeps its scopes, consent page, access tokens, and refresh tokens.
Configure and test the provider before activating this mode on an existing host.
The generic implementation uses the authorization-code flow; live ZeroAuthy
compatibility still requires testing against your installed release.

## How sign-in works

ChatGPT contacts MariaDB MCP first. MCP validates the request, then redirects your
browser to the configured IdP. After sign-in, the IdP redirects to MCP's callback.
MCP verifies the identity and shows its existing scope-selection page. After
approval, ChatGPT exchanges the MCP authorization code with MCP for local tokens.

The IdP receives only `openid`. It does not receive application scopes such as
`tapo:read` and needs no knowledge of apps.d. ChatGPT receives no upstream IdP
tokens. This is SP-initiated sign-in; unsolicited IdP-initiated callbacks are
rejected. Scopes in the original ChatGPT URL remain the only preselected scopes.

## Register the service at your IdP

1. Create a confidential OIDC web application with authorization-code flow and
   S256 PKCE support. Enable its standard `openid` permission.
2. Register the exact callback derived from the service's public_base_url followed
   by `/oauth/oidc/callback`. For `https://mcp.example.invalid`, the callback is
   `https://mcp.example.invalid/oauth/oidc/callback`. A configured base path is
   retained. This is MCP's callback, separate from ChatGPT's existing callback.
3. Record the exact HTTPS issuer and the permitted account's stable `sub` value.
   Use a tenant-specific issuer when your provider has multiple tenants.
4. Record the web application's client ID and secret in a protected file. Choose
   an advertised token endpoint authentication method: `client_secret_basic` or
   `client_secret_post`.

The provider must publish OIDC discovery with matching issuer, HTTPS authorization,
token and JWKS endpoints, code-flow support, and an asymmetric ID-token signing
algorithm. If it advertises PKCE methods, the list must include S256; MCP always
uses S256 even if that optional metadata field is absent. Missing token endpoint
authentication metadata defaults to client_secret_basic. Provider HTTP redirects
are not followed by the backend client. Outbound requests have ten-second timeouts
and a one-MiB response limit, and use normal TLS verification. If discovery
advertises authorization-response issuer support, the callback must include the
exact issuer; any supplied issuer must match.

## Configure the login method

Keep `oauth.provider` set to `builtin`. Add this `login` object inside `oauth`:

```json
{
  "method": "oidc",
  "issuer": "https://identity.example.invalid",
  "credentials_file": "oidc-login-credentials.json",
  "allowed_subjects": ["REPLACE_WITH_OWNER_SUBJECT"],
  "token_endpoint_auth_method": "client_secret_basic"
}
```

Replace the issuer and REPLACE_WITH_OWNER_SUBJECT with the exact values from your
provider. The allowlist matches case-sensitive `sub` values under that one trusted
issuer. All allowed identities act as the existing local owner; tenant membership,
email, display name, roles, and groups do not grant access or change scopes.
Between one and 64 distinct subjects are permitted.

Put only these fields in the separate IdP credentials file:

```json
{
  "client_id": "REPLACE_WITH_IDP_CLIENT_ID",
  "client_secret": "REPLACE_WITH_IDP_CLIENT_SECRET"
}
```

Replace both placeholder values. This registration is distinct from the existing
MCP client credentials used by ChatGPT. Keep the original MCP credentials file,
local owner, public URL, state directory, and callback allowlist unchanged.
Relative credential paths resolve beside mcp.json. Private files require mode
0600 in mode-0700 directories with service ownership; symlinks are rejected.
See the [complete OIDC config](../examples/mcp-oidc.example.json) and
[IdP credential template](../examples/oidc-login-credentials.example.json).

## Check and activate

1. Back up the executable, protected configuration, and OAuth state, then stop
   the MCP service. Existing state must not be initialized or reset.
2. Install a binary supporting OIDC login and update the protected login settings.
3. Run the configuration check as the service account:

   ```sh
   sudo -u mcpagent /usr/local/bin/mariadb-mcp check --config /etc/mariadb-mcp/mcp.json
   ```

4. Start the service after the check succeeds.
5. Connect through your MCP client. Confirm that sign-in starts at MCP, visits the
   IdP, returns to MCP's scope-selection page, and grants only selected scopes.

`check` and service startup require successful IdP discovery in OIDC mode.
A running service validates new logins through the IdP, while existing local token
usage and refresh remain independent of IdP reachability. The IdP callback uses
GET/query response mode so the existing SameSite=Lax login cookie is sent.

MCP verifies the ID-token signature, issuer, client audience/authorized party,
expiry, issued-at presence, nonce, and allowed subject. Upstream state, nonce and
PKCE are separate from ChatGPT's original values. Pending sign-ins expire after
five minutes, are browser-bound, single-use, and subject to the existing request
limit. Provider failures and denied sign-ins do not fall back to password login.
The password POST route is unavailable in OIDC mode. Provider tokens are discarded
after identity validation and are not written to the local token store.

## Preserve and recover existing access

Omitting `oauth.login`, or setting it to `{"method":"password"}`, preserves
password login. Changing between password and OIDC does not alter the persisted
MCP identity, grants, token lifetimes, or refresh rules. The existing MCP credential
file still contains its protected password hash for deliberate administrator
recovery; no password is accepted through HTTP while OIDC mode is selected.

To recover from a failed IdP setup, stop the service, restore password mode, check
configuration, and restart. Keep the same MCP credentials and state directory.
When rolling back to a binary predating OIDC support, remove oauth.login entirely.

Disabling an IdP account or signing out at the IdP does not immediately revoke
previously issued local MCP grants. They retain their existing expiry/refresh
behavior. Global SSO logout, immediate IdP-driven revocation, multi-user roles,
SAML, encrypted ID tokens, and provider-specific extensions are outside this
implementation. Keep ChatGPT's authentication setup pointed at MCP's own OAuth
metadata; upstream OIDC sign-in does not turn MCP into an OIDC identity provider.
