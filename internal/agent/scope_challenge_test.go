package agent

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func scopeChallengeFixture(t *testing.T) (*oauthService, *httptest.Server) {
	t.Helper()
	a, _ := authFixture(t)
	tapo := inventoryApp(t)
	tapo.ID = "tapo"
	nest := *tapo
	nest.ID = "nest"
	nest.Tools = tapo.Tools[:1]
	disabled := *tapo
	disabled.ID = "disabled"
	disabled.Enabled = false
	writeOnly := *tapo
	writeOnly.ID = "writer"
	writeOnly.Tools = tapo.Tools[1:]
	disabledTool := *tapo.Tools[0]
	disabledTool.Enabled = false
	writeOnly.Tools = append([]*Tool{&disabledTool}, writeOnly.Tools...)
	a.registry.Apps = []*App{tapo, &nest, &disabled, &writeOnly}
	a = newOAuth(a.registry, a.store)
	server := httptest.NewServer(a.routes(&database{}))
	t.Cleanup(server.Close)
	return a, server
}

func scopeRPC(t *testing.T, server *httptest.Server, token, body string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("POST", server.URL+"/agent/mcp", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-11-25")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return resp, result
}

func TestMCPReadScopeChallenge(t *testing.T) {
	a, server := scopeChallengeFixture(t)
	before, err := os.ReadFile(filepath.Join(a.store.dir, "oauth-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "invalid-token"} {
		resp, _ := scopeRPC(t, server, token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status %d", resp.StatusCode)
		}
		want := `Bearer resource_metadata="https://mcp.example.invalid/.well-known/oauth-protected-resource/agent/mcp", scope="nest:read tapo:read"`
		if got := resp.Header.Get("WWW-Authenticate"); got != want {
			t.Errorf("challenge: got %q, want %q", got, want)
		}
	}
	after, err := os.ReadFile(filepath.Join(a.store.dir, "oauth-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("discovery altered persisted grants")
	}
}

func TestMCPWriteOnlyChallengeDoesNotRequestWriteByDefault(t *testing.T) {
	a, _ := scopeChallengeFixture(t)
	a.scopes = map[string]bool{"writer:write": true}
	recorder := httptest.NewRecorder()
	a.challenge(recorder)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatal(recorder.Code)
	}
	if strings.Contains(recorder.Header().Get("WWW-Authenticate"), "scope=") {
		t.Fatal("initial challenge requests write access")
	}
}

func TestMCPInsufficientScopeChallenge(t *testing.T) {
	a, server := scopeChallengeFixture(t)
	token, err := a.store.issue([]string{"tapo:read"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, scope string }{
		{"nest__get_item", "nest:read"},
		{"tapo__set_item_label", "tapo:write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + tc.name + `","arguments":{}}}`
			resp, result := scopeRPC(t, server, token.AccessToken, body)
			if resp.StatusCode != http.StatusForbidden || result["error"] != "insufficient_scope" {
				t.Fatal("call was not refused before database dispatch")
			}
			want := `Bearer resource_metadata="https://mcp.example.invalid/.well-known/oauth-protected-resource/agent/mcp", scope="` + tc.scope + `", error="insufficient_scope", error_description="Additional authorization required"`
			if got := resp.Header.Get("WWW-Authenticate"); got != want {
				t.Errorf("challenge: got %q, want %q", got, want)
			}
		})
	}
	resp, result := scopeRPC(t, server, token.AccessToken, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	listed := result["result"].(map[string]any)["tools"].([]any)
	if len(listed) != 1 || listed[0].(map[string]any)["name"] != "tapo__get_item" {
		t.Fatal("existing grant changed tool visibility")
	}
	refreshed, err := a.store.rotate(token.RefreshToken, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.Scope != "tapo:read" {
		t.Fatal("refresh widened existing grant")
	}
}

func TestOAuthScopesFromMCPChallenge(t *testing.T) {
	a, server := scopeChallengeFixture(t)
	resp, _ := scopeRPC(t, server, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	matches := regexp.MustCompile(`(?:^|, )scope="([^"]+)"`).FindStringSubmatch(resp.Header.Get("WWW-Authenticate"))
	if len(matches) != 2 {
		t.Fatal("MCP response does not guide requested scopes")
	}
	wantScope := "nest:read tapo:read"
	if matches[1] != wantScope {
		t.Fatal("unexpected scope guidance")
	}
	verifier := strings.Repeat("v", 64)
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {a.registry.Server.OAuth.RedirectURIs[0]}, "resource": {a.identity.Resource}, "scope": {matches[1]}, "state": {"opaque-state"}, "code_challenge": {digest(verifier)}, "code_challenge_method": {"S256"}}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(server.URL + "/agent/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatal("authorization failed", err)
	}
	cookie := resp.Cookies()[0]
	requestID := hiddenValue(t, body, "request_id")
	post := func(path string, values url.Values) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest("POST", server.URL+path, strings.NewReader(values.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", server.URL)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, b
	}
	resp, body = post("/agent/oauth/login", url.Values{"request_id": {requestID}, "csrf": {hiddenValue(t, body, "csrf")}, "username": {"owner"}, "password": {"fixture-password-long"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatal("login failed")
	}
	for _, s := range []string{"nest:read", "tapo:read"} {
		if !strings.Contains(string(body), `name="scope_`+s+`" value="on" checked`) {
			t.Fatal("requested read scope is not selected")
		}
	}
	if strings.Contains(string(body), `name="scope_tapo:write" value="on" checked`) || strings.Contains(string(body), `name="scope_writer:write" value="on" checked`) {
		t.Fatal("additional write scope was selected by default")
	}
	resp, _ = post("/agent/oauth/consent", url.Values{"request_id": {requestID}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"approve"}, "scope_nest:read": {"on"}, "scope_tapo:read": {"on"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatal("consent failed")
	}
	callback, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") != "opaque-state" {
		t.Fatal("callback state changed")
	}
	resp, body = post("/agent/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {a.identity.Resource}, "code": {callback.Query().Get("code")}, "redirect_uri": {q.Get("redirect_uri")}, "code_verifier": {verifier}})
	var token Tokens
	if err := json.Unmarshal(body, &token); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || token.Scope != wantScope {
		t.Fatal("combined scope token exchange failed")
	}
	refreshed, err := a.store.rotate(token.RefreshToken, time.Now())
	if err != nil || refreshed.Scope != wantScope {
		t.Fatal("combined scope refresh failed", err)
	}
	a.store.close()
	a.store, err = openStore(a.store.dir, a.identity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.store.close() })
	grant, err := a.store.access(refreshed.AccessToken, time.Now())
	if err != nil || !reflect.DeepEqual(grant.Scopes, strings.Fields(wantScope)) {
		t.Fatal("combined grant did not survive reopening", err)
	}
	resp, result := scopeRPC(t, server, refreshed.AccessToken, `{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.StatusCode)
	}
	listed := result["result"].(map[string]any)["tools"].([]any)
	if len(listed) != 2 {
		t.Fatal("combined grant cannot discover both apps")
	}
	names := map[string]bool{}
	for _, tool := range listed {
		names[tool.(map[string]any)["name"].(string)] = true
	}
	if !names["nest__get_item"] || !names["tapo__get_item"] {
		t.Fatal("combined discovery returned unexpected tools")
	}
}
