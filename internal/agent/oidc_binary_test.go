package agent

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func startOIDCBinary(t *testing.T, binary, config, ca, base string) func() {
	t.Helper()
	log, err := os.CreateTemp(t.TempDir(), "binary-log-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "serve", "--config", config)
	cmd.Env = append(os.Environ(), "SSL_CERT_FILE="+ca)
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cmd.Process.Signal(os.Interrupt)
			select {
			case err := <-done:
				if err != nil {
					t.Error("native service shutdown failed")
				}
			case <-time.After(12 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Error("native service did not exit")
			}
			log.Close()
		})
	}
	t.Cleanup(stop)
	for range 100 {
		response, err := http.Get(base + "/agent/health")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				return stop
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("native service startup failed")
	return stop
}
func nativeOIDCGrant(t *testing.T, c *http.Client, base string, p *testOIDCProvider) Tokens {
	t.Helper()
	verifier := strings.Repeat("v", 64)
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://127.0.0.1:9876/callback"}, "resource": {"https://example.invalid/agent/mcp"}, "scope": {"inventory:read"}, "state": {"native-state"}, "code_challenge": {digest(verifier)}, "code_challenge_method": {"S256"}}
	response, err := c.Get(base + "/agent/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	cookie := response.Cookies()[0]
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	post := func(path string, form url.Values) *http.Response {
		request, _ := http.NewRequest("POST", base+path, strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		result, err := c.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	if p == nil {
		if response.StatusCode != 200 {
			t.Fatal("password authorization failed")
		}
		response = post("/agent/oauth/login", url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "username": {"owner"}, "password": {"fixture-long-password"}})
	} else {
		if response.StatusCode != 303 {
			t.Fatal("OIDC authorization failed")
		}
		idp := *p.server.Client()
		idp.CheckRedirect = c.CheckRedirect
		response, err = idp.Get(response.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		callback, _ := url.Parse(response.Header.Get("Location"))
		request, _ := http.NewRequest("GET", base+callback.RequestURI(), nil)
		request.AddCookie(cookie)
		response, err = c.Do(request)
		if err != nil {
			t.Fatal(err)
		}
	}
	body, _ = io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("native consent missing", response.StatusCode)
	}
	response = post("/agent/oauth/consent", url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"approve"}, "scope_inventory:read": {"on"}})
	response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatal("native consent failed")
	}
	callback, _ := url.Parse(response.Header.Get("Location"))
	if callback.Query().Get("state") != "native-state" {
		t.Fatal("native downstream state lost")
	}
	response = post("/agent/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {"https://example.invalid/agent/mcp"}, "code": {callback.Query().Get("code")}, "redirect_uri": {q.Get("redirect_uri")}, "code_verifier": {verifier}})
	defer response.Body.Close()
	var tokens Tokens
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&tokens) != nil || tokens.Scope != "inventory:read" {
		t.Fatal("native token exchange failed")
	}
	return tokens
}
func nativeOIDCTools(t *testing.T, c *http.Client, base, token string) {
	t.Helper()
	body := bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	request, _ := http.NewRequest("POST", base+"/agent/mcp", body)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("MCP-Protocol-Version", "2025-11-25")
	response, err := c.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var value struct {
		Result struct {
			Tools []any `json:"tools"`
		}
	}
	if response.StatusCode != 200 || json.NewDecoder(response.Body).Decode(&value) != nil || len(value.Result.Tools) != 1 {
		t.Fatal("native MCP scope access failed")
	}
	lookup, _ := http.NewRequest("POST", base+"/agent/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inventory__get_item","arguments":{"id":"7"}}}`))
	lookup.Header = request.Header.Clone()
	result, err := c.Do(lookup)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	var row struct {
		Result struct {
			IsError    bool `json:"isError"`
			Structured struct {
				RowCount int `json:"row_count"`
			} `json:"structuredContent"`
		}
	}
	if result.StatusCode != 200 || json.NewDecoder(result.Body).Decode(&row) != nil || row.Result.IsError || row.Result.Structured.RowCount != 1 {
		t.Fatal("native authorized database read failed")
	}
}
func TestOIDCPackagedBinaryMigration(t *testing.T) {
	binary := os.Getenv("MARIADB_MCP_TEST_BINARY")
	if binary == "" {
		t.Skip("set MARIADB_MCP_TEST_BINARY to the packaged executable for native acceptance")
	}
	root, config := registryFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	base := "http://" + address
	var settings map[string]any
	if err = readJSON(config, &settings); err != nil {
		t.Fatal(err)
	}
	settings["listen"] = address
	privateJSON(t, config, settings)
	cmd := exec.Command(binary, "init-state", "--config", config)
	if err = cmd.Run(); err != nil {
		t.Fatal("native state initialization failed")
	}
	provider := newTestOIDCProvider(t)
	ca := filepath.Join(root, "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: provider.server.Certificate().Raw}), 0600)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	stop := startOIDCBinary(t, binary, config, ca, base)
	old := nativeOIDCGrant(t, client, base, nil)
	stop()
	statePath := filepath.Join(root, "state/oauth-state.json")
	before, _ := os.ReadFile(statePath)
	privateJSON(t, filepath.Join(root, "idp.json"), oidcCredentials{"upstream-client", "upstream-secret"})
	settings["oauth"] = map[string]any{"provider": "builtin", "credentials_file": settings["oauth_credentials_file"], "state_directory": settings["state_directory"], "redirect_uris": settings["redirect_uris"], "login": map[string]any{"method": "oidc", "issuer": provider.server.URL, "credentials_file": "idp.json", "allowed_subjects": []string{"owner-subject"}, "token_endpoint_auth_method": "client_secret_post"}}
	for _, key := range []string{"oauth_credentials_file", "state_directory", "redirect_uris"} {
		delete(settings, key)
	}
	privateJSON(t, config, settings)
	stop = startOIDCBinary(t, binary, config, ca, base)
	after, _ := os.ReadFile(statePath)
	if !bytes.Equal(before, after) {
		t.Fatal("mode migration reset token state")
	}
	nativeOIDCTools(t, client, base, old.AccessToken)
	fresh := nativeOIDCGrant(t, client, base, provider)
	nativeOIDCTools(t, client, base, fresh.AccessToken)
	response, err := client.PostForm(base+"/agent/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {"https://example.invalid/agent/mcp"}, "refresh_token": {old.RefreshToken}})
	if err != nil {
		t.Fatal(err)
	}
	var rotated Tokens
	err = json.NewDecoder(response.Body).Decode(&rotated)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || rotated.Scope != "inventory:read" {
		t.Fatal("old native grant refresh failed")
	}
	stop()
	stop = startOIDCBinary(t, binary, config, ca, base)
	nativeOIDCTools(t, client, base, rotated.AccessToken)
	stop()
	snapshot, _ := os.ReadFile(statePath)
	if bytes.Contains(snapshot, []byte("upstream-access")) || bytes.Contains(snapshot, []byte("upstream-refresh")) {
		t.Fatal("native upstream tokens persisted")
	}
	for _, token := range provider.tokens {
		if bytes.Contains(snapshot, []byte(token)) {
			t.Fatal("native ID token persisted")
		}
	}
}
