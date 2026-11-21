package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOIDCSPInitiatedConsent(t *testing.T) {
	p := newTestOIDCProvider(t)
	a, server := authFixture(t)
	a.registry.Server.OAuth.Login = p.registry("client_secret_basic").Server.OAuth.Login
	upstream, err := newOIDCLogin(context.Background(), a.registry, p.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	a.oidc = upstream
	a.scopes["inventory:read"] = true
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://127.0.0.1:9876/callback"}, "resource": {a.identity.Resource}, "scope": {"tapo:read"}, "state": {"chatgpt-state"}, "code_challenge": {digest(strings.Repeat("v", 64))}, "code_challenge_method": {"S256"}}
	response, err := client.Get(server.URL + "/agent/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatal("SP authorization did not redirect to IdP", response.StatusCode)
	}
	cookies := response.Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing login binding")
	}
	upstreamURL, _ := url.Parse(response.Header.Get("Location"))
	if upstreamURL.Query().Get("scope") != "openid" || upstreamURL.Query().Get("state") == q.Get("state") || upstreamURL.Query().Get("code_challenge") == q.Get("code_challenge") {
		t.Fatal("upstream/downstream authorization mixed")
	}
	if upstreamURL.Query().Get("nonce") == "" || upstreamURL.Query().Get("nonce") == upstreamURL.Query().Get("state") {
		t.Fatal("state and nonce are not independent")
	}
	idpClient := *p.server.Client()
	idpClient.CheckRedirect = client.CheckRedirect
	response, err = idpClient.Get(upstreamURL.String())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	callback, _ := url.Parse(response.Header.Get("Location"))
	request, _ := http.NewRequest("GET", server.URL+callback.RequestURI(), nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatal("unbound callback accepted")
	}
	request, _ = http.NewRequest("POST", server.URL+"/agent/oauth/login", strings.NewReader(""))
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("password login exposed in OIDC mode")
	}
	request, _ = http.NewRequest("GET", server.URL+callback.RequestURI(), nil)
	request.AddCookie(cookies[0])
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(string(body), "scope_inventory:read") || !strings.Contains(string(body), `scope_tapo:read" value="on" checked`) {
		t.Fatal("OIDC did not return to local consent", response.StatusCode)
	}
	repeat, _ := http.NewRequest("GET", server.URL+callback.RequestURI(), nil)
	repeat.AddCookie(cookies[0])
	response, err = client.Do(repeat)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 400 {
		t.Fatal("callback replay accepted")
	}
	consent := url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"approve"}, "scope_tapo:read": {"on"}, "scope_inventory:read": {"on"}}
	request, _ = http.NewRequest("POST", server.URL+"/agent/oauth/consent", strings.NewReader(consent.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookies[0])
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatal("local consent failed")
	}
	localCallback, _ := url.Parse(response.Header.Get("Location"))
	if localCallback.Query().Get("state") != "chatgpt-state" {
		t.Fatal("downstream state lost")
	}
	tokenForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {a.identity.Resource}, "code": {localCallback.Query().Get("code")}, "redirect_uri": {q.Get("redirect_uri")}, "code_verifier": {strings.Repeat("v", 64)}}
	response, err = client.PostForm(server.URL+"/agent/oauth/token", tokenForm)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("local token exchange failed")
	}
	var token Tokens
	if err = json.NewDecoder(response.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	if token.Scope != "inventory:read tapo:read" {
		t.Fatal("IdP affected local scope selection")
	}
	state, err := os.ReadFile(filepath.Join(a.store.dir, "oauth-state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "upstream-access") || strings.Contains(string(state), "upstream-refresh") {
		t.Fatal("upstream token persisted")
	}
	for _, raw := range p.tokens {
		if strings.Contains(string(state), raw) {
			t.Fatal("ID token persisted")
		}
	}
}

func beginOIDCTest(t *testing.T) (*oauthService, *testOIDCProvider, *http.Client, string, *http.Cookie, *url.URL) {
	t.Helper()
	p := newTestOIDCProvider(t)
	a, server := authFixture(t)
	a.registry.Server.OAuth.Login = p.registry("client_secret_post").Server.OAuth.Login
	login, err := newOIDCLogin(context.Background(), a.registry, p.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	a.oidc = login
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://127.0.0.1:9876/callback"}, "resource": {a.identity.Resource}, "scope": {"tapo:read"}, "state": {"downstream"}, "code_challenge": {digest(strings.Repeat("v", 64))}, "code_challenge_method": {"S256"}}
	response, err := client.Get(server.URL + "/agent/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatal("OIDC redirect missing")
	}
	cookie := response.Cookies()[0]
	idpClient := *p.server.Client()
	idpClient.CheckRedirect = client.CheckRedirect
	response, err = idpClient.Get(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return a, p, client, server.URL, cookie, callback
}
func TestOIDCCallbackBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		change func(*oauthService, *testOIDCProvider, *url.URL)
		method string
		status int
	}{
		{"missing issuer", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Del("iss")
			u.RawQuery = q.Encode()
		}, "GET", 400},
		{"wrong state", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Set("state", "wrong")
			u.RawQuery = q.Encode()
		}, "GET", 400},
		{"wrong issuer", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Set("iss", "https://wrong.invalid")
			u.RawQuery = q.Encode()
		}, "GET", 400},
		{"duplicate state", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) { u.RawQuery += "&state=duplicate" }, "GET", 400},
		{"unknown field", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			u.RawQuery += "&redirect_uri=https://wrong.invalid"
		}, "GET", 400},
		{"code and error", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) { u.RawQuery += "&error=access_denied" }, "GET", 400},
		{"missing result", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Del("code")
			u.RawQuery = q.Encode()
		}, "GET", 400},
		{"empty code", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Set("code", "")
			u.RawQuery = q.Encode()
		}, "GET", 400},
		{"long code", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Set("code", strings.Repeat("x", 4097))
			u.RawQuery = q.Encode()
		}, "GET", 400},
		{"post response", func(_ *oauthService, _ *testOIDCProvider, _ *url.URL) {}, "POST", 400},
		{"expired request", func(a *oauthService, _ *testOIDCProvider, _ *url.URL) {
			a.mu.Lock()
			for _, p := range a.pending {
				p.expires = time.Now().Add(-time.Second)
			}
			a.mu.Unlock()
		}, "GET", 400},
		{"provider denial", func(_ *oauthService, _ *testOIDCProvider, u *url.URL) {
			q := u.Query()
			q.Del("code")
			q.Set("error", "access_denied")
			q.Set("error_description", "private-upstream-detail")
			u.RawQuery = q.Encode()
		}, "GET", 401},
		{"token endpoint failure", func(_ *oauthService, p *testOIDCProvider, _ *url.URL) {
			p.mu.Lock()
			p.tokenError = true
			p.mu.Unlock()
		}, "GET", 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, p, c, base, cookie, callback := beginOIDCTest(t)
			tc.change(a, p, callback)
			request, _ := http.NewRequest(tc.method, base+callback.RequestURI(), nil)
			request.AddCookie(cookie)
			response, err := c.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if response.StatusCode != tc.status || strings.Contains(string(body), "private-upstream-detail") {
				t.Fatal("invalid callback handling", response.StatusCode)
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.codes) != 0 {
				t.Fatal("failed login issued MCP code")
			}
			for _, pending := range a.pending {
				if pending.authenticated {
					t.Fatal("failed login authenticated owner")
				}
			}
		})
	}
}
func TestOIDCCallbackConsumedConcurrently(t *testing.T) {
	_, _, c, base, cookie, callback := beginOIDCTest(t)
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, _ := http.NewRequest("GET", base+callback.RequestURI(), nil)
			request.AddCookie(cookie)
			response, err := c.Do(request)
			if err != nil {
				statuses <- 0
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		}()
	}
	wg.Wait()
	close(statuses)
	counts := map[int]int{}
	for status := range statuses {
		counts[status]++
	}
	if counts[200] != 1 || counts[400] != 1 {
		t.Fatal("callback was not single use", counts)
	}
}
func TestOIDCProviderOutageKeepsLocalRefresh(t *testing.T) {
	a, p, c, base, _, _ := beginOIDCTest(t)
	tokens, err := a.store.issue([]string{"tapo:read"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	p.server.Close()
	response, err := c.PostForm(base+"/agent/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {a.identity.Resource}, "refresh_token": {tokens.RefreshToken}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("IdP outage broke local refresh")
	}
	var fresh Tokens
	json.NewDecoder(response.Body).Decode(&fresh)
	if fresh.Scope != "tapo:read" {
		t.Fatal("refresh widened during outage")
	}
}

func TestOIDCResponseIssuerPolicy(t *testing.T) {
	l := &oidcLogin{settings: LoginSettings{Issuer: "https://idp.invalid"}}
	if !l.validResponseIssuer(url.Values{}) {
		t.Fatal("optional issuer was required")
	}
	l.requireResponseIssuer = true
	if l.validResponseIssuer(url.Values{}) {
		t.Fatal("advertised issuer requirement ignored")
	}
	if !l.validResponseIssuer(url.Values{"iss": {"https://idp.invalid"}}) || l.validResponseIssuer(url.Values{"iss": {"https://wrong.invalid"}}) {
		t.Fatal("issuer match policy failed")
	}
}
func TestOIDCUnavailableAndInactiveRoutes(t *testing.T) {
	a, server := authFixture(t)
	response, err := http.Get(server.URL + "/agent/oauth/oidc/callback?state=x&code=x")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("OIDC callback active in password mode")
	}
	a.registry.Server.OAuth.Login.Method = "oidc"
	response, err = http.Get(server.URL + "/agent/oauth/oidc/callback?state=x&code=x")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("callback active without initialized provider")
	}
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {"http://127.0.0.1:9876/callback"}, "resource": {a.identity.Resource}, "scope": {"tapo:read"}, "state": {"downstream"}, "code_challenge": {digest(strings.Repeat("v", 64))}, "code_challenge_method": {"S256"}}
	response, err = http.Get(server.URL + "/agent/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 503 {
		t.Fatal("unavailable OIDC fell back to login")
	}
}
func TestOIDCCallbackQueryLimits(t *testing.T) {
	for _, raw := range []string{"state=%", "code=x", "state=x&code=x&code=y", "state=x&code=x&error=denied", "state=x", "state=x&code=", strings.Repeat("x", 16385)} {
		r, _ := http.NewRequest("GET", "https://mcp.example.invalid/callback", nil)
		r.URL.RawQuery = raw
		if _, ok := oidcCallbackValues(r); ok {
			t.Fatal("bad query accepted")
		}
	}
}

func TestOIDCCallbackMaximums(t *testing.T) {
	q := url.Values{"state": {"bound-state"}, "code": {strings.Repeat("c", 4096)}}
	check := func(ok bool) {
		t.Helper()
		request := httptest.NewRequest("GET", "/oauth/oidc/callback?"+q.Encode(), nil)
		if _, got := oidcCallbackValues(request); got != ok {
			t.Fatal("callback maximum policy changed", len(request.URL.RawQuery))
		}
	}
	check(true)
	q.Set("error_description", strings.Repeat("d", 16384-len(q.Encode())-len("&error_description=")))
	if len(q.Encode()) != 16384 {
		t.Fatal("invalid boundary fixture")
	}
	check(true)
	q.Set("error_description", q.Get("error_description")+"d")
	check(false)
}
