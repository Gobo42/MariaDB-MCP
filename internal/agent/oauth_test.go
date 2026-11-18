package agent

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

func authFixture(t *testing.T) (*oauthService, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	hash, e := newPasswordHash("fixture-password-long")
	if e != nil {
		t.Fatal(e)
	}
	r := &Registry{Server: Server{Listen: "127.0.0.1:8810", PublicBaseURL: "https://mcp.example.invalid/agent", RedirectURIs: []string{"http://127.0.0.1:9876/callback"}}, Auth: AuthConfig{"owner", hash, "client", "secret"}, Apps: []*App{{ID: "tapo", Enabled: true, Tools: []*Tool{{Kind: "query", Enabled: true}}}}}
	id := identity(r)
	if e = initStore(dir, id); e != nil {
		t.Fatal(e)
	}
	s, e := openStore(dir, id)
	if e != nil {
		t.Fatal(e)
	}
	a := newOAuth(r, s)
	server := httptest.NewServer(a.routes(nil))
	t.Cleanup(func() { server.Close(); s.close() })
	return a, server
}
func hiddenValue(t *testing.T, b []byte, n string) string {
	t.Helper()
	m := regexp.MustCompile("name=\"" + n + "\" value=\"([^\"]*)\"").FindSubmatch(b)
	if m == nil {
		t.Fatal("missing hidden", n)
	}
	return string(m[1])
}
func TestOAuthFlow(t *testing.T) {
	a, s := authFixture(t)
	a.registry.Server.RedirectURIs = append(a.registry.Server.RedirectURIs, "https://other.allowed.invalid/callback")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	v := strings.Repeat("a", 64)
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {a.registry.Server.RedirectURIs[0]}, "resource": {a.identity.Resource}, "scope": {"tapo:read"}, "state": {"opaque"}, "ui_locales": {"en-US"}, "code_challenge": {digest(v)}, "code_challenge_method": {"S256"}}
	resp, e := client.Get(s.URL + "/agent/oauth/authorize?" + q.Encode())
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	cookie := resp.Cookies()[0]
	formPolicy := resp.Header.Get("Referrer-Policy")
	id, csrf := hiddenValue(t, b, "request_id"), hiddenValue(t, b, "csrf")
	post := func(path string, values url.Values) *http.Response {
		req, _ := http.NewRequest("POST", s.URL+path, strings.NewReader(values.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if path == "/agent/oauth/login" || path == "/agent/oauth/consent" {
			origin := s.URL
			// Fetch makes no-referrer HTML form navigations send Origin: null.
			if formPolicy == "no-referrer" {
				origin = "null"
			}
			req.Header.Set("Origin", origin)
		}
		req.AddCookie(cookie)
		r, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		if strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
			formPolicy = r.Header.Get("Referrer-Policy")
		}
		return r
	}
	login := url.Values{"request_id": {id}, "csrf": {csrf}, "username": {"owner"}, "password": {"fixture-password-long"}}
	wrong := post("/agent/oauth/login", url.Values{"request_id": {id}, "csrf": {"wrong"}, "username": {"owner"}, "password": {"fixture-password-long"}})
	wrong.Body.Close()
	if wrong.StatusCode != 400 {
		t.Fatalf("CSRF rejection: got status %d, want 400", wrong.StatusCode)
	}
	resp = post("/agent/oauth/login", login)
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	policy := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(policy, "form-action 'self' http://127.0.0.1:9876;") || strings.Contains(policy, "other.allowed.invalid") {
		t.Fatal("consent policy does not allow only the selected callback origin")
	}
	resp = post("/agent/oauth/consent", url.Values{"request_id": {id}, "csrf": {hiddenValue(t, b, "csrf")}, "decision": {"approve"}, "scope_tapo:read": {"on"}})
	resp.Body.Close()
	if resp.StatusCode != 303 {
		t.Fatal(resp.StatusCode)
	}
	u, _ := url.Parse(resp.Header.Get("Location"))
	code := u.Query().Get("code")
	exchange := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {a.identity.Resource}, "code": {code}, "redirect_uri": {q.Get("redirect_uri")}, "code_verifier": {v}}
	resp = post("/agent/oauth/token", exchange)
	var tok Tokens
	json.NewDecoder(resp.Body).Decode(&tok)
	resp.Body.Close()
	if resp.StatusCode != 200 || tok.AccessToken == "" {
		t.Fatal("exchange failed")
	}
	if _, e = a.store.access(tok.AccessToken, time.Now()); e != nil {
		t.Fatal(e)
	}
	resp = post("/agent/oauth/token", exchange)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("code replay")
	}
}
func TestURLPreservesEscapedPrefix(t *testing.T) {
	r := &Registry{Server: Server{PublicBaseURL: "https://example.invalid/a%2Fb/"}}
	if got := routeURL(r, "mcp"); got != "https://example.invalid/a%2Fb/mcp" {
		t.Fatal(got)
	}
}
func TestOAuthRequestBoundaries(t *testing.T) {
	a, s := authFixture(t)
	base := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {a.registry.Server.RedirectURIs[0]}, "resource": {a.identity.Resource}, "scope": {"tapo:read"}, "state": {"opaque"}, "ui_locales": {"en-US"}, "code_challenge": {digest(strings.Repeat("a", 64))}, "code_challenge_method": {"S256"}}
	for _, c := range []struct{ key, value string }{{"code_challenge_method", "plain"}, {"resource", "https://other.invalid/mcp"}, {"scope", "tapo:write"}, {"redirect_uri", "https://other.invalid/cb"}, {"unknown", "x"}} {
		q := url.Values{}
		for k, v := range base {
			q[k] = append([]string{}, v...)
		}
		q.Set(c.key, c.value)
		r, e := http.Get(s.URL + "/agent/oauth/authorize?" + q.Encode())
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatal("binding accepted", c.key)
		}
	}
	for _, origin := range []string{"https://hostile.invalid", "null"} {
		req, _ := http.NewRequest("GET", s.URL+"/agent/health", nil)
		req.Header.Set("Origin", origin)
		r, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 403 {
			t.Fatal("untrusted origin accepted", origin)
		}
	}
	a.mu.Lock()
	for i := 0; i < 64; i++ {
		a.pending[fmt.Sprint(i)] = &pendingAuth{expires: time.Now().Add(time.Hour)}
	}
	a.mu.Unlock()
	r, e := http.Get(s.URL + "/agent/oauth/authorize?" + base.Encode())
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 429 {
		t.Fatal("capacity")
	}
}
func TestExpiredAuthorizationCode(t *testing.T) {
	a, s := authFixture(t)
	a.mu.Lock()
	a.codes[digest("expired")] = authCode{request: url.Values{"redirect_uri": {"http://127.0.0.1:9876/callback"}, "code_challenge": {digest(strings.Repeat("a", 64))}}, scopes: []string{"tapo:read"}, expires: time.Now().Add(-time.Second)}
	a.mu.Unlock()
	f := url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {a.identity.Resource}, "code": {"expired"}, "redirect_uri": {"http://127.0.0.1:9876/callback"}, "code_verifier": {strings.Repeat("a", 64)}}
	r, e := http.PostForm(s.URL+"/agent/oauth/token", f)
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("expired code accepted")
	}
	if len(a.codes) != 0 {
		t.Fatal("code not pruned")
	}
}

func TestOAuthUILocales(t *testing.T) {
	a, server := authFixture(t)
	for _, c := range []struct {
		name    string
		locales []string
		want    int
	}{
		{"english", []string{"en-US"}, http.StatusOK},
		{"language preferences", []string{"fr-CA fr en"}, http.StatusOK},
		{"unsupported locale", []string{"xx-ZZ"}, http.StatusOK},
		{"empty preference", []string{""}, http.StatusOK},
		{"duplicate parameter", []string{"en-US", "fr"}, http.StatusBadRequest},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {a.registry.Server.RedirectURIs[0]}, "resource": {a.identity.Resource}, "scope": {"tapo:read"}, "state": {"opaque"}, "code_challenge": {digest(strings.Repeat("a", 64))}, "code_challenge_method": {"S256"}, "ui_locales": c.locales}
			resp, err := http.Get(server.URL + "/agent/oauth/authorize?" + q.Encode())
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != c.want {
				t.Fatalf("got status %d, want %d", resp.StatusCode, c.want)
			}
			if c.want == http.StatusOK {
				hiddenValue(t, body, "request_id")
				hiddenValue(t, body, "csrf")
			}
		})
	}
}
