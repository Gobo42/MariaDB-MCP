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
	"strconv"
	"strings"
	"testing"
	"time"
)

func consentFixture(t *testing.T, requested string) (*oauthService, *httptest.Server, []byte, func(string, url.Values) (*http.Response, []byte)) {
	t.Helper()
	a, _ := authFixture(t)
	a.registry.Apps = []*App{
		{ID: "tapo", Enabled: true, Tools: []*Tool{{Kind: "query", Enabled: true}}},
		{ID: "nest", Enabled: true, Tools: []*Tool{{Kind: "query", Enabled: true}}},
		{ID: "snmp", Enabled: true, Tools: []*Tool{{Kind: "query", Enabled: true}}},
		{ID: "writer", Enabled: true, Tools: []*Tool{{Kind: "execute", Enabled: true}}},
		{ID: "disabled", Enabled: false, Tools: []*Tool{{Kind: "query", Enabled: true}}},
		{ID: "hidden", Enabled: true, Tools: []*Tool{{Kind: "query", Enabled: false}}},
	}
	a = newOAuth(a.registry, a.store)
	server := httptest.NewServer(a.routes(nil))
	t.Cleanup(server.Close)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	q := url.Values{"response_type": {"code"}, "client_id": {"client"}, "redirect_uri": {a.registry.Server.RedirectURIs[0]}, "resource": {a.identity.Resource}, "scope": {requested}, "state": {"keep-state"}, "code_challenge": {digest(strings.Repeat("v", 64))}, "code_challenge_method": {"S256"}}
	response, err := client.Get(server.URL + "/agent/oauth/authorize?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 {
		t.Fatal("authorize failed", err)
	}
	cookie := response.Cookies()[0]
	post := func(path string, form url.Values) (*http.Response, []byte) {
		t.Helper()
		req, err := http.NewRequest("POST", server.URL+path, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", server.URL)
		req.AddCookie(cookie)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response, body
	}
	response, body = post("/agent/oauth/login", url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "username": {"owner"}, "password": {"fixture-password-long"}})
	if response.StatusCode != 200 {
		t.Fatal("login failed")
	}
	return a, server, body, post
}

func TestOAuthConsentListsAllScopesWithOnlyURLDefaults(t *testing.T) {
	for _, requested := range []string{"tapo:read", "tapo:read nest:read", "writer:write"} {
		t.Run(requested, func(t *testing.T) {
			_, _, body, _ := consentFixture(t, requested)
			tags := regexp.MustCompile(`<input[^>]*type="checkbox"[^>]*>`).FindAllString(string(body), -1)
			got := map[string]bool{}
			for _, tag := range tags {
				name := regexp.MustCompile(`name="scope_([^"]+)"`).FindStringSubmatch(tag)
				if len(name) != 2 {
					t.Fatal("checkbox lacks scope name")
				}
				got[name[1]] = regexp.MustCompile(`\schecked(?:[\s=>]|$)`).MatchString(tag)
			}
			want := map[string]bool{"nest:read": false, "snmp:read": false, "tapo:read": false, "writer:write": false}
			for _, scope := range strings.Fields(requested) {
				want[scope] = true
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("checkbox defaults: got %v, want %v", got, want)
			}
			if !strings.Contains(string(body), "<fieldset>") || !strings.Contains(string(body), "<legend>") {
				t.Fatal("scope choices lack an accessible group")
			}
		})
	}
}

func TestOAuthConsentGrantsOnlyExplicitSelections(t *testing.T) {
	for _, tc := range []struct {
		name     string
		selected []string
		want     string
	}{
		{"keep URL default", []string{"tapo:read"}, "tapo:read"},
		{"add read scopes", []string{"tapo:read", "snmp:read", "nest:read"}, "nest:read snmp:read tapo:read"},
		{"explicit write scope", []string{"tapo:read", "writer:write"}, "tapo:read writer:write"},
		{"deselect URL default", []string{"nest:read"}, "nest:read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, body, post := consentFixture(t, "tapo:read")
			old, err := a.store.issue([]string{"tapo:read"}, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"approve"}}
			for _, scope := range tc.selected {
				form.Set("scope_"+scope, "on")
			}
			response, _ := post("/agent/oauth/consent", form)
			if response.StatusCode != 303 {
				t.Fatalf("consent status %d", response.StatusCode)
			}
			callback, err := url.Parse(response.Header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if callback.Query().Get("state") != "keep-state" || callback.Query().Get("iss") != "https://mcp.example.invalid/agent" {
				t.Fatal("callback binding changed")
			}
			response, body = post("/agent/oauth/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"client"}, "client_secret": {"secret"}, "resource": {a.identity.Resource}, "code": {callback.Query().Get("code")}, "redirect_uri": {a.registry.Server.RedirectURIs[0]}, "code_verifier": {strings.Repeat("v", 64)}})
			var token Tokens
			if json.Unmarshal(body, &token) != nil || response.StatusCode != 200 || token.Scope != tc.want {
				t.Fatalf("token scopes: status=%d got=%q want=%q", response.StatusCode, token.Scope, tc.want)
			}
			refreshed, err := a.store.rotate(token.RefreshToken, time.Now())
			if err != nil || refreshed.Scope != tc.want {
				t.Fatal("refresh changed selected scopes", err)
			}
			previous, err := a.store.rotate(old.RefreshToken, time.Now())
			if err != nil || previous.Scope != "tapo:read" {
				t.Fatal("existing grant expanded", err)
			}
			a.store.close()
			a.store, err = openStore(a.store.dir, a.identity)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { a.store.close() })
			grant, err := a.store.access(refreshed.AccessToken, time.Now())
			if err != nil || !reflect.DeepEqual(grant.Scopes, strings.Fields(tc.want)) {
				t.Fatal("selection did not survive restart", err)
			}
		})
	}
}

func TestOAuthConsentRejectsInvalidSelectionsWithoutGrant(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields url.Values
	}{
		{"empty", url.Values{}},
		{"unknown", url.Values{"scope_unknown:read": {"on"}}},
		{"disabled app", url.Values{"scope_disabled:read": {"on"}}},
		{"disabled tool", url.Values{"scope_hidden:read": {"on"}}},
		{"duplicate choice", url.Values{"scope_tapo:read": {"on", "on"}}},
		{"invalid value", url.Values{"scope_tapo:read": {"off"}}},
		{"invalid CSRF", url.Values{"scope_tapo:read": {"on"}, "csrf": {"wrong"}}},
		{"unknown request", url.Values{"scope_tapo:read": {"on"}, "request_id": {"unknown"}}},
		{"invalid decision", url.Values{"scope_tapo:read": {"on"}, "decision": {"later"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, body, post := consentFixture(t, "tapo:read")
			path := filepath.Join(a.store.dir, "oauth-state.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			form := url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"approve"}}
			for key, values := range tc.fields {
				form[key] = values
			}
			response, _ := post("/agent/oauth/consent", form)
			if response.StatusCode != 400 {
				t.Fatalf("invalid selection got status %d", response.StatusCode)
			}
			if len(a.codes) != 0 {
				t.Fatal("invalid selection issued a code")
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != string(before) {
				t.Fatal("invalid selection changed stored grants", err)
			}
		})
	}
}

func TestOAuthConsentDenyDoesNotGrantSelectedScopes(t *testing.T) {
	a, _, body, post := consentFixture(t, "tapo:read")
	response, _ := post("/agent/oauth/consent", url.Values{"request_id": {hiddenValue(t, body, "request_id")}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"deny"}, "scope_writer:write": {"on"}})
	callback, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != 303 || callback.Query().Get("error") != "access_denied" || callback.Query().Has("code") || len(a.codes) != 0 {
		t.Fatal("denial granted access")
	}
}

func TestConsentSelectionScopeLimit(t *testing.T) {
	available := make([]string, 65)
	form := url.Values{}
	for i := range available {
		available[i] = "app" + strconv.Itoa(i) + ":read"
		form.Set("scope_"+available[i], "on")
	}
	if _, ok := selectedConsentScopes(available, form); ok {
		t.Fatal("approved more than 64 scopes")
	}
	form.Del("scope_" + available[64])
	selected, ok := selectedConsentScopes(available, form)
	if !ok || len(selected) != 64 {
		t.Fatal("64 selected scopes should be accepted")
	}
}

func TestOAuthConsentRequiresLoginAndBoundCookie(t *testing.T) {
	for _, loggedIn := range []bool{false, true} {
		a, server, body, _ := consentFixture(t, "tapo:read")
		id := hiddenValue(t, body, "request_id")
		if !loggedIn {
			a.pending[id].authenticated = false
		}
		form := url.Values{"request_id": {id}, "csrf": {hiddenValue(t, body, "csrf")}, "decision": {"approve"}, "scope_tapo:read": {"on"}}
		request, err := http.NewRequest("POST", server.URL+"/agent/oauth/consent", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.Header.Set("Origin", server.URL)
		if !loggedIn {
			// Keep the original cookie so this case specifically checks the login gate.
			for _, pending := range a.pending {
				pending.cookieHash = digest("fixture-cookie")
			}
			request.AddCookie(&http.Cookie{Name: "mcp_login", Value: "fixture-cookie"})
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 400 || len(a.codes) != 0 {
			t.Fatal("unbound or unauthenticated approval accepted")
		}
	}
}
