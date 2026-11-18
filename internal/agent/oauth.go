package agent

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

type pendingAuth struct {
	request          url.Values
	scopes           []string
	cookieHash, csrf string
	authenticated    bool
	expires          time.Time
}
type authCode struct {
	request url.Values
	scopes  []string
	expires time.Time
}
type oauthService struct {
	registry      *Registry
	identity      Identity
	scopes        map[string]bool
	store         *tokenStore
	mu            sync.Mutex
	pending       map[string]*pendingAuth
	codes         map[string]authCode
	attempts      []time.Time
	passwordSlots chan struct{}
}

func routeURL(r *Registry, parts ...string) string {
	u, _ := url.Parse(r.Server.PublicBaseURL)
	if u.Path == "" {
		u.Path = "/"
	}
	escaped := strings.TrimSuffix(u.EscapedPath(), "/")
	if len(parts) > 0 {
		for _, part := range parts {
			escaped += "/" + url.PathEscape(part)
		}
	}
	if escaped == "" {
		escaped = "/"
	}
	u.Path, _ = url.PathUnescape(escaped)
	u.RawPath = escaped
	return u.String()
}
func routePrefix(r *Registry) string {
	u, _ := url.Parse(routeURL(r))
	if u.Path == "/" {
		return ""
	}
	return u.Path
}
func identity(r *Registry) Identity {
	return Identity{r.Auth.Username, r.Auth.ClientID, routeURL(r, "mcp")}
}
func scope(a string, t *Tool) string {
	if t.Kind == "query" {
		return a + ":read"
	}
	return a + ":write"
}
func newOAuth(r *Registry, s *tokenStore) *oauthService {
	a := &oauthService{registry: r, identity: identity(r), scopes: map[string]bool{}, store: s, pending: map[string]*pendingAuth{}, codes: map[string]authCode{}, passwordSlots: make(chan struct{}, 2)}
	for _, app := range r.Apps {
		if app.Enabled {
			for _, t := range app.Tools {
				if t.Enabled {
					a.scopes[scope(app.ID, t)] = true
				}
			}
		}
	}
	return a
}
func (a *oauthService) scopeList() []string {
	s := []string{}
	for k := range a.scopes {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func oauthError(w http.ResponseWriter, status int, code string) {
	jsonReply(w, status, map[string]any{"error": code})
}
func securityHeaders(w http.ResponseWriter, formRedirect string) {
	formAction := "'self'"
	if formRedirect != "" {
		u, _ := url.Parse(formRedirect)
		formAction += " " + u.Scheme + "://" + u.Host
	}
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'none'; form-action "+formAction+"; frame-ancestors 'none'; base-uri 'none'")
	h.Set("Referrer-Policy", "strict-origin")
	h.Set("X-Content-Type-Options", "nosniff")
}
func (a *oauthService) validHeaders(r *http.Request) bool {
	host := r.Host
	if host == "" || strings.ContainsAny(host, "/@?#\\") {
		return false
	}
	u, e := url.Parse("http://" + host)
	if e != nil || u.Host != host || u.User != nil || u.Path != "" {
		return false
	}
	pub, _ := url.Parse(a.registry.Server.PublicBaseURL)
	ip := net.ParseIP(u.Hostname())
	listen, _, _ := net.SplitHostPort(a.registry.Server.Listen)
	private := ip != nil && (ip.IsLoopback() || ip.Equal(net.ParseIP(listen)))
	if host != pub.Host && !private {
		return false
	}
	if origins := r.Header.Values("Origin"); len(origins) > 0 {
		if len(origins) != 1 {
			return false
		}
		o, e := url.Parse(origins[0])
		if e != nil || o.User != nil || o.RawQuery != "" || o.Fragment != "" || (o.Path != "" && o.Path != "/") {
			return false
		}
		if !(o.Scheme == pub.Scheme && o.Host == pub.Host) && !(private && o.Scheme == "http" && o.Host == host) {
			return false
		}
	}
	return true
}
func (a *oauthService) prune(now time.Time) {
	for id, p := range a.pending {
		if !p.expires.After(now) {
			delete(a.pending, id)
		}
	}
	for id, c := range a.codes {
		if !c.expires.After(now) {
			delete(a.codes, id)
		}
	}
	i := 0
	for i < len(a.attempts) && !a.attempts[i].After(now.Add(-time.Minute)) {
		i++
	}
	a.attempts = append([]time.Time{}, a.attempts[i:]...)
}
func checkedValues(values url.Values, required, optional []string) bool {
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		allowed[k] = true
	}
	for k, v := range values {
		if !allowed[k] || len(v) != 1 {
			return false
		}
	}
	for _, k := range required {
		if _, ok := values[k]; !ok {
			return false
		}
	}
	return true
}
func formValues(w http.ResponseWriter, r *http.Request, required, optional []string) (url.Values, bool) {
	if r.Method != "POST" {
		w.WriteHeader(405)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") || r.ParseForm() != nil || r.URL.RawQuery != "" || !checkedValues(r.PostForm, required, optional) {
		oauthError(w, 400, "invalid_request")
		return nil, false
	}
	return r.PostForm, true
}
func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + html.EscapeString(title) + "</title></head><body><main><h1>" + html.EscapeString(title) + "</h1>" + body + "</main></body></html>"))
}
func hidden(id, csrf string) string {
	return "<input type=\"hidden\" name=\"request_id\" value=\"" + html.EscapeString(id) + "\"><input type=\"hidden\" name=\"csrf\" value=\"" + html.EscapeString(csrf) + "\">"
}
func (a *oauthService) matches(p *pendingAuth, r *http.Request, csrf string, now time.Time) bool {
	c, e := r.Cookie("mcp_login")
	return e == nil && p.expires.After(now) && equal(p.csrf, csrf) && equal(p.cookieHash, digest(c.Value))
}
func (a *oauthService) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" || len(r.URL.RawQuery) > 16384 {
		oauthError(w, 400, "invalid_request")
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || !checkedValues(q, []string{"response_type", "client_id", "redirect_uri", "resource", "scope", "state", "code_challenge", "code_challenge_method"}, []string{"ui_locales"}) {
		oauthError(w, 400, "invalid_request")
		return
	}
	allowedRedirect := false
	for _, uri := range a.registry.Server.OAuth.RedirectURIs {
		allowedRedirect = allowedRedirect || q.Get("redirect_uri") == uri
	}
	challenge, e := base64.RawURLEncoding.DecodeString(q.Get("code_challenge"))
	scopes := strings.Fields(q.Get("scope"))
	good := len(scopes) > 0 && len(scopes) <= 64
	set := map[string]bool{}
	for _, s := range scopes {
		good = good && a.scopes[s]
		set[s] = true
	}
	scopes = nil
	for s := range set {
		scopes = append(scopes, s)
	}
	sort.Strings(scopes)
	if !good || q.Get("response_type") != "code" || q.Get("client_id") != a.registry.Auth.ClientID || !allowedRedirect || q.Get("resource") != a.identity.Resource || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || e != nil || len(challenge) != 32 || len(q.Get("state")) > 1024 {
		oauthError(w, 400, "invalid_request")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	a.prune(now)
	if len(a.pending)+len(a.codes) >= 64 {
		oauthError(w, 429, "temporarily_unavailable")
		return
	}
	id, e := randomSecret()
	if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	csrf, e := randomSecret()
	if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	cookie, e := randomSecret()
	if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	pub, _ := url.Parse(a.registry.Server.PublicBaseURL)
	prefix := routePrefix(a.registry)
	http.SetCookie(w, &http.Cookie{Name: "mcp_login", Value: cookie, Path: prefix + "/oauth", HttpOnly: true, Secure: r.Host == pub.Host, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	a.pending[id] = &pendingAuth{q, scopes, digest(cookie), csrf, false, now.Add(5 * time.Minute)}
	page(w, "Sign in", "<p>Sign in to review the requested access.</p><form method=\"post\" action=\""+html.EscapeString(prefix+"/oauth/login")+"\">"+hidden(id, csrf)+"<p><label for=\"username\">Username</label><br><input id=\"username\" name=\"username\" autocomplete=\"username\" spellcheck=\"false\" autocorrect=\"off\" autocapitalize=\"none\" maxlength=\"128\" required></p><p><label for=\"current-password\">Password</label><br><input type=\"password\" id=\"current-password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"1024\" required></p><button type=\"submit\">Sign in</button></form>")
}
func (a *oauthService) login(w http.ResponseWriter, r *http.Request) {
	f, ok := formValues(w, r, []string{"request_id", "csrf", "username", "password"}, nil)
	if !ok {
		return
	}
	if !a.acceptLoginAttempt(w, r, f, time.Now().UTC()) {
		return
	}
	select {
	case a.passwordSlots <- struct{}{}:
	default:
		oauthError(w, 429, "temporarily_unavailable")
		return
	}
	valid := verifyPassword(a.registry.Auth.PasswordHash, f.Get("password"))
	<-a.passwordSlots
	if !valid || !equal(f.Get("username"), a.registry.Auth.Username) {
		oauthError(w, 401, "invalid_login")
		return
	}
	a.showConsent(w, r, f)
}

func (a *oauthService) acceptLoginAttempt(w http.ResponseWriter, r *http.Request, f url.Values, now time.Time) bool {
	a.mu.Lock()
	a.prune(now)
	p := a.pending[f.Get("request_id")]
	if p == nil || !a.matches(p, r, f.Get("csrf"), now) || p.authenticated || len(f.Get("password")) > 1024 || len(f.Get("username")) > 128 {
		a.mu.Unlock()
		oauthError(w, 400, "invalid_request")
		return false
	}
	if len(a.attempts) >= 10 {
		a.mu.Unlock()
		oauthError(w, 429, "temporarily_unavailable")
		return false
	}
	a.attempts = append(a.attempts, now)
	a.mu.Unlock()
	return true
}

func (a *oauthService) showConsent(w http.ResponseWriter, r *http.Request, f url.Values) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p := a.pending[f.Get("request_id")]
	if p == nil || !a.matches(p, r, f.Get("csrf"), time.Now().UTC()) || p.authenticated {
		oauthError(w, 400, "invalid_request")
		return
	}
	csrf, e := randomSecret()
	if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	p.authenticated = true
	p.csrf = csrf
	// Chromium also checks form-action when the consent POST redirects to the callback.
	securityHeaders(w, p.request.Get("redirect_uri"))
	page(w, "Approve access", "<p>Choose the access to grant. Scopes requested by the client are selected. Check any additional scopes you want to approve.</p><form method=\"post\" action=\""+html.EscapeString(routePrefix(a.registry)+"/oauth/consent")+"\">"+hidden(f.Get("request_id"), csrf)+"<fieldset><legend>Access scopes</legend>"+scopeChoices(a.scopeList(), p.scopes)+"</fieldset><button type=\"submit\" name=\"decision\" value=\"approve\">Approve access</button> <button type=\"submit\" name=\"decision\" value=\"deny\">Deny access</button></form>")
}
func (a *oauthService) consent(w http.ResponseWriter, r *http.Request) {
	var choices []string
	for _, s := range a.scopeList() {
		choices = append(choices, "scope_"+s)
	}
	f, ok := formValues(w, r, []string{"request_id", "csrf", "decision"}, choices)
	if !ok {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	a.prune(now)
	p := a.pending[f.Get("request_id")]
	if !a.validConsent(p, r, f, now) {
		oauthError(w, 400, "invalid_request")
		return
	}
	u, _ := url.Parse(p.request.Get("redirect_uri"))
	q := u.Query()
	if f.Get("decision") == "deny" {
		q.Add("error", "access_denied")
	} else {
		selected, ok := selectedConsentScopes(a.scopeList(), f)
		if !ok {
			oauthError(w, 400, "invalid_scope")
			return
		}
		code, e := randomSecret()
		if e != nil {
			oauthError(w, 503, "temporarily_unavailable")
			return
		}
		a.codes[digest(code)] = authCode{p.request, selected, now.Add(time.Minute)}
		q.Add("code", code)
	}
	delete(a.pending, f.Get("request_id"))
	q.Add("state", p.request.Get("state"))
	q.Add("iss", routeURL(a.registry))
	u.RawQuery = q.Encode()
	w.Header().Set("Location", u.String())
	w.WriteHeader(303)
}
func (a *oauthService) token(w http.ResponseWriter, r *http.Request) {
	f, ok := formValues(w, r, []string{"grant_type", "resource"}, []string{"client_id", "client_secret", "code", "redirect_uri", "code_verifier", "refresh_token", "scope"})
	if !ok {
		return
	}
	id, secret := f.Get("client_id"), f.Get("client_secret")
	if headers := r.Header.Values("Authorization"); len(headers) > 0 {
		if len(headers) != 1 || f.Has("client_id") || f.Has("client_secret") {
			oauthError(w, 400, "invalid_request")
			return
		}
		parts := strings.SplitN(headers[0], " ", 2)
		valid := len(parts) == 2 && strings.EqualFold(parts[0], "basic")
		if valid {
			b, e := base64.StdEncoding.DecodeString(parts[1])
			if e == nil {
				bits := strings.SplitN(string(b), ":", 2)
				if len(bits) == 2 {
					id, secret = bits[0], bits[1]
				} else {
					valid = false
				}
			} else {
				valid = false
			}
		}
		if !valid {
			oauthError(w, 401, "invalid_client")
			return
		}
	}
	if !equal(id, a.registry.Auth.ClientID) || !equal(secret, a.registry.Auth.ClientSecret) {
		oauthError(w, 401, "invalid_client")
		return
	}
	if f.Get("resource") != a.identity.Resource || f.Has("scope") {
		oauthError(w, 400, "invalid_request")
		return
	}
	var tok Tokens
	var e error
	now := time.Now().UTC()
	switch f.Get("grant_type") {
	case "authorization_code":
		verifier := f.Get("code_verifier")
		if f.Has("refresh_token") || !f.Has("code") || !f.Has("redirect_uri") || len(verifier) < 43 || len(verifier) > 128 {
			oauthError(w, 400, "invalid_request")
			return
		}
		for _, c := range verifier {
			if !(c >= 65 && c <= 90 || c >= 97 && c <= 122 || c >= 48 && c <= 57 || strings.ContainsRune("-._~", c)) {
				oauthError(w, 400, "invalid_request")
				return
			}
		}
		a.mu.Lock()
		a.prune(now)
		key := digest(f.Get("code"))
		c, ok := a.codes[key]
		if !ok || c.request.Get("redirect_uri") != f.Get("redirect_uri") || !equal(c.request.Get("code_challenge"), digest(verifier)) {
			a.mu.Unlock()
			oauthError(w, 400, "invalid_grant")
			return
		}
		tok, e = a.store.issue(c.scopes, now)
		if e == nil {
			delete(a.codes, key)
		}
		a.mu.Unlock()
	case "refresh_token":
		if !f.Has("refresh_token") || f.Has("code") || f.Has("redirect_uri") || f.Has("code_verifier") {
			oauthError(w, 400, "invalid_request")
			return
		}
		tok, e = a.store.rotate(f.Get("refresh_token"), now)
	default:
		oauthError(w, 400, "unsupported_grant_type")
		return
	}
	if e == errAuth {
		oauthError(w, 400, "invalid_grant")
	} else if e != nil {
		oauthError(w, 503, "temporarily_unavailable")
	} else {
		jsonReply(w, 200, tok)
	}
}
func (a *oauthService) routes(database *database) http.Handler {
	prefix := routePrefix(a.registry)
	var protected http.Handler
	if database != nil {
		protected = a.mcpHandler(database)
	}
	handlers := map[string]http.HandlerFunc{
		"/.well-known/oauth-authorization-server" + prefix: func(w http.ResponseWriter, r *http.Request) {
			jsonReply(w, 200, map[string]any{"issuer": routeURL(a.registry), "authorization_endpoint": routeURL(a.registry, "oauth", "authorize"), "token_endpoint": routeURL(a.registry, "oauth", "token"), "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"}, "scopes_supported": a.scopeList()})
		},
		"/.well-known/oauth-protected-resource" + prefix + "/mcp": func(w http.ResponseWriter, r *http.Request) {
			jsonReply(w, 200, map[string]any{"resource": a.identity.Resource, "authorization_servers": []string{routeURL(a.registry)}, "scopes_supported": a.scopeList(), "bearer_methods_supported": []string{"header"}})
		},
		prefix + "/oauth/authorize": a.authorize, prefix + "/oauth/login": a.login, prefix + "/oauth/consent": a.consent, prefix + "/oauth/token": a.token,
		prefix + "/health": func(w http.ResponseWriter, r *http.Request) { jsonReply(w, 200, map[string]string{"status": "ok"}) },
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w, "")
		if !a.validHeaders(r) {
			w.WriteHeader(403)
			return
		}
		if h, ok := handlers[r.URL.Path]; ok {
			if !strings.Contains(r.URL.Path, "/oauth/") && r.Method != "GET" {
				w.WriteHeader(405)
				return
			}
			h(w, r)
			return
		}
		if r.URL.Path == prefix+"/mcp" && database != nil {
			protected.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
	})
}
