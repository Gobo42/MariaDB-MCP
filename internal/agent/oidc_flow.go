package agent

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

type oidcAttempt struct{ stateHash, nonce, verifier string }
type oidcCompletion struct {
	id, csrf string
	attempt  oidcAttempt
}

// authorize holds the pending-request mutex; no network call is made here.
func (a *oauthService) startOIDC(w http.ResponseWriter, r *http.Request, id string) {
	if a.oidc == nil {
		delete(a.pending, id)
		oauthError(w, 503, "temporarily_unavailable")
		return
	}
	values := make([]string, 3)
	for i := range values {
		v, err := randomSecret()
		if err != nil {
			delete(a.pending, id)
			oauthError(w, 503, "temporarily_unavailable")
			return
		}
		values[i] = v
	}
	state, nonce, verifier := values[0], values[1], values[2]
	a.pending[id].upstream = &oidcAttempt{digest(state), nonce, verifier}
	http.Redirect(w, r, a.oidc.authURL(state, nonce, verifier), 303)
}
func (a *oauthService) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if a.registry.Server.OAuth.Login.Method != "oidc" || a.oidc == nil {
		w.WriteHeader(404)
		return
	}
	q, ok := oidcCallbackValues(r)
	if !ok {
		oauthError(w, 400, "invalid_request")
		return
	}
	if !a.oidc.validResponseIssuer(q) {
		oauthError(w, 400, "invalid_request")
		return
	}
	completion := a.takeOIDCAttempt(r, q.Get("state"))
	if completion == nil {
		oauthError(w, 400, "invalid_request")
		return
	}
	if q.Has("error") {
		oauthError(w, 401, "invalid_login")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.oidc.exchange(ctx, q.Get("code"), completion.attempt.nonce, completion.attempt.verifier); err != nil {
		oauthError(w, 401, "invalid_login")
		return
	}
	a.showConsent(w, r, url.Values{"request_id": {completion.id}, "csrf": {completion.csrf}})
}
func oidcCallbackValues(r *http.Request) (url.Values, bool) {
	if r.Method != "GET" || len(r.URL.RawQuery) > 16384 {
		return nil, false
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !checkedValues(q, []string{"state"}, []string{"code", "error", "error_description", "error_uri", "iss", "session_state"}) {
		return nil, false
	}
	if q.Has("code") == q.Has("error") {
		return nil, false
	}
	if q.Has("code") && (q.Get("code") == "" || len(q.Get("code")) > 4096) {
		return nil, false
	}
	return q, true
}
func (a *oauthService) takeOIDCAttempt(r *http.Request, state string) *oidcCompletion {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now().UTC()
	a.prune(now)
	for id, p := range a.pending {
		if p.upstream == nil || !equal(p.upstream.stateHash, digest(state)) {
			continue
		}
		if p.authenticated || !a.matches(p, r, p.csrf, now) {
			return nil
		}
		completion := &oidcCompletion{id, p.csrf, *p.upstream}
		p.upstream = nil
		return completion
	}
	return nil
}
