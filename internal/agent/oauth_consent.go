package agent

import (
	"html"
	"net/http"
	"net/url"
	"slices"
	"time"
)

func scopeChoices(available, requested []string) string {
	choices := ""
	for _, scope := range available {
		checked := ""
		if slices.Contains(requested, scope) {
			checked = " checked"
		}
		choices += "<p><label><input type=\"checkbox\" name=\"scope_" + html.EscapeString(scope) + "\" value=\"on\"" + checked + "> " + html.EscapeString(scope) + "</label></p>"
	}
	return choices
}

func selectedConsentScopes(available []string, form url.Values) ([]string, bool) {
	var selected []string
	for _, scope := range available {
		if form.Has("scope_" + scope) {
			if form.Get("scope_"+scope) != "on" {
				return nil, false
			}
			selected = append(selected, scope)
		}
	}
	return selected, len(selected) > 0 && len(selected) <= 64
}

func (a *oauthService) validConsent(p *pendingAuth, r *http.Request, form url.Values, now time.Time) bool {
	return p != nil && p.authenticated && a.matches(p, r, form.Get("csrf"), now) &&
		(form.Get("decision") == "approve" || form.Get("decision") == "deny")
}
