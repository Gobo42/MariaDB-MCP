package agent

import (
	"net/url"
	"strings"
)

type LoginSettings struct {
	Method          string   `json:"method" required:"true"`
	Issuer          string   `json:"issuer,omitempty"`
	CredentialsFile string   `json:"credentials_file,omitempty"`
	AllowedSubjects []string `json:"allowed_subjects,omitempty"`
	TokenAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	credentials     oidcCredentials
}
type oidcCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func (l *LoginSettings) load(file string) error {
	if err := l.validate(); err != nil {
		return err
	}
	if l.Method != "oidc" {
		return nil
	}
	path, err := resolve(file, l.CredentialsFile, false)
	if err != nil {
		return err
	}
	if err = readJSON(path, &l.credentials); err != nil {
		return err
	}
	if !validText(l.credentials.ClientID, 1024) || !validText(l.credentials.ClientSecret, 4096) {
		return errConfig
	}
	l.CredentialsFile = path
	return nil
}
func (l LoginSettings) validate() error {
	switch l.Method {
	case "password":
		return l.validatePassword()
	case "oidc":
		return l.validateOIDC()
	default:
		return errConfig
	}
}
func (l LoginSettings) validatePassword() error {
	if l.Issuer != "" || l.CredentialsFile != "" || l.AllowedSubjects != nil || l.TokenAuthMethod != "" {
		return errConfig
	}
	return nil
}
func (l LoginSettings) validateOIDC() error {
	if !validOIDCIssuer(l.Issuer) || l.CredentialsFile == "" {
		return errConfig
	}
	if l.TokenAuthMethod != "client_secret_basic" && l.TokenAuthMethod != "client_secret_post" {
		return errConfig
	}
	return validateSubjects(l.AllowedSubjects)
}
func validateSubjects(subjects []string) error {
	if len(subjects) == 0 || len(subjects) > 64 {
		return errConfig
	}
	seen := map[string]bool{}
	for _, s := range subjects {
		if !validText(s, 255) || strings.TrimSpace(s) != s || seen[s] {
			return errConfig
		}
		seen[s] = true
	}
	return nil
}
func validOIDCIssuer(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && validOIDCEndpoint(raw) && u.RawQuery == "" && !u.ForceQuery
}
func validOIDCEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && len(raw) <= 2048
}
