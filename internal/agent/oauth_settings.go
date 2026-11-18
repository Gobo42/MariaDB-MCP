package agent

import (
	"net"
	"net/url"
)

// OAuthSettings describes the selected authorization provider without storing secrets.
type OAuthSettings struct {
	Provider        string   `json:"provider" required:"true"`
	CredentialsFile string   `json:"credentials_file" required:"true"`
	StateDirectory  string   `json:"state_directory"`
	RedirectURIs    []string `json:"redirect_uris" required:"true"`
}

func readServer(file string, server *Server) error {
	var fields map[string]any
	if err := readJSON(file, &fields); err != nil {
		return err
	}
	if err := groupOAuthFields(fields); err != nil {
		return err
	}
	return decode(jsonBytes(fields), server)
}

func groupOAuthFields(fields map[string]any) error {
	if fields == nil {
		return errConfig
	}
	legacy := map[string]string{"oauth_credentials_file": "credentials_file", "state_directory": "state_directory", "redirect_uris": "redirect_uris"}
	_, nested := fields["oauth"]
	oauth := map[string]any{"provider": "builtin"}
	for old, current := range legacy {
		if value, present := fields[old]; present {
			if nested {
				return errConfig
			}
			oauth[current] = value
			delete(fields, old)
		}
	}
	if !nested {
		fields["oauth"] = oauth
	}
	return nil
}

func (o OAuthSettings) validate() error {
	if o.Provider != "builtin" || o.CredentialsFile == "" || o.StateDirectory == "" || len(o.RedirectURIs) == 0 {
		return errConfig
	}
	seen := map[string]bool{}
	for _, raw := range o.RedirectURIs {
		if seen[raw] || !validRedirectURI(raw) {
			return errConfig
		}
		seen[raw] = true
	}
	return nil
}

func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" || u.Fragment != "" {
		return false
	}
	ip := net.ParseIP(u.Hostname())
	return u.Scheme == "https" || u.Scheme == "http" && ip != nil && ip.IsLoopback()
}
