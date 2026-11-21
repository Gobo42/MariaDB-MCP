package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOIDCLoginConfiguration(t *testing.T) {
	root, file, fields := nestedOAuthFixture(t)
	privateJSON(t, filepath.Join(root, "idp.json"), map[string]any{"client_id": "upstream-client", "client_secret": "upstream-secret"})
	fields["oauth"].(map[string]any)["login"] = map[string]any{"method": "oidc", "issuer": "https://identity.example.invalid", "credentials_file": "idp.json", "allowed_subjects": []string{"owner-subject"}, "token_endpoint_auth_method": "client_secret_basic"}
	privateJSON(t, file, fields)
	if _, err := loadRegistry(file); err != nil {
		t.Fatalf("standard OIDC configuration rejected: %v", err)
	}
}
func TestExplicitPasswordLoginConfiguration(t *testing.T) {
	_, file, fields := nestedOAuthFixture(t)
	fields["oauth"].(map[string]any)["login"] = map[string]any{"method": "password"}
	privateJSON(t, file, fields)
	if _, err := loadRegistry(file); err != nil {
		t.Fatal(err)
	}
}

func TestOIDCConfigurationBoundaries(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"null login", func(m map[string]any) { m["login"] = nil }},
		{"missing method", func(m map[string]any) { delete(m["login"].(map[string]any), "method") }},
		{"unknown method", func(m map[string]any) { m["login"].(map[string]any)["method"] = "saml" }},
		{"empty method", func(m map[string]any) { m["login"].(map[string]any)["method"] = "" }},
		{"password with oidc fields", func(m map[string]any) { m["login"].(map[string]any)["method"] = "password" }},
		{"http issuer", func(m map[string]any) { m["login"].(map[string]any)["issuer"] = "http://idp.invalid" }},
		{"query issuer", func(m map[string]any) { m["login"].(map[string]any)["issuer"] = "https://idp.invalid?" }},
		{"fragment issuer", func(m map[string]any) { m["login"].(map[string]any)["issuer"] = "https://idp.invalid/#x" }},
		{"userinfo issuer", func(m map[string]any) { m["login"].(map[string]any)["issuer"] = "https://user@idp.invalid" }},
		{"missing issuer", func(m map[string]any) { delete(m["login"].(map[string]any), "issuer") }},
		{"missing credentials", func(m map[string]any) { delete(m["login"].(map[string]any), "credentials_file") }},
		{"bad client auth", func(m map[string]any) { m["login"].(map[string]any)["token_endpoint_auth_method"] = "none" }},
		{"no subjects", func(m map[string]any) { m["login"].(map[string]any)["allowed_subjects"] = []string{} }},
		{"duplicate subjects", func(m map[string]any) { m["login"].(map[string]any)["allowed_subjects"] = []string{"owner", "owner"} }},
		{"blank subject", func(m map[string]any) { m["login"].(map[string]any)["allowed_subjects"] = []string{" owner "} }},
		{"long subject", func(m map[string]any) {
			m["login"].(map[string]any)["allowed_subjects"] = []string{strings.Repeat("x", 256)}
		}},
		{"too many subjects", func(m map[string]any) { m["login"].(map[string]any)["allowed_subjects"] = make([]string, 65) }},
		{"unknown field", func(m map[string]any) { m["login"].(map[string]any)["scopes"] = []string{"tapo:read"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, file, fields := nestedOAuthFixture(t)
			privateJSON(t, filepath.Join(root, "idp.json"), map[string]any{"client_id": "idp-client", "client_secret": "idp-secret"})
			oauth := fields["oauth"].(map[string]any)
			oauth["login"] = map[string]any{"method": "oidc", "issuer": "https://idp.invalid", "credentials_file": "idp.json", "allowed_subjects": []string{"owner"}, "token_endpoint_auth_method": "client_secret_post"}
			tc.edit(oauth)
			privateJSON(t, file, fields)
			if _, err := loadRegistry(file); err == nil {
				t.Fatal("invalid login config accepted")
			}
		})
	}
}
func TestOIDCCredentialProtection(t *testing.T) {
	root, file, fields := nestedOAuthFixture(t)
	path := filepath.Join(root, "idp.json")
	fields["oauth"].(map[string]any)["login"] = map[string]any{"method": "oidc", "issuer": "https://idp.invalid", "credentials_file": "idp.json", "allowed_subjects": []string{"owner"}, "token_endpoint_auth_method": "client_secret_basic"}
	privateJSON(t, file, fields)
	for _, data := range []map[string]any{{"client_id": "idp", "client_secret": ""}, {"client_id": "", "client_secret": "secret"}, {"client_id": "idp", "client_secret": "secret", "unknown": true}} {
		privateJSON(t, path, data)
		if _, err := loadRegistry(file); err == nil {
			t.Fatal("invalid IdP credentials accepted")
		}
	}
	privateJSON(t, path, map[string]any{"client_id": "idp", "client_secret": "secret"})
	os.Chmod(path, 0644)
	if _, err := loadRegistry(file); err == nil {
		t.Fatal("public credentials accepted")
	}
	os.Chmod(path, 0600)
	for _, suffix := range []string{"/", "///"} {
		fields["oauth"].(map[string]any)["login"].(map[string]any)["credentials_file"] = "idp.json" + suffix
		privateJSON(t, file, fields)
		if _, err := loadRegistry(file); err == nil {
			t.Fatal("file argument treated as directory")
		}
	}
	os.Symlink(path, filepath.Join(root, "idp-link.json"))
	fields["oauth"].(map[string]any)["login"].(map[string]any)["credentials_file"] = "idp-link.json"
	privateJSON(t, file, fields)
	if _, err := loadRegistry(file); err == nil {
		t.Fatal("symlink credential accepted")
	}
}

func TestOIDCPasswordRejectsEachUpstreamSetting(t *testing.T) {
	for _, field := range []struct {
		name  string
		value any
	}{
		{"issuer", "https://idp.invalid"}, {"credentials_file", "idp.json"},
		{"allowed_subjects", []string{"owner"}}, {"token_endpoint_auth_method", "client_secret_basic"},
	} {
		t.Run(field.name, func(t *testing.T) {
			_, file, config := nestedOAuthFixture(t)
			config["oauth"].(map[string]any)["login"] = map[string]any{"method": "password", field.name: field.value}
			privateJSON(t, file, config)
			if _, err := loadRegistry(file); err == nil {
				t.Fatal("password mode accepted upstream setting")
			}
		})
	}
}
func TestOIDCConfigurationMaximums(t *testing.T) {
	root, file, config := nestedOAuthFixture(t)
	privateJSON(t, filepath.Join(root, "idp.json"), map[string]any{"client_id": "upstream", "client_secret": "secret"})
	subjects := make([]string, 64)
	for i := range subjects {
		subjects[i] = fmt.Sprintf("owner-%d", i)
	}
	prefix := "https://idp.invalid/"
	login := map[string]any{"method": "oidc", "issuer": prefix + strings.Repeat("a", 2048-len(prefix)), "credentials_file": "idp.json", "allowed_subjects": subjects, "token_endpoint_auth_method": "client_secret_basic"}
	config["oauth"].(map[string]any)["login"] = login
	privateJSON(t, file, config)
	if _, err := loadRegistry(file); err != nil {
		t.Fatal("maximum supported issuer/subject count rejected", err)
	}
	login["allowed_subjects"] = append(subjects, "extra-owner")
	privateJSON(t, file, config)
	if _, err := loadRegistry(file); err == nil {
		t.Fatal("too many distinct subjects accepted")
	}
	login["allowed_subjects"] = subjects
	login["issuer"] = login["issuer"].(string) + "a"
	privateJSON(t, file, config)
	if _, err := loadRegistry(file); err == nil {
		t.Fatal("oversize issuer accepted")
	}
}
