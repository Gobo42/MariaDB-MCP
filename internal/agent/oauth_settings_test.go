package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func nestedOAuthFixture(t *testing.T) (string, string, map[string]any) {
	t.Helper()
	root, file := registryFixture(t)
	var fields map[string]any
	if err := readJSON(file, &fields); err != nil {
		t.Fatal(err)
	}
	fields["oauth"] = map[string]any{"provider": "builtin", "credentials_file": fields["oauth_credentials_file"], "state_directory": fields["state_directory"], "redirect_uris": fields["redirect_uris"]}
	for _, key := range []string{"oauth_credentials_file", "state_directory", "redirect_uris"} {
		delete(fields, key)
	}
	return root, file, fields
}

func TestNestedOAuthMatchesLegacyConfiguration(t *testing.T) {
	_, file, fields := nestedOAuthFixture(t)
	legacy, err := loadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	privateJSON(t, file, fields)
	nested, err := loadRegistry(file)
	if err != nil {
		t.Fatalf("nested oauth configuration rejected: %v", err)
	}
	if !reflect.DeepEqual(nested.Server, legacy.Server) || nested.Auth != legacy.Auth || identity(nested) != identity(legacy) {
		t.Fatal("configuration migration changed effective settings or identity")
	}
}

func TestNestedOAuthConfigurationBoundaries(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{"null block", func(m map[string]any) { m["oauth"] = nil }},
		{"array block", func(m map[string]any) { m["oauth"] = []any{} }},
		{"empty block", func(m map[string]any) { m["oauth"] = map[string]any{} }},
		{"missing provider", func(m map[string]any) { delete(m["oauth"].(map[string]any), "provider") }},
		{"empty provider", func(m map[string]any) { m["oauth"].(map[string]any)["provider"] = "" }},
		{"external provider", func(m map[string]any) { m["oauth"].(map[string]any)["provider"] = "oidc" }},
		{"provider case", func(m map[string]any) { m["oauth"].(map[string]any)["provider"] = "BUILTIN" }},
		{"null provider", func(m map[string]any) { m["oauth"].(map[string]any)["provider"] = nil }},
		{"missing credentials", func(m map[string]any) { delete(m["oauth"].(map[string]any), "credentials_file") }},
		{"empty credentials", func(m map[string]any) { m["oauth"].(map[string]any)["credentials_file"] = "" }},
		{"null credentials", func(m map[string]any) { m["oauth"].(map[string]any)["credentials_file"] = nil }},
		{"credential directory suffix", func(m map[string]any) { m["oauth"].(map[string]any)["credentials_file"] = "oauth.json/" }},
		{"missing callbacks", func(m map[string]any) { delete(m["oauth"].(map[string]any), "redirect_uris") }},
		{"empty callbacks", func(m map[string]any) { m["oauth"].(map[string]any)["redirect_uris"] = []string{} }},
		{"null callbacks", func(m map[string]any) { m["oauth"].(map[string]any)["redirect_uris"] = nil }},
		{"null callback", func(m map[string]any) { m["oauth"].(map[string]any)["redirect_uris"] = []any{nil} }},
		{"insecure callback", func(m map[string]any) {
			m["oauth"].(map[string]any)["redirect_uris"] = []string{"http://example.invalid/callback"}
		}},
		{"duplicate callbacks", func(m map[string]any) {
			m["oauth"].(map[string]any)["redirect_uris"] = []string{"http://127.0.0.1:9876/callback", "http://127.0.0.1:9876/callback"}
		}},
		{"null state", func(m map[string]any) { m["oauth"].(map[string]any)["state_directory"] = nil }},
		{"empty state", func(m map[string]any) { m["oauth"].(map[string]any)["state_directory"] = "" }},
		{"unknown oauth field", func(m map[string]any) { m["oauth"].(map[string]any)["issuer"] = "https://other.invalid" }},
		{"unknown root field", func(m map[string]any) { m["oauth_provider"] = "builtin" }},
		{"mixed credentials", func(m map[string]any) { m["oauth_credentials_file"] = "oauth.json" }},
		{"mixed empty credentials", func(m map[string]any) { m["oauth_credentials_file"] = "" }},
		{"mixed null credentials", func(m map[string]any) { m["oauth_credentials_file"] = nil }},
		{"mixed state", func(m map[string]any) { m["state_directory"] = "state" }},
		{"mixed empty callbacks", func(m map[string]any) { m["redirect_uris"] = []string{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, file, fields := nestedOAuthFixture(t)
			tc.edit(fields)
			privateJSON(t, file, fields)
			if _, err := loadRegistry(file); err == nil {
				t.Fatal("invalid OAuth configuration accepted")
			}
		})
	}
}

func TestOAuthConfigurationMigrationPreservesState(t *testing.T) {
	_, file, fields := nestedOAuthFixture(t)
	legacy, err := loadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	if err = initStore(legacy.Server.OAuth.StateDirectory, identity(legacy)); err != nil {
		t.Fatal(err)
	}
	store, err := openStore(legacy.Server.OAuth.StateDirectory, identity(legacy))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tokens, err := store.issue([]string{"inventory:read"}, now)
	store.close()
	if err != nil {
		t.Fatal(err)
	}
	stateFile := filepath.Join(legacy.Server.OAuth.StateDirectory, "oauth-state.json")
	before, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	privateJSON(t, file, fields)
	nested, err := loadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	store, err = openStore(nested.Server.OAuth.StateDirectory, identity(nested))
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	after, err := os.ReadFile(stateFile)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("state changed during configuration migration")
	}
	grant, err := store.access(tokens.AccessToken, now)
	if err != nil || !reflect.DeepEqual(grant.Scopes, []string{"inventory:read"}) {
		t.Fatal("old access grant lost")
	}
	refreshed, err := store.rotate(tokens.RefreshToken, now)
	if err != nil || refreshed.Scope != "inventory:read" {
		t.Fatal("old refresh grant lost or widened")
	}
}

func TestOAuthStateDirectoryNormalization(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			for _, suffix := range []string{"", "/", "///"} {
				root, file, fields := nestedOAuthFixture(t)
				state := filepath.Join(root, "state")
				if existing {
					if err := os.Mkdir(state, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(state, "keep"), []byte("keep"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				value := "state"
				if absolute {
					value = state
				}
				fields["oauth"].(map[string]any)["state_directory"] = value + suffix
				privateJSON(t, file, fields)
				registry, err := loadRegistry(file)
				if err != nil || registry.Server.OAuth.StateDirectory != state {
					t.Fatalf("state normalization absolute=%v existing=%v suffix=%q: %v", absolute, existing, suffix, err)
				}
				if existing {
					b, err := os.ReadFile(filepath.Join(state, "keep"))
					if err != nil || string(b) != "keep" {
						t.Fatal("existing state changed")
					}
				} else if _, err := os.Stat(state); !os.IsNotExist(err) {
					t.Fatal("config load created state")
				}
			}
		}
	}
	root, file, fields := nestedOAuthFixture(t)
	real := filepath.Join(root, "actual")
	if err := os.Mkdir(real, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	fields["oauth"].(map[string]any)["state_directory"] = "link///"
	privateJSON(t, file, fields)
	if _, err := loadRegistry(file); err == nil {
		t.Fatal("symlinked state accepted")
	}
	fields["oauth"].(map[string]any)["state_directory"] = "/"
	privateJSON(t, file, fields)
	registry, err := loadRegistry(file)
	if err != nil || registry.Server.OAuth.StateDirectory != "/" {
		t.Fatal("root normalization changed")
	}
	if err := initStore(registry.Server.OAuth.StateDirectory, identity(registry)); err == nil {
		t.Fatal("nonprivate root state accepted")
	}
}

func TestOAuthDefaultStateDirectory(t *testing.T) {
	_, file, fields := nestedOAuthFixture(t)
	delete(fields["oauth"].(map[string]any), "state_directory")
	privateJSON(t, file, fields)
	nested, err := loadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	oauth := fields["oauth"].(map[string]any)
	delete(fields, "oauth")
	fields["oauth_credentials_file"] = oauth["credentials_file"]
	fields["redirect_uris"] = oauth["redirect_uris"]
	privateJSON(t, file, fields)
	legacy, err := loadRegistry(file)
	if err != nil {
		t.Fatal(err)
	}
	if nested.Server.OAuth.StateDirectory != "/var/lib/mariadb-mcp" || !reflect.DeepEqual(nested.Server, legacy.Server) {
		t.Fatal("state default changed")
	}
}

func TestOAuthRawConfigurationBoundaries(t *testing.T) {
	_, file, _ := nestedOAuthFixture(t)
	for _, raw := range []string{`null`, `[]`, `{`, `{"version":1,"version":1}`, `{"oauth":{"provider":"builtin","provider":"builtin"}}`} {
		if err := os.WriteFile(file, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadRegistry(file); err == nil {
			t.Fatalf("invalid JSON accepted: %s", raw)
		}
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRegistry(file); err == nil {
		t.Fatal("missing configuration accepted")
	}
}

func TestOAuthCallbackPolicyUnchanged(t *testing.T) {
	for _, tc := range []struct {
		uri   string
		valid bool
	}{
		{"https://client.example.invalid/callback", true},
		{"http://127.0.0.1:9876/callback", true},
		{"http://[::1]:9876/callback", true},
		{"http://example.invalid/callback", false},
		{"http://192.0.2.1/callback", false},
		{"https://owner@example.invalid/callback", false},
		{"https://example.invalid/callback#fragment", false},
		{"https:///callback", false},
		{"https://%/callback", false},
		{"javascript:alert(1)", false},
		{"http://localhost/callback", false},
	} {
		if validRedirectURI(tc.uri) != tc.valid {
			t.Errorf("callback policy changed for %q", tc.uri)
		}
	}
}
