package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func privateJSON(t *testing.T, p string, v any) {
	t.Helper()
	if e := os.WriteFile(p, jsonBytes(v), 0600); e != nil {
		t.Fatal(e)
	}
}
func registryFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	for _, d := range []string{"apps.d", "connections", "credentials"} {
		if e := os.Mkdir(filepath.Join(root, d), 0700); e != nil {
			t.Fatal(e)
		}
	}
	hash, e := newPasswordHash("fixture-long-password")
	if e != nil {
		t.Fatal(e)
	}
	privateJSON(t, filepath.Join(root, "oauth.json"), AuthConfig{"owner", hash, "client", "secret"})
	app := inventoryApp(t)
	privateJSON(t, filepath.Join(root, "apps.d/inventory.json"), app)
	privateJSON(t, filepath.Join(root, "connections/inventory.json"), Connection{Socket: "/tmp/mcp-mariadb-data/test.sock", Database: "inventory", CredentialsFile: "../credentials/inventory.json"})
	privateJSON(t, filepath.Join(root, "credentials/inventory.json"), Credentials{"mcp_inventory", "fixture-only-password"})
	file := filepath.Join(root, "mcp.json")
	privateJSON(t, file, map[string]any{"version": 1, "public_base_url": "https://example.invalid/agent", "apps_directory": "apps.d///", "oauth_credentials_file": "oauth.json", "state_directory": "state///", "redirect_uris": []string{"http://127.0.0.1:9876/callback"}})
	return root, file
}
func TestRegistryBoundaries(t *testing.T) {
	root, file := registryFixture(t)
	r, e := loadRegistry(file)
	if e != nil {
		t.Fatal(e)
	}
	if r.Server.AppsDirectory != filepath.Join(root, "apps.d") || r.Server.OAuth.StateDirectory != filepath.Join(root, "state") {
		t.Fatal("path normalization")
	}
	b, e := os.ReadFile(filepath.Join(root, "apps.d/inventory.json"))
	if e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(root, "apps.d/duplicate.json"), b, 0600)
	if _, e = loadRegistry(file); e == nil {
		t.Fatal("shared identities")
	}
	os.Remove(filepath.Join(root, "apps.d/duplicate.json"))
	var m map[string]any
	json.Unmarshal(b, &m)
	m["unsupported"] = "value"
	privateJSON(t, filepath.Join(root, "apps.d/inventory.json"), m)
	if _, e = loadRegistry(file); e == nil {
		t.Fatal("unknown key")
	}
	os.WriteFile(filepath.Join(root, "apps.d/inventory.json"), b, 0600)
	os.Symlink(filepath.Join(root, "apps.d/inventory.json"), filepath.Join(root, "apps.d/link.json"))
	if _, e = loadRegistry(file); e == nil {
		t.Fatal("symlink app")
	}
	os.Remove(filepath.Join(root, "apps.d/link.json"))
}
func TestDirectoryRegressionMatrix(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(root)
	for i, relative := range []bool{true, false} {
		for j, suffix := range []string{"", "/", "///"} {
			name := string(rune(97+i)) + string(rune(97+j))
			p := name + suffix
			if !relative {
				p = root + "/" + p
			}
			dir, e := ensureDir(p)
			if e != nil {
				t.Fatal(e)
			}
			file := filepath.Join(dir, "keep")
			if e = createPrivate(file, []byte("keep")); e != nil {
				t.Fatal(e)
			}
			if _, e = ensureDir(p); e != nil {
				t.Fatal(e)
			}
			b, e := readPrivate(file, 10)
			if e != nil || string(b) != "keep" {
				t.Fatal("existing content changed")
			}
		}
	}
	if p, e := normalizeDir("/"); e != nil || p != "/" {
		t.Fatal("root trimmed")
	}
}
func TestFIFOAndJSONDepth(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	fifo := filepath.Join(root, "fifo")
	if e := syscall.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	if _, e := readPrivate(fifo, 1024); e == nil || time.Since(start) > time.Second {
		t.Fatal("FIFO blocked")
	}
	raw := strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33)
	if _, e := parseJSON([]byte(raw)); e == nil {
		t.Fatal("depth")
	}
}
func TestNestedTypedNullAndRequired(t *testing.T) {
	for _, raw := range []string{`{"version":1,"schema_version":{"table":"schema_migrations","column":"version"}}`, `{"tools":[{"name":"tool","description":"test","kind":"query","sql":"SELECT 1","input_schema":{},"bindings":[{"source":"argument","name":"x","db_type":"string","nullable":null}]}]}`} {
		var app App
		if e := decode([]byte(raw), &app); e == nil {
			t.Fatal("nested typed null/required accepted")
		}
	}
}
func TestNullToolRefusedBeforeValidation(t *testing.T) {
	var a App
	if e := decode([]byte(`{"tools":[null]}`), &a); e == nil {
		t.Fatal("null tool accepted")
	}
}
