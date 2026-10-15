package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONBoundary(t *testing.T) {
	for _, s := range []string{`{"a":1,"a":2}`, `{"a":{"x":1,"x":2}}`, `{"$serde_json::private::Number":"1"}`, `{"x":1} {}`} {
		if _, e := parseJSON([]byte(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
	v, e := parseJSON([]byte(`{"x":900719925474099312345,"y":0.12345678901234567890}`))
	if e != nil || v.(map[string]any)["x"].(json.Number).String() != "900719925474099312345" {
		t.Fatal(v, e)
	}
}
func TestPrivatePaths(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	for _, p := range []string{root, root + "/", root + "///"} {
		if _, e := privateDir(p); e != nil {
			t.Fatal(e)
		}
	}
	cwd, _ := os.Getwd()
	defer os.Chdir(cwd)
	os.Chdir(root)
	for _, p := range []string{"new", "new/", "new///", filepath.Join(root, "new") + "///"} {
		n, e := normalizeDir(p)
		if e != nil || n != filepath.Join(root, "new") {
			t.Fatal(n, e)
		}
	}
	os.Symlink(root, filepath.Join(root, "link"))
	if _, e := normalizeDir(root + "/link/../new"); e == nil {
		t.Fatal("symlink traversal")
	}
	if e := createPrivate(filepath.Join(root, "file"), []byte(`{}`)); e != nil {
		t.Fatal(e)
	}
	if e := createPrivate(filepath.Join(root, "file"), nil); e == nil {
		t.Fatal("overwrite")
	}
	if _, e := readPrivate(filepath.Join(root, "file")+"/", 1024); e == nil {
		t.Fatal("file separator")
	}
	os.Chmod(filepath.Join(root, "file"), 0644)
	if _, e := readPrivate(filepath.Join(root, "file"), 1024); e == nil {
		t.Fatal("public file")
	}
}
func TestNumbersBoundSchemaWork(t *testing.T) {
	for _, s := range []string{`{"n":1e100000000}`, `{"n":1e-100000000}`} {
		if _, e := parseJSON([]byte(s)); e == nil {
			t.Fatal("unbounded exponent accepted")
		}
	}
}
func TestTypedNullRejection(t *testing.T) {
	var a App
	if e := decode([]byte(`{"enabled":null}`), &a); e == nil {
		t.Fatal("null boolean accepted")
	}
	var v SchemaVersion
	if e := decode([]byte(`{"table":"migrations","column":"version"}`), &v); e == nil {
		t.Fatal("missing version expected accepted")
	}
}
func TestEscapedSurrogates(t *testing.T) {
	for _, raw := range []string{`{"x":"\ud800"}`, `{"x":"\udc00"}`, `{"x":"\ud800\u1234"}`} {
		if _, e := parseJSON([]byte(raw)); e == nil {
			t.Fatal("invalid surrogate accepted")
		}
	}
	if _, e := parseJSON([]byte(`{"x":"\ud83d\ude00","literal":"\\ud800"}`)); e != nil {
		t.Fatal(e)
	}
}
