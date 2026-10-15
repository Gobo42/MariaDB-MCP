package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenPersistence(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	id := Identity{"owner", "client", "https://example.invalid/mcp"}
	now := time.Now().UTC()
	if e := initStore(dir+"///", id); e != nil {
		t.Fatal(e)
	}
	if e := initStore(dir, id); e == nil {
		t.Fatal("overwritten")
	}
	s, e := openStore(dir, id)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = openStore(dir, id); e == nil {
		t.Fatal("second writer")
	}
	tok, e := s.issue([]string{"tapo:read"}, now)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "oauth-state.json"))
	if strings.Contains(string(b), tok.AccessToken) || strings.Contains(string(b), tok.RefreshToken) {
		t.Fatal("raw token on disk")
	}
	s.close()
	s, e = openStore(dir, id)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	if _, e = s.access(tok.AccessToken, now); e != nil {
		t.Fatal(e)
	}
	newer, e := s.rotate(tok.RefreshToken, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.rotate(tok.RefreshToken, now); e == nil {
		t.Fatal("replay")
	}
	if _, e = s.access(newer.AccessToken, now); e == nil {
		t.Fatal("family not revoked")
	}
	s.close()
	if _, e = openStore(dir, Identity{"other", "client", id.Resource}); e == nil {
		t.Fatal("identity rebound")
	}
}
func TestStoreFailures(t *testing.T) {
	for _, stage := range []string{"write", "sync", "rename", "directory_sync"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			os.Chmod(dir, 0700)
			id := Identity{"owner", "client", "https://example.invalid/mcp"}
			if e := initStore(dir, id); e != nil {
				t.Fatal(e)
			}
			s, e := openStore(dir, id)
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC()
			tok, e := s.issue([]string{"tapo:read"}, now)
			if e != nil {
				t.Fatal(e)
			}
			switch stage {
			case "write":
				s.io.write = func(*os.File, []byte) error { return errPersistence }
			case "sync":
				s.io.sync = func(*os.File) error { return errPersistence }
			case "rename":
				s.io.rename = func(string, string) error { return errPersistence }
			case "directory_sync":
				s.io.syncDir = func(string) error { return errPersistence }
			}
			if _, e = s.rotate(tok.RefreshToken, now); e == nil {
				t.Fatal("acknowledged failed publication")
			}
			if _, e = s.access(tok.AccessToken, now); e == nil {
				t.Fatal("not suspended")
			}
			s.close()
			s, e = openStore(dir, id)
			if e != nil {
				t.Fatal(e)
			}
			s.close()
		})
	}
}
func TestTokenExpiryAndCapacity(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	id := Identity{"owner", "client", "https://example.invalid/mcp"}
	if e := initStore(dir, id); e != nil {
		t.Fatal(e)
	}
	s, e := openStore(dir, id)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	now := time.Now().UTC()
	tok, e := s.issue([]string{"tapo:read"}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.access(tok.AccessToken, now.Add(time.Hour)); e == nil {
		t.Fatal("expired access")
	}
	if _, e = s.rotate(tok.RefreshToken, now.Add(7*24*time.Hour)); e == nil {
		t.Fatal("expired refresh")
	}
	for i := 1; i < 128; i++ {
		if _, e = s.issue([]string{"tapo:read"}, now); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := os.ReadFile(filepath.Join(dir, "oauth-state.json"))
	if _, e = s.issue([]string{"tapo:read"}, now); e == nil {
		t.Fatal("capacity")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "oauth-state.json"))
	if string(before) != string(after) {
		t.Fatal("capacity altered snapshot")
	}
	if _, e = s.access(tok.AccessToken, now); e != nil {
		t.Fatal("capacity broke existing grant")
	}
}
