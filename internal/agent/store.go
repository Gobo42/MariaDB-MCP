package agent

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

type Identity struct {
	Owner    string `json:"owner"`
	ClientID string `json:"client_id"`
	Resource string `json:"resource"`
}
type Grant struct {
	Identity      Identity  `json:"identity"`
	Scopes        []string  `json:"scopes"`
	Family        string    `json:"family"`
	FamilyExpires time.Time `json:"family_expires"`
}
type record struct {
	Hash    string    `json:"hash"`
	Kind    string    `json:"kind"`
	Grant   Grant     `json:"grant"`
	Expires time.Time `json:"expires"`
	Revoked bool      `json:"revoked"`
}
type snapshot struct {
	Version  int      `json:"version"`
	Identity Identity `json:"identity"`
	Records  []record `json:"records"`
}
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    uint64 `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}
type storeIO struct {
	write   func(*os.File, []byte) error
	sync    func(*os.File) error
	rename  func(string, string) error
	syncDir func(string) error
}
type tokenStore struct {
	mu        sync.Mutex
	dir       string
	snapshot  snapshot
	lock      *os.File
	suspended bool
	io        storeIO
}

func initStore(dir string, id Identity) error {
	dir, e := ensureDir(dir)
	if e != nil {
		return errPersistence
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 0 {
		return errPersistence
	}
	if e = createPrivate(filepath.Join(dir, "oauth-state.json"), jsonBytes(snapshot{Version: 1, Identity: id, Records: []record{}})); e != nil {
		return errPersistence
	}
	return nil
}
func openStore(dir string, id Identity) (*tokenStore, error) {
	dir, e := privateDir(dir)
	if e != nil {
		return nil, errPersistence
	}
	path := filepath.Join(dir, "oauth-state.json")
	if _, e = readPrivate(path, 1048576); e != nil {
		return nil, errPersistence
	}
	lock, e := openFile(filepath.Join(dir, ".lock"), syscall.O_RDWR|syscall.O_CREAT)
	if e != nil {
		return nil, errPersistence
	}
	fail := func() (*tokenStore, error) { lock.Close(); return nil, errPersistence }
	m, e := lock.Stat()
	if e != nil || !m.Mode().IsRegular() || m.Mode().Perm() != 0600 || m.Size() != 0 {
		return fail()
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail()
	}
	var snap snapshot
	if e = readJSON(path, &snap); e != nil || snap.Version != 1 || snap.Identity != id || snap.Records == nil || len(snap.Records) > 256 {
		return fail()
	}
	seen := map[string]bool{}
	for _, r := range snap.Records {
		b, e := base64.RawURLEncoding.DecodeString(r.Hash)
		if e != nil || len(b) != 32 || r.Grant.Identity != id || seen[r.Hash] || len(r.Grant.Family) != 43 || len(r.Grant.Scopes) == 0 || len(r.Grant.Scopes) > 64 || r.Expires.IsZero() || r.Grant.FamilyExpires.IsZero() || r.Expires.After(r.Grant.FamilyExpires) || (r.Kind != "access" && r.Kind != "refresh" && r.Kind != "consumed") {
			return fail()
		}
		seen[r.Hash] = true
		for _, s := range r.Grant.Scopes {
			if s == "" || len(s) > 40 {
				return fail()
			}
		}
	}
	return &tokenStore{dir: dir, snapshot: snap, lock: lock, io: storeIO{write: func(f *os.File, b []byte) error { _, e := f.Write(b); return e }, sync: func(f *os.File) error { return f.Sync() }, rename: os.Rename, syncDir: syncDir}}, nil
}
func (s *tokenStore) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock != nil {
		s.lock.Close()
		s.lock = nil
		s.suspended = true
	}
}
func (s *tokenStore) publish(snap snapshot) error {
	if s.suspended || s.lock == nil {
		return errPersistence
	}
	b, e := json.Marshal(snap)
	if e != nil || len(b) > 1048576 {
		return errPersistence
	}
	dest := filepath.Join(s.dir, "oauth-state.json")
	name, e := randomSecret()
	if e != nil {
		return e
	}
	temp := filepath.Join(s.dir, ".state-"+name)
	publish := func() error {
		if _, e := readPrivate(dest, 1048576); e != nil {
			return e
		}
		f, e := openFile(temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
		if e != nil {
			return e
		}
		defer f.Close()
		if e = s.io.write(f, b); e != nil {
			return e
		}
		if e = s.io.sync(f); e != nil {
			return e
		}
		if e = s.io.rename(temp, dest); e != nil {
			return e
		}
		return s.io.syncDir(s.dir)
	}
	if e = publish(); e != nil {
		os.Remove(temp)
		s.suspended = true
		return errPersistence
	}
	s.snapshot = snap
	return nil
}
func (s *tokenStore) clone(now time.Time) snapshot {
	snap := snapshot{Version: 1, Identity: s.snapshot.Identity, Records: []record{}}
	for _, r := range s.snapshot.Records {
		if r.Expires.After(now) {
			r.Grant.Scopes = append([]string{}, r.Grant.Scopes...)
			snap.Records = append(snap.Records, r)
		}
	}
	return snap
}
func addTokens(snap *snapshot, g Grant, now time.Time) (Tokens, error) {
	if len(snap.Records)+2 > 256 {
		return Tokens{}, errPersistence
	}
	a, e := randomSecret()
	if e != nil {
		return Tokens{}, e
	}
	r, e := randomSecret()
	if e != nil {
		return Tokens{}, e
	}
	expiry := now.Add(time.Hour)
	if expiry.After(g.FamilyExpires) {
		expiry = g.FamilyExpires
	}
	snap.Records = append(snap.Records, record{digest(a), "access", g, expiry, false}, record{digest(r), "refresh", g, g.FamilyExpires, false})
	return Tokens{a, r, uint64(expiry.Sub(now) / time.Second), "Bearer", joinScopes(g.Scopes)}, nil
}
func joinScopes(scopes []string) string {
	out := ""
	for i, s := range scopes {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out
}
func (s *tokenStore) issue(scopes []string, now time.Time) (Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scopes = append([]string{}, scopes...)
	sort.Strings(scopes)
	unique := []string{}
	for _, v := range scopes {
		if v == "" || len(v) > 40 {
			return Tokens{}, errAuth
		}
		if len(unique) == 0 || unique[len(unique)-1] != v {
			unique = append(unique, v)
		}
	}
	if len(unique) == 0 || len(unique) > 64 {
		return Tokens{}, errAuth
	}
	family, e := randomSecret()
	if e != nil {
		return Tokens{}, e
	}
	snap := s.clone(now)
	g := Grant{snap.Identity, unique, family, now.Add(7 * 24 * time.Hour)}
	tok, e := addTokens(&snap, g, now)
	if e != nil {
		return Tokens{}, e
	}
	if e = s.publish(snap); e != nil {
		return Tokens{}, e
	}
	return tok, nil
}
func (s *tokenStore) rotate(raw string, now time.Time) (Tokens, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.suspended {
		return Tokens{}, errPersistence
	}
	snap := s.clone(now)
	hash := digest(raw)
	index := -1
	for i, r := range snap.Records {
		if r.Kind != "access" && equal(hash, r.Hash) {
			index = i
			break
		}
	}
	if index < 0 || snap.Records[index].Revoked {
		return Tokens{}, errAuth
	}
	r := snap.Records[index]
	if r.Kind == "consumed" {
		for i := range snap.Records {
			if snap.Records[i].Grant.Family == r.Grant.Family {
				snap.Records[i].Revoked = true
			}
		}
		if e := s.publish(snap); e != nil {
			return Tokens{}, e
		}
		return Tokens{}, errAuth
	}
	snap.Records[index].Kind = "consumed"
	tok, e := addTokens(&snap, r.Grant, now)
	if e != nil {
		return Tokens{}, e
	}
	if e = s.publish(snap); e != nil {
		return Tokens{}, e
	}
	return tok, nil
}
func (s *tokenStore) access(raw string, now time.Time) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.suspended {
		return Grant{}, errPersistence
	}
	hash := digest(raw)
	for _, r := range s.snapshot.Records {
		if r.Kind == "access" && !r.Revoked && r.Expires.After(now) && equal(r.Hash, hash) {
			g := r.Grant
			g.Scopes = append([]string{}, g.Scopes...)
			return g, nil
		}
	}
	return Grant{}, errAuth
}
