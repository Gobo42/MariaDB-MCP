package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type AuthConfig struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}
type passwordParams struct {
	memory, iterations uint32
	parallel           uint8
	salt, hash         []byte
}

func parsePassword(hash string) (passwordParams, error) {
	var p passwordParams
	s := strings.Split(hash, "$")
	if len(s) != 6 || s[0] != "" || s[1] != "argon2id" || s[2] != "v=19" {
		return p, errConfig
	}
	var parallel uint32
	if n, e := fmt.Sscanf(s[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &parallel); e != nil || n != 3 || p.memory < 19456 || p.memory > 65536 || p.iterations < 1 || p.iterations > 4 || parallel < 1 || parallel > 4 {
		return p, errConfig
	}
	p.parallel = uint8(parallel)
	var e error
	p.salt, e = base64.RawStdEncoding.DecodeString(s[4])
	if e != nil || len(p.salt) < 8 || len(p.salt) > 64 {
		return p, errConfig
	}
	p.hash, e = base64.RawStdEncoding.DecodeString(s[5])
	if e != nil || len(p.hash) < 16 || len(p.hash) > 64 {
		return p, errConfig
	}
	return p, nil
}
func (a AuthConfig) validate() error {
	for _, s := range []string{a.Username, a.PasswordHash, a.ClientID, a.ClientSecret} {
		if strings.TrimSpace(s) == "" {
			return errConfig
		}
	}
	_, e := parsePassword(a.PasswordHash)
	return e
}
func verifyPassword(hash, password string) bool {
	p, e := parsePassword(hash)
	if e != nil {
		return false
	}
	actual := argon2.IDKey([]byte(password), p.salt, p.iterations, p.memory, p.parallel, uint32(len(p.hash)))
	return subtle.ConstantTimeCompare(actual, p.hash) == 1
}
func newPasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", errPersistence
	}
	hash := argon2.IDKey([]byte(password), salt, 2, 19456, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=19456,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), nil
}
func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", errPersistence
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func digest(s string) string {
	h := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
func equal(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
