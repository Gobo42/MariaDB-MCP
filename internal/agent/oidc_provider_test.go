package agent

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type oidcTestCode struct{ nonce, challenge, redirect string }
type testOIDCProvider struct {
	server          *httptest.Server
	mu              sync.Mutex
	key             *rsa.PrivateKey
	kid             string
	codes           map[string]oidcTestCode
	overrides       map[string]any
	metadataChanges map[string]any
	tokenError      bool
	badSignature    bool
	omitIDToken     bool
	tokens          []string
	methods         []string
}

func newTestOIDCProvider(t *testing.T) *testOIDCProvider {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &testOIDCProvider{key: key, kid: "first", codes: map[string]oidcTestCode{}}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}
func (p *testOIDCProvider) serve(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		m := map[string]any{"issuer": p.server.URL, "authorization_response_iss_parameter_supported": true, "authorization_endpoint": p.server.URL + "/authorize", "token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/keys", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "subject_types_supported": []string{"public"}, "scopes_supported": []string{"openid"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"}}
		for k, v := range p.metadataChanges {
			m[k] = v
		}
		jsonReply(w, 200, m)
	case "/keys":
		jsonReply(w, 200, map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": p.kid, "n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes())}}})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("scope") != "openid" || q.Get("response_type") != "code" || q.Get("response_mode") != "query" || q.Get("client_id") != "upstream-client" || q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
			w.WriteHeader(400)
			return
		}
		code, _ := randomSecret()
		p.codes[code] = oidcTestCode{q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")}
		u, _ := url.Parse(q.Get("redirect_uri"))
		v := u.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		v.Set("iss", p.server.URL)
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), 303)
	case "/token":
		if p.tokenError {
			jsonReply(w, 500, map[string]string{"error": "server_error"})
			return
		}
		r.ParseForm()
		id, secret, basic := r.BasicAuth()
		method := "client_secret_basic"
		if !basic {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
			method = "client_secret_post"
		}
		code, ok := p.codes[r.Form.Get("code")]
		delete(p.codes, r.Form.Get("code"))
		if !ok || id != "upstream-client" || secret != "upstream-secret" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != code.redirect || digest(r.Form.Get("code_verifier")) != code.challenge {
			jsonReply(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		p.methods = append(p.methods, method)
		claims := map[string]any{"iss": p.server.URL, "sub": "owner-subject", "aud": "upstream-client", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "nonce": code.nonce}
		for k, v := range p.overrides {
			if v == nil {
				delete(claims, k)
			} else {
				claims[k] = v
			}
		}
		header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": p.kid})
		body, _ := json.Marshal(claims)
		unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
		h := sha256.Sum256([]byte(unsigned))
		signature, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, h[:])
		token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
		if p.badSignature {
			signature[0] ^= 1
			token = unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
		}
		if p.omitIDToken {
			jsonReply(w, 200, map[string]any{"access_token": "upstream", "token_type": "Bearer"})
			return
		}
		p.tokens = append(p.tokens, token)
		jsonReply(w, 200, map[string]any{"access_token": "upstream-access-never-persist", "refresh_token": "upstream-refresh-never-persist", "token_type": "Bearer", "expires_in": 60, "id_token": token})
	default:
		w.WriteHeader(404)
	}
}
func (p *testOIDCProvider) registry(method string) *Registry {
	return &Registry{Server: Server{PublicBaseURL: "https://mcp.example.invalid/agent", OAuth: OAuthSettings{Login: LoginSettings{Method: "oidc", Issuer: p.server.URL, AllowedSubjects: []string{"owner-subject"}, TokenAuthMethod: method, credentials: oidcCredentials{"upstream-client", "upstream-secret"}}}}}
}
func (p *testOIDCProvider) code(t *testing.T, login *oidcLogin, nonce, verifier string) string {
	t.Helper()
	target := login.authURL("upstream-state", nonce, verifier)
	c := *p.server.Client()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := c.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 303 {
		t.Fatal("upstream authorize failed")
	}
	u, _ := url.Parse(response.Header.Get("Location"))
	return u.Query().Get("code")
}
func TestOIDCProviderExchange(t *testing.T) {
	p := newTestOIDCProvider(t)
	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		login, err := newOIDCLogin(context.Background(), p.registry(method), p.server.Client().Transport)
		if err != nil {
			t.Fatal(err)
		}
		if login.client.Timeout <= 0 || login.client.Timeout > 10*time.Second {
			t.Fatal("provider requests lack the bounded timeout")
		}
		verifier := strings.Repeat("v", 64)
		code := p.code(t, login, "nonce", verifier)
		if err = login.exchange(context.Background(), code, "nonce", verifier); err != nil {
			t.Fatal(err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.Join(p.methods, ",") != "client_secret_basic,client_secret_post" {
		t.Fatal("client authentication method ignored")
	}
}
func TestOIDCRejectsInvalidIdentity(t *testing.T) {
	p := newTestOIDCProvider(t)
	login, err := newOIDCLogin(context.Background(), p.registry("client_secret_basic"), p.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	cases := []map[string]any{{"nonce": "wrong"}, {"iss": "https://wrong.invalid"}, {"aud": "wrong"}, {"exp": time.Now().Add(-time.Minute).Unix()}, {"sub": "other-owner"}, {"sub": ""}, {"azp": "wrong"}, {"azp": []string{"upstream-client"}}, {"aud": []string{"upstream-client", "other"}}}
	for _, override := range cases {
		p.mu.Lock()
		p.overrides = override
		p.mu.Unlock()
		verifier := strings.Repeat("v", 64)
		code := p.code(t, login, "nonce", verifier)
		if err = login.exchange(context.Background(), code, "nonce", verifier); err == nil {
			t.Fatalf("invalid claims accepted: %v", override)
		}
	}
	p.mu.Lock()
	p.overrides = map[string]any{"aud": []string{"upstream-client", "other"}, "azp": "upstream-client"}
	p.mu.Unlock()
	verifier := strings.Repeat("v", 64)
	if err = login.exchange(context.Background(), p.code(t, login, "nonce", verifier), "nonce", verifier); err != nil {
		t.Fatal("valid authorized party refused", err)
	}
}
func TestOIDCDiscoveryBoundaries(t *testing.T) {
	p := newTestOIDCProvider(t)
	for _, change := range []map[string]any{{"issuer": "https://other.invalid"}, {"authorization_endpoint": "http://unsafe.invalid"}, {"token_endpoint": "http://unsafe.invalid"}, {"jwks_uri": "http://unsafe.invalid"}, {"response_types_supported": []string{"token"}}, {"response_types_supported": "code"}, {"code_challenge_methods_supported": []string{"plain"}}, {"id_token_signing_alg_values_supported": []string{"HS256"}}, {"token_endpoint_auth_methods_supported": []string{"none"}}} {
		p.mu.Lock()
		p.metadataChanges = change
		p.mu.Unlock()
		if _, err := newOIDCLogin(context.Background(), p.registry("client_secret_basic"), p.server.Client().Transport); err == nil {
			t.Fatal("bad metadata accepted", change)
		}
	}
}

func TestOIDCSignatureAndKeyRotation(t *testing.T) {
	p := newTestOIDCProvider(t)
	login, err := newOIDCLogin(context.Background(), p.registry("client_secret_basic"), p.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	v := strings.Repeat("v", 64)
	for _, missing := range []bool{false, true} {
		p.mu.Lock()
		p.badSignature = !missing
		p.omitIDToken = missing
		p.mu.Unlock()
		if err := login.exchange(context.Background(), p.code(t, login, "nonce", v), "nonce", v); err == nil {
			t.Fatal("unsigned/missing identity accepted")
		}
	}
	p.mu.Lock()
	p.badSignature = false
	p.omitIDToken = false
	p.mu.Unlock()
	if err := login.exchange(context.Background(), p.code(t, login, "nonce", v), "nonce", v); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.key = key
	p.kid = "rotated"
	p.mu.Unlock()
	if err := login.exchange(context.Background(), p.code(t, login, "nonce", v), "nonce", v); err != nil {
		t.Fatal("rotated signing key rejected", err)
	}
}
func TestOIDCRequiresIssuedAt(t *testing.T) {
	p := newTestOIDCProvider(t)
	p.overrides = map[string]any{"iat": nil}
	login, err := newOIDCLogin(context.Background(), p.registry("client_secret_basic"), p.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	v := strings.Repeat("v", 64)
	if err := login.exchange(context.Background(), p.code(t, login, "nonce", v), "nonce", v); err == nil {
		t.Fatal("ID token without mandatory issued-at accepted")
	}
}

type oidcRoundTripFunc func(*http.Request) (*http.Response, error)

func (f oidcRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestOIDCTransportBoundaries(t *testing.T) {
	request, _ := http.NewRequest("GET", "https://idp.invalid/keys", nil)
	for _, body := range []string{"small", strings.Repeat("x", 1048576), strings.Repeat("x", 1048577)} {
		transport := oidcTransport{oidcRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}
		response, err := transport.RoundTrip(request)
		if len(body) > 1048576 {
			if err == nil {
				t.Fatal("oversize provider response accepted")
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(b) != body {
				t.Fatal("provider response changed")
			}
		}
	}
	transport := oidcTransport{oidcRoundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("private network details") })}
	if _, err := transport.RoundTrip(request); err != errConfig {
		t.Fatal("network error leaked")
	}
	request, _ = http.NewRequest("GET", "http://idp.invalid", nil)
	if _, err := transport.RoundTrip(request); err == nil {
		t.Fatal("plaintext provider request allowed")
	}
}
func TestOIDCDiscoveryOptionalMetadata(t *testing.T) {
	p := newTestOIDCProvider(t)
	p.metadataChanges = map[string]any{"code_challenge_methods_supported": nil, "token_endpoint_auth_methods_supported": nil}
	if _, err := newOIDCLogin(context.Background(), p.registry("client_secret_basic"), p.server.Client().Transport); err != nil {
		t.Fatal("standards default basic client auth rejected", err)
	}
	if _, err := newOIDCLogin(context.Background(), p.registry("client_secret_post"), p.server.Client().Transport); err == nil {
		t.Fatal("unadvertised post client auth accepted")
	}
	if login, err := newOIDCLogin(context.Background(), &Registry{}, nil); err != nil || login != nil {
		t.Fatal("password mode contacted IdP")
	}
}

func TestOIDCRejectsEmptyNonce(t *testing.T) {
	p := newTestOIDCProvider(t)
	p.overrides = map[string]any{"nonce": ""}
	login, err := newOIDCLogin(context.Background(), p.registry("client_secret_basic"), p.server.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	v := strings.Repeat("v", 64)
	if err := login.exchange(context.Background(), p.code(t, login, "original", v), "", v); err == nil {
		t.Fatal("empty nonce accepted")
	}
}
