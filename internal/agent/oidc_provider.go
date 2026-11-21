package agent

import (
	"bytes"
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"slices"
	"time"
)

type oidcLogin struct {
	requireResponseIssuer bool
	config                oauth2.Config
	verifier              *oidc.IDTokenVerifier
	client                *http.Client
	settings              LoginSettings
}
type oidcMetadata struct {
	ResponseIssuer bool     `json:"authorization_response_iss_parameter_supported"`
	Authorization  string   `json:"authorization_endpoint"`
	Token          string   `json:"token_endpoint"`
	Keys           string   `json:"jwks_uri"`
	Responses      []string `json:"response_types_supported"`
	Methods        []string `json:"token_endpoint_auth_methods_supported"`
	PKCE           []string `json:"code_challenge_methods_supported"`
	Algorithms     []string `json:"id_token_signing_alg_values_supported"`
}
type oidcTransport struct{ base http.RoundTripper }

func (t oidcTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if !validOIDCEndpoint(request.URL.String()) {
		return nil, errConfig
	}
	response, err := t.base.RoundTrip(request)
	if err != nil {
		return nil, errConfig
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1048577))
	if err != nil || len(body) > 1048576 {
		return nil, errConfig
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	return response, nil
}
func newOIDCLogin(ctx context.Context, r *Registry, transport http.RoundTripper) (*oidcLogin, error) {
	settings := r.Server.OAuth.Login
	if settings.Method != "oidc" {
		return nil, nil
	}
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{Timeout: 10 * time.Second, Transport: oidcTransport{transport}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	providerContext := oidc.ClientContext(context.Background(), client)
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), settings.Issuer)
	if err != nil {
		return nil, errConfig
	}
	var metadata oidcMetadata
	if err = provider.Claims(&metadata); err != nil {
		return nil, errConfig
	}
	if err = metadata.validate(settings.TokenAuthMethod); err != nil {
		return nil, err
	}
	algorithms := metadata.signingAlgorithms()
	if len(algorithms) == 0 {
		return nil, errConfig
	}
	style := oauth2.AuthStyleInHeader
	if settings.TokenAuthMethod == "client_secret_post" {
		style = oauth2.AuthStyleInParams
	}
	config := oauth2.Config{ClientID: settings.credentials.ClientID, ClientSecret: settings.credentials.ClientSecret, RedirectURL: routeURL(r, "oauth", "oidc", "callback"), Scopes: []string{oidc.ScopeOpenID}, Endpoint: oauth2.Endpoint{AuthURL: metadata.Authorization, TokenURL: metadata.Token, AuthStyle: style}}
	return &oidcLogin{config: config, verifier: provider.VerifierContext(providerContext, &oidc.Config{ClientID: config.ClientID, SupportedSigningAlgs: algorithms}), client: client, settings: settings, requireResponseIssuer: metadata.ResponseIssuer}, nil
}
func (m oidcMetadata) validate(method string) error {
	if !validOIDCEndpoint(m.Authorization) || !validOIDCEndpoint(m.Token) || !validOIDCEndpoint(m.Keys) {
		return errConfig
	}
	if !slices.Contains(m.Responses, "code") {
		return errConfig
	}
	if len(m.PKCE) > 0 && !slices.Contains(m.PKCE, "S256") {
		return errConfig
	}
	methods := m.Methods
	if len(methods) == 0 {
		methods = []string{"client_secret_basic"}
	}
	if !slices.Contains(methods, method) {
		return errConfig
	}
	return nil
}
func (m oidcMetadata) signingAlgorithms() []string {
	var algorithms []string
	for _, alg := range m.Algorithms {
		if slices.Contains([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}, alg) {
			algorithms = append(algorithms, alg)
		}
	}
	return algorithms
}
func (l *oidcLogin) authURL(state, nonce, verifier string) string {
	return l.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("response_mode", "query"))
}
func (l *oidcLogin) exchange(ctx context.Context, code, nonce, verifier string) error {
	ctx = oidc.ClientContext(ctx, l.client)
	tokens, err := l.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return errAuth
	}
	raw, _ := tokens.Extra("id_token").(string)
	token, err := l.verifier.Verify(ctx, raw)
	if err != nil {
		return errAuth
	}
	return l.verifyIdentity(token, nonce)
}
func (l *oidcLogin) verifyIdentity(token *oidc.IDToken, nonce string) error {
	if token.Issuer != l.settings.Issuer || !equal(token.Nonce, nonce) || nonce == "" {
		return errAuth
	}
	if token.IssuedAt.IsZero() {
		return errAuth
	}
	if !slices.Contains(l.settings.AllowedSubjects, token.Subject) {
		return errAuth
	}
	return l.verifyAuthorizedParty(token)
}
func (l *oidcLogin) verifyAuthorizedParty(token *oidc.IDToken) error {
	var claims struct {
		AuthorizedParty string `json:"azp"`
	}
	if err := token.Claims(&claims); err != nil {
		return errAuth
	}
	if len(token.Audience) > 1 || claims.AuthorizedParty != "" {
		if claims.AuthorizedParty != l.config.ClientID {
			return errAuth
		}
	}
	return nil
}

func (l *oidcLogin) validResponseIssuer(q url.Values) bool {
	if !q.Has("iss") {
		return !l.requireResponseIssuer
	}
	return q.Get("iss") == l.settings.Issuer
}
