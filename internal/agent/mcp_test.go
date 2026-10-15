package agent

import (
	"context"
	"encoding/json"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMCPHTTPScopes(t *testing.T) {
	a, _ := authFixture(t)
	app := inventoryApp(t)
	a.registry.Apps = []*App{app}
	a.scopes = map[string]bool{"inventory:read": true, "inventory:write": true}
	d, e := connectDatabase(context.Background(), a.registry)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	s := httptest.NewServer(a.routes(d))
	defer s.Close()
	tok, e := a.store.issue([]string{"inventory:read"}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	rpc := func(body, token string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", s.URL+"/agent/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		r, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		var v map[string]any
		json.Unmarshal(b, &v)
		return r.StatusCode, v
	}
	if status, _ := rpc(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, ""); status != 401 {
		t.Fatal(status)
	}
	status, v := rpc(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, tok.AccessToken)
	if status != 200 {
		t.Fatal(status, v)
	}
	tools := v["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 1 {
		t.Fatal("scope list")
	}
	if status, _ := rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inventory__set_item_label","arguments":{}}}`, tok.AccessToken); status != 403 {
		t.Fatal("write scope bypass", status)
	}
	status, v = rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inventory__get_item","arguments":{"id":"7"}}}`, tok.AccessToken)
	if status != 200 || v["error"] != nil {
		t.Fatal(status, v)
	}
}

type bearerTransport struct {
	token string
	base  http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header = r.Header.Clone()
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}
func TestOfficialGoClient(t *testing.T) {
	a, _ := authFixture(t)
	app := inventoryApp(t)
	a.registry.Apps = []*App{app}
	a.scopes = map[string]bool{"inventory:read": true, "inventory:write": true}
	d, e := connectDatabase(context.Background(), a.registry)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	s := httptest.NewServer(a.routes(d))
	defer s.Close()
	tok, e := a.store.issue([]string{"inventory:read"}, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "go-acceptance", Version: "1"}, nil)
	session, e := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: s.URL + "/agent/mcp", HTTPClient: &http.Client{Transport: bearerTransport{tok.AccessToken, http.DefaultTransport}}, MaxRetries: -1, DisableStandaloneSSE: true}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	tools, e := session.ListTools(ctx, nil)
	if e != nil || len(tools.Tools) != 1 {
		t.Fatal(e)
	}
	result, e := session.CallTool(ctx, &mcp.CallToolParams{Name: "inventory__get_item", Arguments: map[string]any{"id": "7"}})
	if e != nil || result.IsError || result.StructuredContent == nil {
		t.Fatal("SDK call", e)
	}
}
