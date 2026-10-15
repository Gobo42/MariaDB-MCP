package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type authContext struct {
	raw   string
	grant Grant
}
type authContextKey struct{}

func fieldSchema(f Field) map[string]any {
	s := map[string]any{}
	switch f.Type {
	case "string":
		s["type"] = "string"
	case "integer":
		s = map[string]any{"type": "integer", "minimum": -safeInteger, "maximum": safeInteger}
	case "number", "boolean":
		s["type"] = f.Type
	case "bigint":
		s = map[string]any{"type": "string", "pattern": "^(0|-?[1-9][0-9]*)$"}
	case "decimal":
		s = map[string]any{"type": "string", "pattern": "^-?(0|[1-9][0-9]*)([.][0-9]+)?$"}
	case "date", "timestamp":
		format := "date"
		if f.Type == "timestamp" {
			format = "date-time"
		}
		s = map[string]any{"type": "string", "format": format}
	case "datetime":
		s = map[string]any{"type": "string", "pattern": datetimeRE.String()}
	case "time":
		s = map[string]any{"type": "string", "pattern": "^[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?$"}
	case "duration":
		s = map[string]any{"type": "string", "pattern": timeRE.String()}
	case "binary":
		s = map[string]any{"type": "string", "contentEncoding": "base64"}
	case "json":
		if f.JSONSchema != nil {
			for k, v := range f.JSONSchema {
				s[k] = v
			}
		}
	}
	if f.Description != "" {
		s["description"] = f.Description
	}
	if f.Nullable {
		return map[string]any{"anyOf": []any{s, map[string]any{"type": "null"}}}
	}
	return s
}
func outputSchema(t *Tool) map[string]any {
	p := map[string]any{"app_id": map[string]any{"type": "string"}, "tool": map[string]any{"type": "string"}, "kind": map[string]any{"const": t.Kind}}
	if t.Kind == "query" {
		fields, req := map[string]any{}, []string{}
		for _, f := range t.Fields {
			fields[f.Name] = fieldSchema(f)
			req = append(req, f.Name)
		}
		p["fields"] = map[string]any{"const": fieldsMetadata(t)}
		p["rows"] = map[string]any{"type": "array", "maxItems": t.maxRows(), "items": map[string]any{"type": "object", "properties": fields, "required": req, "additionalProperties": false}}
		p["row_count"] = map[string]any{"type": "integer", "minimum": 0, "maximum": t.maxRows()}
		p["limit"] = map[string]any{"type": "integer", "minimum": 1, "maximum": t.maxRows()}
		p["truncated"] = map[string]any{"type": "boolean"}
		p["ranges"] = map[string]any{"type": "array", "items": map[string]any{"type": "object", "properties": map[string]any{"start_argument": map[string]any{"type": "string"}, "end_argument": map[string]any{"type": "string"}, "start": map[string]any{"type": "string", "format": "date-time"}, "end": map[string]any{"type": "string", "format": "date-time"}}, "required": []string{"start_argument", "end_argument", "start", "end"}, "additionalProperties": false}}
	} else {
		p["affected_rows"] = map[string]any{"type": "integer", "minimum": t.minAffected(), "maximum": t.maxAffected()}
		p["last_insert_id"] = map[string]any{"type": []string{"string", "null"}, "pattern": "^[1-9][0-9]*$"}
		p["commit"] = map[string]any{"const": "committed"}
	}
	required := []string{}
	for k := range p {
		required = append(required, k)
	}
	return map[string]any{"type": "object", "properties": p, "required": required, "additionalProperties": false}
}
func toolDefinition(app *App, t *Tool) *mcp.Tool {
	read := t.Kind == "query"
	destructive, idempotent := !read, read
	open := false
	if t.Destructive != nil {
		destructive = *t.Destructive
	}
	if t.Idempotent != nil {
		idempotent = *t.Idempotent
	}
	return &mcp.Tool{Name: app.ID + "__" + t.Name, Description: t.Description, InputSchema: t.InputSchema, OutputSchema: outputSchema(t), Annotations: &mcp.ToolAnnotations{ReadOnlyHint: read, DestructiveHint: &destructive, IdempotentHint: idempotent, OpenWorldHint: &open}}
}
func hasScope(g Grant, s string) bool {
	for _, v := range g.Scopes {
		if v == s {
			return true
		}
	}
	return false
}
func (a *oauthService) authenticate(r *http.Request) (authContext, error) {
	h := r.Header.Values("Authorization")
	if len(h) != 1 {
		return authContext{}, errAuth
	}
	parts := strings.SplitN(h[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || len(parts[1]) == 0 || len(parts[1]) > 128 {
		return authContext{}, errAuth
	}
	g, e := a.store.access(parts[1], time.Now().UTC())
	if e != nil {
		return authContext{}, e
	}
	for _, s := range g.Scopes {
		if a.scopes[s] {
			return authContext{parts[1], g}, nil
		}
	}
	return authContext{}, errAuth
}
func (a *oauthService) challenge(w http.ResponseWriter) {
	u, _ := url.Parse(a.registry.Server.PublicBaseURL)
	u.Path = "/.well-known/oauth-protected-resource" + routePrefix(a.registry) + "/mcp"
	u.RawPath = ""
	w.Header().Set("WWW-Authenticate", "Bearer resource_metadata=\""+u.String()+"\"")
	oauthError(w, 401, "unauthorized")
}
func (a *oauthService) mcpHandler(d *database) http.Handler {
	sdk := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		grant := r.Context().Value(authContextKey{}).(authContext)
		server := mcp.NewServer(&mcp.Implementation{Name: "mariadb-mcp", Version: "0.1.0"}, nil)
		for _, app := range a.registry.Apps {
			if !app.Enabled {
				continue
			}
			for _, tool := range app.Tools {
				if !tool.Enabled || !hasScope(grant.grant, scope(app.ID, tool)) {
					continue
				}
				server.AddTool(toolDefinition(app, tool), func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					started := time.Now()
					var value map[string]any
					var e error
					g, authErr := a.store.access(grant.raw, time.Now().UTC())
					if authErr != nil || !hasScope(g, scope(app.ID, tool)) {
						e = errAuth
					} else {
						raw := req.Params.Arguments
						if len(raw) == 0 {
							raw = json.RawMessage("{}")
						}
						v, parseErr := parseJSON(raw)
						args, ok := v.(map[string]any)
						if parseErr != nil || !ok {
							e = errArgs
						} else {
							value, e = d.execute(ctx, app, tool, args)
						}
					}
					code, outcome := "ok", "read"
					if e != nil {
						code = e.Error()
					}
					if tool.Kind == "execute" {
						outcome = "not_acknowledged"
						if e == nil {
							outcome = "committed"
						} else if e == errUnknown {
							outcome = "unknown"
						}
					}
					fmt.Fprintf(os.Stderr, "app=%s tool=%s duration_ms=%d code=%s outcome=%s\n", app.ID, tool.Name, time.Since(started).Milliseconds(), code, outcome)
					if e != nil {
						value = map[string]any{"error": map[string]any{"code": code, "message": code}}
					}
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(jsonBytes(value))}}, StructuredContent: value, IsError: e != nil}, nil
				})
			}
		}
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, DisableLocalhostProtection: true})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grant, e := a.authenticate(r)
		if e != nil {
			a.challenge(w)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
		if e != nil {
			w.WriteHeader(413)
			return
		}
		if len(b) > 0 {
			v, e := parseJSON(b)
			if e != nil {
				oauthError(w, 400, "invalid_request")
				return
			}
			if m, ok := v.(map[string]any); ok && m["method"] == "tools/call" {
				if p, ok := m["params"].(map[string]any); ok {
					if n, ok := p["name"].(string); ok {
						for _, app := range a.registry.Apps {
							if !app.Enabled {
								continue
							}
							for _, t := range app.Tools {
								if t.Enabled && app.ID+"__"+t.Name == n && !hasScope(grant.grant, scope(app.ID, t)) {
									oauthError(w, 403, "insufficient_scope")
									return
								}
							}
						}
					}
				}
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(b))
		r = r.WithContext(context.WithValue(r.Context(), authContextKey{}, grant))
		sdk.ServeHTTP(w, r)
	})
}
