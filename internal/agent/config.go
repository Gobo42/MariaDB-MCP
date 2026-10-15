package agent

import (
	"encoding/json"
	js "github.com/santhosh-tekuri/jsonschema/v6"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type Server struct {
	Version              int      `json:"version"`
	Listen               string   `json:"listen"`
	PublicBaseURL        string   `json:"public_base_url"`
	AppsDirectory        string   `json:"apps_directory"`
	OAuthCredentialsFile string   `json:"oauth_credentials_file"`
	StateDirectory       string   `json:"state_directory"`
	RedirectURIs         []string `json:"redirect_uris"`
}
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Connection struct {
	Socket          string `json:"socket"`
	Database        string `json:"database"`
	CredentialsFile string `json:"credentials_file"`
}
type GrantConfig struct {
	Table      string   `json:"table"`
	Privileges []string `json:"privileges"`
}
type SchemaCheck struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns"`
}
type SchemaVersion struct {
	Table    string `json:"table"`
	Column   string `json:"column"`
	Expected uint64 `json:"expected" required:"true"`
}
type Binding struct {
	Source   string `json:"source"`
	Name     string `json:"name"`
	DBType   string `json:"db_type"`
	Nullable bool   `json:"nullable"`
}
type Field struct {
	Name        string         `json:"name"`
	Column      string         `json:"column,omitempty"`
	Type        string         `json:"type"`
	Nullable    bool           `json:"nullable"`
	Description string         `json:"description,omitempty"`
	Units       *string        `json:"units,omitempty"`
	JSONSchema  map[string]any `json:"json_schema,omitempty"`
}
type Constraint struct {
	Kind       string `json:"kind"`
	Start      string `json:"start"`
	End        string `json:"end"`
	MaxSeconds uint64 `json:"max_seconds"`
}
type Tool struct {
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	Enabled            bool           `json:"enabled"`
	Kind               string         `json:"kind"`
	InputSchema        map[string]any `json:"input_schema"`
	SQL                string         `json:"sql"`
	Bindings           []Binding      `json:"bindings"`
	Constraints        []Constraint   `json:"constraints,omitempty"`
	TimeoutSeconds     int            `json:"timeout_seconds"`
	Fields             []Field        `json:"fields"`
	MaxRows            *int           `json:"max_rows"`
	DefaultLimit       *int           `json:"default_limit"`
	LimitArgument      *string        `json:"limit_argument"`
	EmptyResult        *string        `json:"empty_result"`
	MaxAffectedRows    *int           `json:"max_affected_rows"`
	MinAffectedRows    *int           `json:"min_affected_rows"`
	ReturnLastInsertID *bool          `json:"return_last_insert_id"`
	Destructive        *bool          `json:"destructive"`
	Idempotent         *bool          `json:"idempotent"`
	validator          *js.Schema
	policy             *SQLPolicy
}

func (t *Tool) UnmarshalJSON(b []byte) error {
	type raw Tool
	v := raw{Enabled: true, TimeoutSeconds: 5}
	if e := decode(b, &v); e != nil {
		return e
	}
	m, e := parseJSON(b)
	if e != nil {
		return e
	}
	o := m.(map[string]any)
	for _, k := range []string{"name", "description", "kind", "input_schema", "sql", "bindings"} {
		if _, ok := o[k]; !ok {
			return errConfig
		}
	}
	*t = Tool(v)
	return nil
}
func (t *Tool) maxRows() int {
	if t.MaxRows != nil {
		return *t.MaxRows
	}
	return 1000
}
func (t *Tool) defaultLimit() int {
	if t.DefaultLimit != nil {
		return *t.DefaultLimit
	}
	return min(500, t.maxRows())
}
func (t *Tool) maxAffected() int {
	if t.MaxAffectedRows != nil {
		return *t.MaxAffectedRows
	}
	return 1
}
func (t *Tool) minAffected() int {
	if t.MinAffectedRows != nil {
		return *t.MinAffectedRows
	}
	return 0
}

type App struct {
	Version        int            `json:"version"`
	ID             string         `json:"app_id"`
	Description    string         `json:"description"`
	Enabled        bool           `json:"enabled"`
	ConnectionFile string         `json:"connection_file"`
	User           string         `json:"database_user"`
	Access         string         `json:"access"`
	Grants         []GrantConfig  `json:"grants"`
	Constants      map[string]any `json:"constants"`
	SchemaChecks   []SchemaCheck  `json:"schema_checks,omitempty"`
	SchemaVersion  *SchemaVersion `json:"schema_version"`
	Tools          []*Tool        `json:"tools"`
	connection     Connection
	credentials    Credentials
}

func (a *App) UnmarshalJSON(b []byte) error {
	type raw App
	v := raw{Enabled: true, Access: "read_only", Constants: map[string]any{}}
	if e := decode(b, &v); e != nil {
		return e
	}
	*a = App(v)
	return nil
}

type Registry struct {
	Server Server
	Apps   []*App
	Auth   AuthConfig
}

var idRE = regexp.MustCompile("^[a-z][a-z0-9_]*$")
var sqlIDRE = regexp.MustCompile("^[a-zA-Z0-9_]+$")

func identifier(s string, max int) bool { return len(s) <= max && idRE.MatchString(s) }
func sqlIdentifier(s string) bool       { return len(s) <= 64 && sqlIDRE.MatchString(s) }
func validText(s string, max int) bool {
	if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

var dataTypes = map[string]bool{"string": true, "integer": true, "bigint": true, "decimal": true, "number": true, "boolean": true, "date": true, "datetime": true, "timestamp": true, "time": true, "duration": true, "json": true, "binary": true}

func (a *App) validate() error {
	if a.Version != 1 || !identifier(a.ID, 32) || !identifier(a.User, 32) || !validText(a.Description, 1024) || len(a.Tools) == 0 || len(a.Grants) == 0 || (a.Access != "read_only" && a.Access != "read_write") {
		return errConfig
	}
	tables := map[string]bool{}
	for _, g := range a.Grants {
		if !sqlIdentifier(g.Table) || tables[g.Table] || len(g.Privileges) == 0 {
			return errConfig
		}
		tables[g.Table] = true
		seen := map[string]bool{}
		for _, p := range g.Privileges {
			if seen[p] || !strings.Contains(" SELECT INSERT UPDATE DELETE ", " "+p+" ") || a.Access == "read_only" && p != "SELECT" {
				return errConfig
			}
			seen[p] = true
		}
	}
	for k := range a.Constants {
		if !identifier(k, 64) {
			return errConfig
		}
	}
	for _, s := range a.SchemaChecks {
		seen := map[string]bool{}
		if !tables[s.Table] || len(s.Columns) == 0 {
			return errConfig
		}
		for _, c := range s.Columns {
			if !sqlIdentifier(c) || seen[c] {
				return errConfig
			}
			seen[c] = true
		}
	}
	if s := a.SchemaVersion; s != nil {
		if !sqlIdentifier(s.Column) || !a.allowed(s.Table, "SELECT") {
			return errConfig
		}
	}
	names := map[string]bool{}
	active := false
	for _, t := range a.Tools {
		if !identifier(t.Name, 64) || names[t.Name] || !validText(t.Description, 2048) || strings.TrimSpace(t.SQL) == "" || t.TimeoutSeconds < 1 || t.TimeoutSeconds > 5 {
			return errConfig
		}
		names[t.Name] = true
		active = active || t.Enabled
		var e error
		t.validator, e = compileSchema(t.InputSchema, true)
		if e != nil {
			return e
		}
		props, _ := t.InputSchema["properties"].(map[string]any)
		for _, b := range t.Bindings {
			if !dataTypes[b.DBType] {
				return errConfig
			}
			switch b.Source {
			case "argument":
				p, ok := props[b.Name].(map[string]any)
				if !ok || t.LimitArgument != nil && *t.LimitArgument == b.Name {
					return errConfig
				}
				if b.DBType != "json" {
					expected := "string"
					switch b.DBType {
					case "integer", "number", "boolean":
						expected = b.DBType
					}
					ts := []any{p["type"]}
					if ar, ok := p["type"].([]any); ok {
						ts = ar
					}
					for _, v := range ts {
						if v != expected && !(v == "integer" && b.DBType == "number") && !(v == "null" && b.Nullable) {
							return errConfig
						}
					}
				}
			case "constant":
				v, ok := a.Constants[b.Name]
				if !ok {
					return errConfig
				}
				if _, e = bindValue(b.DBType, v, b.Nullable); e != nil {
					return errConfig
				}
			case "runtime":
				if b.Nullable || !(b.Name == "fetch_limit" && t.Kind == "query" && b.DBType == "integer" || b.Name == "now_utc" && b.DBType == "timestamp") {
					return errConfig
				}
			default:
				return errConfig
			}
		}
		for _, r := range t.Constraints {
			if r.Kind != "time_range" || r.MaxSeconds == 0 || r.MaxSeconds > 9223372036854775807 || r.Start == r.End {
				return errConfig
			}
			for _, n := range []string{r.Start, r.End} {
				p, ok := props[n].(map[string]any)
				req, _ := t.InputSchema["required"].([]any)
				if !ok || p["type"] != "string" || p["format"] != "date-time" || !hasAny(req, n) {
					return errConfig
				}
			}
		}
		switch t.Kind {
		case "query":
			if t.MaxAffectedRows != nil || t.MinAffectedRows != nil || t.ReturnLastInsertID != nil || t.Destructive != nil || t.Idempotent != nil || len(t.Fields) == 0 || t.maxRows() < 1 || t.maxRows() > 1000 || t.defaultLimit() < 1 || t.defaultLimit() > t.maxRows() {
				return errConfig
			}
			if t.EmptyResult != nil && *t.EmptyResult != "empty" && *t.EmptyResult != "not_found" {
				return errConfig
			}
			if t.LimitArgument != nil {
				p, ok := props[*t.LimitArgument].(map[string]any)
				if !ok || p["type"] != "integer" {
					return errConfig
				}
			}
			fn, aliases := map[string]bool{}, map[string]bool{}
			for _, f := range t.Fields {
				col := f.Column
				if col == "" {
					col = f.Name
				}
				if !identifier(f.Name, 64) || fn[f.Name] || !sqlIdentifier(col) || aliases[col] || !dataTypes[f.Type] || utf8.RuneCountInString(f.Description) > 1024 || f.Units != nil && !validText(*f.Units, 64) {
					return errConfig
				}
				fn[f.Name] = true
				aliases[col] = true
				if f.JSONSchema != nil {
					if f.Type != "json" {
						return errConfig
					}
					if _, e = compileSchema(f.JSONSchema, false); e != nil {
						return e
					}
				}
			}
		case "execute":
			if a.Access != "read_write" || t.Fields != nil || t.MaxRows != nil || t.DefaultLimit != nil || t.LimitArgument != nil || t.EmptyResult != nil || t.maxAffected() < 1 || t.maxAffected() > 1000 || t.minAffected() < 0 || t.minAffected() > t.maxAffected() {
				return errConfig
			}
		default:
			return errConfig
		}
		t.policy, e = validateSQL(a, t)
		if e != nil {
			return e
		}
	}
	if a.Enabled && !active {
		return errConfig
	}
	return nil
}
func (a *App) allowed(table, p string) bool {
	for _, g := range a.Grants {
		if g.Table == table {
			for _, v := range g.Privileges {
				if v == p {
					return true
				}
			}
		}
	}
	return false
}
func hasAny(a []any, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func loadRegistry(file string) (*Registry, error) {
	file, e := normalizeFile(file)
	if e != nil {
		return nil, e
	}
	r := &Registry{Server: Server{Listen: "127.0.0.1:8810", StateDirectory: "/var/lib/mariadb-mcp"}}
	if e = readJSON(file, &r.Server); e != nil {
		return nil, e
	}
	s := &r.Server
	host, port, e := net.SplitHostPort(s.Listen)
	pn, pe := strconv.Atoi(port)
	if e != nil || pe != nil || pn < 0 || pn > 65535 || net.ParseIP(host) == nil || port == "" || s.Version != 1 || len(s.RedirectURIs) == 0 {
		return nil, errConfig
	}
	u, e := url.Parse(s.PublicBaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, errConfig
	}
	seen := map[string]bool{}
	for _, raw := range s.RedirectURIs {
		u, e := url.Parse(raw)
		if e != nil || seen[raw] || u.User != nil || u.Hostname() == "" || u.Fragment != "" || !(u.Scheme == "https" || u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()) {
			return nil, errConfig
		}
		seen[raw] = true
	}
	if s.AppsDirectory, e = resolve(file, s.AppsDirectory, true); e != nil {
		return nil, e
	}
	if _, e = privateDir(s.AppsDirectory); e != nil {
		return nil, e
	}
	if s.OAuthCredentialsFile, e = resolve(file, s.OAuthCredentialsFile, false); e != nil {
		return nil, e
	}
	if e = readJSON(s.OAuthCredentialsFile, &r.Auth); e != nil {
		return nil, e
	}
	if e = r.Auth.validate(); e != nil {
		return nil, e
	}
	if s.StateDirectory, e = resolve(file, s.StateDirectory, true); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(s.AppsDirectory)
	if e != nil {
		return nil, errConfig
	}
	ids, users, conns, creds, tools := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	active := 0
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(s.AppsDirectory, entry.Name())
		a := &App{}
		if e = readJSON(path, a); e != nil {
			return nil, e
		}
		if e = a.validate(); e != nil {
			return nil, e
		}
		if ids[a.ID] || users[a.User] {
			return nil, errConfig
		}
		ids[a.ID] = true
		users[a.User] = true
		for _, t := range a.Tools {
			name := a.ID + "__" + t.Name
			if tools[name] {
				return nil, errConfig
			}
			tools[name] = true
			if a.Enabled && t.Enabled {
				active++
			}
		}
		if a.ConnectionFile, e = resolve(path, a.ConnectionFile, false); e != nil {
			return nil, e
		}
		if conns[a.ConnectionFile] {
			return nil, errConfig
		}
		conns[a.ConnectionFile] = true
		if e = readJSON(a.ConnectionFile, &a.connection); e != nil {
			return nil, e
		}
		if !filepath.IsAbs(a.connection.Socket) || strings.ContainsRune(a.connection.Socket, 0) || !sqlIdentifier(a.connection.Database) {
			return nil, errConfig
		}
		if a.connection.CredentialsFile, e = resolve(a.ConnectionFile, a.connection.CredentialsFile, false); e != nil {
			return nil, e
		}
		if creds[a.connection.CredentialsFile] {
			return nil, errConfig
		}
		creds[a.connection.CredentialsFile] = true
		if e = readJSON(a.connection.CredentialsFile, &a.credentials); e != nil {
			return nil, e
		}
		if a.credentials.Username != a.User || strings.TrimSpace(a.credentials.Password) == "" {
			return nil, errConfig
		}
		r.Apps = append(r.Apps, a)
	}
	if active == 0 {
		return nil, errConfig
	}
	return r, nil
}
func jsonBytes(v any) []byte { b, _ := json.Marshal(v); return b }
