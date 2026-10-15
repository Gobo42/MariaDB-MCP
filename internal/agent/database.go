package agent

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	mysql "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"net"
	"os"
	"reflect"
	"strings"
	"time"
)

var errDB = errors.New("database_unavailable")
var errTimeout = errors.New("query_timeout")
var errWarning = errors.New("statement_warning")
var errPrecondition = errors.New("write_precondition_failed")
var errUnknown = errors.New("write_outcome_unknown")
var errLarge = errors.New("result_too_large")
var errNotFound = errors.New("not_found")

func databaseError(e error) error {
	if errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled) {
		return errTimeout
	}
	var m *mysql.MySQLError
	if errors.As(e, &m) && (m.Number == 1969 || m.Number == 3024 || m.Number == 1205) {
		return errTimeout
	}
	return errDB
}

type database struct{ pools map[string]*sql.DB }

func dbConfig(a *App) *mysql.Config {
	c := mysql.NewConfig()
	c.Net = "unix"
	c.Addr = a.connection.Socket
	c.DBName = a.connection.Database
	c.User = a.credentials.Username
	c.Passwd = a.credentials.Password
	c.Timeout = 5 * time.Second
	c.ReadTimeout = 5 * time.Second
	c.WriteTimeout = 5 * time.Second
	c.ClientFoundRows = false
	c.ParseTime = false
	c.MultiStatements = false
	c.InterpolateParams = false
	c.Logger = log.New(io.Discard, "", 0)
	return c
}
func connectDatabase(ctx context.Context, r *Registry) (*database, error) {
	d := &database{pools: map[string]*sql.DB{}}
	for _, a := range r.Apps {
		if !a.Enabled {
			continue
		}
		c := dbConfig(a)
		con, e := mysql.NewConnector(c)
		if e != nil {
			d.close()
			return nil, errConfig
		}
		pool := sql.OpenDB(con)
		pool.SetMaxOpenConns(4)
		pool.SetMaxIdleConns(4)
		d.pools[a.ID] = pool
		if e = checkApp(ctx, a); e != nil {
			d.close()
			return nil, e
		}
	}
	return d, nil
}
func (d *database) close() {
	for _, p := range d.pools {
		p.Close()
	}
}
func session(ctx context.Context, c *sql.Conn, seconds int) error {
	_, e := c.ExecContext(ctx, fmt.Sprintf("SET SESSION time_zone = '+00:00', sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION', max_statement_time = %d", seconds))
	if e != nil {
		return databaseError(e)
	}
	return nil
}
func checkGrants(a *App, grants []string) error {
	actual, expected := map[string]bool{}, map[string]bool{}
	for _, g := range a.Grants {
		for _, p := range g.Privileges {
			expected[g.Table+":"+p] = true
		}
	}
	for _, raw := range grants {
		if strings.Contains(raw, "WITH GRANT OPTION") || !strings.HasPrefix(raw, "GRANT ") {
			return errConfig
		}
		parts := strings.SplitN(strings.TrimPrefix(raw, "GRANT "), " ON ", 2)
		if len(parts) != 2 {
			return errConfig
		}
		tail := strings.SplitN(parts[1], " TO ", 2)
		if len(tail) != 2 {
			return errConfig
		}
		if parts[0] == "USAGE" && tail[0] == "*.*" {
			continue
		}
		prefix := "`" + a.connection.Database + "`.`"
		if !strings.HasPrefix(tail[0], prefix) || !strings.HasSuffix(tail[0], "`") {
			return errConfig
		}
		table := strings.TrimSuffix(strings.TrimPrefix(tail[0], prefix), "`")
		if !sqlIdentifier(table) {
			return errConfig
		}
		for _, p := range strings.Split(parts[0], ", ") {
			key := table + ":" + p
			if !strings.Contains(" SELECT INSERT UPDATE DELETE ", " "+p+" ") || actual[key] {
				return errConfig
			}
			actual[key] = true
		}
	}
	if !reflect.DeepEqual(actual, expected) {
		return errConfig
	}
	return nil
}
func checkApp(parent context.Context, a *App) error {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cfg := dbConfig(a)
	var tap *metadataConn
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, e := (&net.Dialer{}).DialContext(ctx, "unix", addr)
		if e != nil {
			return nil, e
		}
		tap = &metadataConn{Conn: c}
		return tap, nil
	}
	connector, e := mysql.NewConnector(cfg)
	if e != nil {
		return errConfig
	}
	pool := sql.OpenDB(connector)
	defer pool.Close()
	conn, e := pool.Conn(ctx)
	if e != nil {
		return databaseError(e)
	}
	defer conn.Close()
	if e = session(ctx, conn, 5); e != nil {
		return e
	}
	var user string
	if e = conn.QueryRowContext(ctx, "SELECT CURRENT_USER()").Scan(&user); e != nil {
		return databaseError(e)
	}
	if user != a.User+"@localhost" {
		return errConfig
	}
	var role sql.NullString
	if e = conn.QueryRowContext(ctx, "SELECT CURRENT_ROLE()").Scan(&role); e != nil {
		return databaseError(e)
	}
	if role.Valid {
		return errConfig
	}
	rows, e := conn.QueryContext(ctx, "SHOW GRANTS")
	if e != nil {
		return databaseError(e)
	}
	grants := []string{}
	for rows.Next() {
		var g string
		if e = rows.Scan(&g); e != nil {
			rows.Close()
			return errConfig
		}
		grants = append(grants, g)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return databaseError(e)
	}
	if e = checkGrants(a, grants); e != nil {
		fmt.Fprintln(os.Stderr, "stage=grants")
		return e
	}
	for _, check := range a.SchemaChecks {
		rows, e := conn.QueryContext(ctx, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=? AND TABLE_NAME=?", a.connection.Database, check.Table)
		if e != nil {
			return databaseError(e)
		}
		cols := map[string]bool{}
		for rows.Next() {
			var col string
			if e = rows.Scan(&col); e != nil {
				rows.Close()
				return errConfig
			}
			cols[col] = true
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return databaseError(e)
		}
		for _, col := range check.Columns {
			if !cols[col] {
				return errConfig
			}
		}
	}
	if v := a.SchemaVersion; v != nil {
		var value any
		if e = conn.QueryRowContext(ctx, fmt.Sprintf("SELECT MAX(`%s`) FROM `%s`", v.Column, v.Table)).Scan(&value); e != nil {
			return databaseError(e)
		}
		if value == nil {
			return errConfig
		}
		switch value.(type) {
		case int64, uint64:
		default:
			return errConfig
		}
		if fmt.Sprint(value) != fmt.Sprint(v.Expected) {
			return errConfig
		}
	}
	for _, t := range a.Tools {
		if !t.Enabled {
			continue
		}
		for _, table := range t.policy.WriteTables {
			var engine sql.NullString
			if e = conn.QueryRowContext(ctx, "SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=? AND TABLE_NAME=?", a.connection.Database, table).Scan(&engine); e != nil {
				return databaseError(e)
			}
			if !engine.Valid || engine.String != "InnoDB" {
				return errConfig
			}
		}
		e = conn.Raw(func(raw any) error {
			c, ok := raw.(driver.ConnPrepareContext)
			if !ok {
				return errConfig
			}
			stmt, e := c.PrepareContext(ctx, t.SQL)
			if e != nil {
				return databaseError(e)
			}
			defer stmt.Close()
			if stmt.NumInput() != len(t.Bindings) {
				return errConfig
			}
			tap.mu.Lock()
			defer tap.mu.Unlock()
			if tap.invalid || len(tap.infos) != len(t.Fields) {
				fmt.Fprintf(os.Stderr, "stage=metadata invalid=%t actual=%d expected=%d packets=%d params=%d columns=%d\n", tap.invalid, len(tap.infos), len(t.Fields), tap.packet, tap.params, tap.columns)
				return errConfig
			}
			for i, f := range t.Fields {
				col := f.Column
				if col == "" {
					col = f.Name
				}
				if tap.infos[i].name != col || !compatible(f, tap.infos[i].kind) {
					fmt.Fprintf(os.Stderr, "stage=column index=%d type=%d expected=%s alias_matches=%t\n", i, tap.infos[i].kind, f.Type, tap.infos[i].name == col)
					return errConfig
				}
			}
			return nil
		})
		if e != nil {
			return e
		}
	}
	return nil
}
func fieldsMetadata(t *Tool) []any {
	out := []any{}
	for _, f := range t.Fields {
		f.Column = ""
		v, _ := parseJSON(jsonBytes(f))
		out = append(out, v)
	}
	return out
}
func wireSize(value any) int {
	text := string(jsonBytes(value))
	return len(jsonBytes(map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "structuredContent": value, "isError": false})) + 512
}
func (d *database) execute(parent context.Context, a *App, t *Tool, args map[string]any) (map[string]any, error) {
	args, e := arguments(t, args)
	if e != nil {
		return nil, e
	}
	limit := 1
	if t.Kind == "query" {
		limit, e = effectiveLimit(t, args)
		if e != nil {
			return nil, e
		}
	}
	params, e := parameters(a, t, args, time.Now().UTC(), limit)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(t.TimeoutSeconds)*time.Second)
	defer cancel()
	pool := d.pools[a.ID]
	if pool == nil {
		return nil, errConfig
	}
	conn, e := pool.Conn(ctx)
	if e != nil {
		return nil, databaseError(e)
	}
	success := false
	defer func() {
		if !success {
			conn.Raw(func(any) error { return driver.ErrBadConn })
		}
		conn.Close()
	}()
	if e = session(ctx, conn, t.TimeoutSeconds); e != nil {
		return nil, e
	}
	begin := "START TRANSACTION"
	if t.Kind == "query" {
		begin += " READ ONLY"
	}
	if _, e = conn.ExecContext(ctx, begin); e != nil {
		return nil, databaseError(e)
	}
	out := map[string]any{"app_id": a.ID, "tool": a.ID + "__" + t.Name, "kind": t.Kind}
	if t.Kind == "query" {
		ranges := []any{}
		for _, r := range t.Constraints {
			start, _ := time.Parse(time.RFC3339Nano, args[r.Start].(string))
			end, _ := time.Parse(time.RFC3339Nano, args[r.End].(string))
			ranges = append(ranges, map[string]any{"start_argument": r.Start, "end_argument": r.End, "start": start.UTC().Format(time.RFC3339Nano), "end": end.UTC().Format(time.RFC3339Nano)})
		}
		data := []any{}
		out["fields"] = fieldsMetadata(t)
		out["rows"] = data
		out["row_count"] = 0
		out["limit"] = limit
		out["truncated"] = false
		out["ranges"] = ranges
		rows, e := conn.QueryContext(ctx, t.SQL, params...)
		if e != nil {
			return nil, databaseError(e)
		}
		cols, e := rows.Columns()
		if e != nil || len(cols) != len(t.Fields) {
			rows.Close()
			return nil, errType
		}
		for i, f := range t.Fields {
			col := f.Column
			if col == "" {
				col = f.Name
			}
			if cols[i] != col {
				rows.Close()
				return nil, errType
			}
		}
		skip := false
		for rows.Next() {
			if skip {
				continue
			}
			if len(data) >= limit {
				out["truncated"] = true
				skip = true
				continue
			}
			values := make([]any, len(t.Fields))
			ptrs := make([]any, len(values))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if e = rows.Scan(ptrs...); e != nil {
				rows.Close()
				return nil, errType
			}
			row := map[string]any{}
			for i, f := range t.Fields {
				v, e := convertField(f, values[i])
				if e != nil {
					rows.Close()
					return nil, e
				}
				row[f.Name] = v
			}
			data = append(data, row)
			out["rows"] = data
			out["row_count"] = len(data)
			if wireSize(out) > 1048576 {
				data = data[:len(data)-1]
				if len(data) == 0 {
					rows.Close()
					return nil, errLarge
				}
				out["rows"] = data
				out["row_count"] = len(data)
				out["truncated"] = true
				skip = true
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, databaseError(e)
		}
		if len(data) == 0 && t.EmptyResult != nil && *t.EmptyResult == "not_found" {
			return nil, errNotFound
		}
	} else {
		result, e := conn.ExecContext(ctx, t.SQL, params...)
		if e != nil {
			return nil, databaseError(e)
		}
		count, e := result.RowsAffected()
		if e != nil {
			return nil, errDB
		}
		if count < int64(t.minAffected()) || count > int64(t.maxAffected()) {
			return nil, errPrecondition
		}
		out["affected_rows"] = count
		out["last_insert_id"] = nil
		out["commit"] = "committed"
	}
	var warnings int
	if e = conn.QueryRowContext(ctx, "SHOW COUNT(*) WARNINGS").Scan(&warnings); e != nil {
		return nil, databaseError(e)
	}
	if warnings != 0 {
		return nil, errWarning
	}
	if t.Kind == "execute" && t.ReturnLastInsertID != nil && *t.ReturnLastInsertID {
		var id string
		if e = conn.QueryRowContext(ctx, "SELECT LAST_INSERT_ID()").Scan(&id); e != nil {
			return nil, databaseError(e)
		}
		if id != "0" {
			out["last_insert_id"] = id
		}
	}
	if _, e = conn.ExecContext(ctx, "COMMIT"); e != nil {
		if t.Kind == "execute" {
			return nil, errUnknown
		}
		return nil, databaseError(e)
	}
	success = true
	return out, nil
}
