package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	mysql "github.com/go-sql-driver/mysql"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func inventoryApp(t *testing.T) *App {
	t.Helper()
	b, e := os.ReadFile("../../examples/apps.d/inventory.example.json")
	if e != nil {
		t.Fatal(e)
	}
	var a App
	if e = decode(b, &a); e != nil {
		t.Fatal(e)
	}
	a.connection = Connection{Socket: "/build/tmp/mariadb-mcp-fixture/test.sock", Database: "inventory"}
	a.credentials = Credentials{"mcp_inventory", "fixture-only-password"}
	if e = a.validate(); e != nil {
		t.Fatal(e)
	}
	return &a
}
func TestDatabaseTransactions(t *testing.T) {
	a := inventoryApp(t)
	d, e := connectDatabase(context.Background(), &Registry{Apps: []*App{a}})
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	q, w := a.Tools[0], a.Tools[1]
	v, e := d.execute(context.Background(), a, q, map[string]any{"id": "7"})
	if e != nil {
		t.Fatal(e)
	}
	row := v["rows"].([]any)[0].(map[string]any)
	if row["id"] != "7" || row["price"] != "123.450000000000000000000000000000" || row["attributes"].(map[string]any)["exact"].(json.Number) != "12345678901234567890.123456789" {
		t.Fatal("precision loss")
	}
	ver := row["version"]
	args := map[string]any{"id": "7", "label": "Go transaction", "expected_version": ver}
	v, e = d.execute(context.Background(), a, w, args)
	if e != nil || v["commit"] != "committed" {
		t.Fatal(v, e)
	}
	if _, e = d.execute(context.Background(), a, w, args); e == nil || e.Error() != "write_precondition_failed" {
		t.Fatal("stale write accepted", e)
	}
}
func TestGrantEquality(t *testing.T) {
	a := &App{Grants: []GrantConfig{{"items", []string{"SELECT"}}}, connection: Connection{Database: "inventory"}}
	if e := checkGrants(a, []string{"GRANT USAGE ON *.* TO test", "GRANT SELECT ON `inventory`.`items` TO test"}); e != nil {
		t.Fatal(e)
	}
	for _, g := range []string{"GRANT SELECT ON `inventory`.* TO test", "GRANT ALL PRIVILEGES ON *.* TO test", "GRANT SELECT ON `inventory`.`items` TO test WITH GRANT OPTION", "GRANT SELECT (id) ON `inventory`.`items` TO test"} {
		if e := checkGrants(a, []string{g}); e == nil {
			t.Fatal("excess privileges")
		}
	}
}
func TestDBErrorRedaction(t *testing.T) {
	if e := databaseError(errors.New("password=secret SQL sensitive")); e.Error() != "database_unavailable" {
		t.Fatal(e)
	}
}
func TestNativeTypes(t *testing.T) {
	cases := []struct {
		name, kind, cast string
		input, expected  any
	}{
		{"text", "string", "CHAR", "Hello", "Hello"}, {"whole", "integer", "SIGNED", json.Number("12"), int64(12)}, {"large", "bigint", "UNSIGNED", "18446744073709551615", "18446744073709551615"}, {"exact", "decimal", "DECIMAL(65,30)", "123.4500", "123.450000000000000000000000000000"}, {"approx", "number", "DOUBLE", json.Number("1.25"), json.Number("1.25")}, {"flag", "boolean", "SIGNED", true, true}, {"day", "date", "DATE", "2026-10-12", "2026-10-12"}, {"wall", "datetime", "DATETIME(6)", "2026-10-12T10:20:30.123456", "2026-10-12T10:20:30.123456"}, {"utc", "timestamp", "DATETIME(6)", "2026-10-12T12:20:30.123456+02:00", "2026-10-12T10:20:30.123456Z"}, {"clock", "time", "TIME(6)", "12:34:56.123456", "12:34:56.123456"}, {"span", "duration", "TIME(6)", "-125:05:06.123456", "-125:05:06.123456"}, {"payload", "json", "CHAR", map[string]any{"exact": json.Number("12345678901234567890.123456789")}, map[string]any{"exact": json.Number("12345678901234567890.123456789")}}, {"bytes", "binary", "BINARY", "AP8N", "AP8N"}}
	app := inventoryApp(t)
	tool := &Tool{Name: "all_types", Description: "Native types", Enabled: true, Kind: "query", TimeoutSeconds: 5}
	props := map[string]any{}
	required := []any{}
	args := map[string]any{}
	selects := []string{}
	for _, c := range cases {
		kind := "string"
		if c.kind == "integer" || c.kind == "number" || c.kind == "boolean" {
			kind = c.kind
		}
		if c.kind == "json" {
			kind = "object"
		}
		props[c.name] = map[string]any{"type": kind}
		required = append(required, c.name)
		args[c.name] = c.input
		selects = append(selects, "CAST(? AS "+c.cast+") AS "+c.name)
		tool.Bindings = append(tool.Bindings, Binding{Source: "argument", Name: c.name, DBType: c.kind})
		tool.Fields = append(tool.Fields, Field{Name: c.name, Type: c.kind})
	}
	tool.InputSchema = map[string]any{"type": "object", "properties": props, "required": required, "additionalProperties": false}
	tool.SQL = "SELECT " + strings.Join(selects, ",") + " ORDER BY text LIMIT ?"
	tool.Bindings = append(tool.Bindings, Binding{Source: "runtime", Name: "fetch_limit", DBType: "integer"})
	app.Tools = []*Tool{tool}
	if e := app.validate(); e != nil {
		t.Fatal(e)
	}
	db, e := connectDatabase(context.Background(), &Registry{Apps: []*App{app}})
	if e != nil {
		t.Fatal(e)
	}
	defer db.close()
	v, e := db.execute(context.Background(), app, tool, args)
	if e != nil {
		t.Fatal(e)
	}
	row := v["rows"].([]any)[0].(map[string]any)
	for _, c := range cases {
		if !reflect.DeepEqual(row[c.name], c.expected) {
			t.Fatalf("%s: %v != %v", c.name, row[c.name], c.expected)
		}
	}
}
func fixtureAdmin(t *testing.T) *sql.DB {
	t.Helper()
	cfg := mysql.NewConfig()
	cfg.Net = "unix"
	cfg.Addr = "/build/tmp/mariadb-mcp-fixture/test.sock"
	cfg.User = "root"
	db, e := sql.Open("mysql", cfg.FormatDSN())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
func adminExec(t *testing.T, db *sql.DB, sqlText string) {
	t.Helper()
	if _, e := db.Exec(sqlText); e != nil {
		t.Fatal("fixture SQL failed")
	}
}
func TestRollbackConcurrencyDeadline(t *testing.T) {
	admin := fixtureAdmin(t)
	for _, id := range []int{2000, 2001, 2002} {
		adminExec(t, admin, fmt.Sprintf("INSERT INTO inventory.items VALUES(%d,'Before',1,NULL,'2026-10-12',1) ON DUPLICATE KEY UPDATE label='Before',version=1", id))
	}
	a := inventoryApp(t)
	db, e := connectDatabase(context.Background(), &Registry{Apps: []*App{a}})
	if e != nil {
		t.Fatal(e)
	}
	defer db.close()
	w := *a.Tools[1]
	w.SQL = "UPDATE items SET label=?,version=version+1,updated_at=? WHERE id>=? AND id<=2001 AND version=?"
	w.policy, e = validateSQL(a, &w)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.execute(context.Background(), a, &w, map[string]any{"id": "2000", "label": "Overflow", "expected_version": json.Number("1")})
	if e != errPrecondition {
		t.Fatal(e)
	}
	var count int
	admin.QueryRow("SELECT COUNT(*) FROM inventory.items WHERE id IN(2000,2001) AND label='Before' AND version=1").Scan(&count)
	if count != 2 {
		t.Fatal("rollback failed")
	}
	results := make(chan error, 2)
	for _, label := range []string{"A", "B"} {
		go func(label string) {
			_, e := db.execute(context.Background(), a, a.Tools[1], map[string]any{"id": "2000", "label": label, "expected_version": json.Number("1")})
			results <- e
		}(label)
	}
	e1, e2 := <-results, <-results
	if !(e1 == nil && e2 == errPrecondition || e2 == nil && e1 == errPrecondition) {
		t.Fatal("concurrency", e1, e2)
	}
	tx, e := admin.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE inventory.items SET label='Locked' WHERE id=2002"); e != nil {
		t.Fatal(e)
	}
	blocked := *a.Tools[1]
	blocked.TimeoutSeconds = 1
	start := time.Now()
	_, e = db.execute(context.Background(), a, &blocked, map[string]any{"id": "2002", "label": "Timed out", "expected_version": json.Number("1")})
	if e != errTimeout || time.Since(start) > 2*time.Second {
		t.Fatal("deadline", e)
	}
	tx.Rollback()
	var label string
	admin.QueryRow("SELECT label FROM inventory.items WHERE id=2002").Scan(&label)
	if label != "Before" {
		t.Fatal("timed out write persisted")
	}
}
func TestQueryCapsWarningsMetadata(t *testing.T) {
	a := inventoryApp(t)
	db, e := connectDatabase(context.Background(), &Registry{Apps: []*App{a}})
	if e != nil {
		t.Fatal(e)
	}
	defer db.close()
	for _, c := range []struct {
		sql  string
		want error
	}{{"SELECT CAST(REPEAT('x',600000) AS CHAR) AS label ORDER BY label LIMIT ?", errLarge}, {"SELECT CAST(1/0 AS CHAR) AS label ORDER BY label LIMIT ?", errWarning}} {
		tool := &Tool{Name: "query", Kind: "query", TimeoutSeconds: 5, InputSchema: map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}, SQL: c.sql, Bindings: []Binding{{Source: "runtime", Name: "fetch_limit", DBType: "integer"}}, Fields: []Field{{Name: "label", Type: "string", Nullable: true}}}
		tool.validator, _ = compileSchema(tool.InputSchema, true)
		tool.policy, e = validateSQL(a, tool)
		if e != nil {
			t.Fatal(e)
		}
		_, e = db.execute(context.Background(), a, tool, map[string]any{})
		if e != c.want {
			t.Fatal("cap/warning", e, c.want)
		}
	}
	bad := *a.Tools[0]
	bad.Fields = append([]Field{}, bad.Fields...)
	bad.Fields[1].Type = "date"
	a.Tools = []*Tool{&bad}
	if e = checkApp(context.Background(), a); e == nil {
		t.Fatal("metadata mismatch ignored")
	}
}
func TestInsertUpsertDeleteAndEngine(t *testing.T) {
	admin := fixtureAdmin(t)
	adminExec(t, admin, "CREATE USER IF NOT EXISTS 'mcp_dml'@'localhost' IDENTIFIED BY 'fixture-only-password'")
	adminExec(t, admin, "GRANT SELECT,INSERT,UPDATE,DELETE ON inventory.items TO 'mcp_dml'@'localhost'")
	adminExec(t, admin, "DELETE FROM inventory.items WHERE id=3000")
	a := inventoryApp(t)
	a.User = "mcp_dml"
	a.credentials.Username = "mcp_dml"
	a.Grants[0].Privileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE"}
	insert := *a.Tools[1]
	insert.SQL = "INSERT INTO items(label,updated_at,id,version,price) VALUES(?,?,?,?,1) ON DUPLICATE KEY UPDATE label=VALUES(label)"
	max := 2
	insert.MaxAffectedRows = &max
	insert.policy, _ = validateSQL(a, &insert)
	db, e := connectDatabase(context.Background(), &Registry{Apps: []*App{a}})
	if e != nil {
		t.Fatal(e)
	}
	defer db.close()
	args := map[string]any{"id": "3000", "label": "Insert", "expected_version": json.Number("1")}
	v, e := db.execute(context.Background(), a, &insert, args)
	if e != nil || v["affected_rows"] != int64(1) {
		t.Fatal(v, e)
	}
	args["label"] = "Upsert"
	v, e = db.execute(context.Background(), a, &insert, args)
	if e != nil || v["affected_rows"] != int64(2) {
		t.Fatal(v, e)
	}
	del := *a.Tools[1]
	del.SQL = "DELETE FROM items WHERE id=?"
	del.Bindings = []Binding{del.Bindings[2]}
	del.policy, _ = validateSQL(a, &del)
	v, e = db.execute(context.Background(), a, &del, args)
	if e != nil || v["affected_rows"] != int64(1) {
		t.Fatal(v, e)
	}
	adminExec(t, admin, "CREATE TABLE IF NOT EXISTS inventory.go_nontransactional LIKE inventory.items")
	adminExec(t, admin, "ALTER TABLE inventory.go_nontransactional ENGINE=MyISAM")
	adminExec(t, admin, "CREATE USER IF NOT EXISTS 'mcp_go_myisam'@'localhost' IDENTIFIED BY 'fixture-only-password'")
	adminExec(t, admin, "GRANT SELECT,UPDATE ON inventory.go_nontransactional TO 'mcp_go_myisam'@'localhost'")
	a.User = "mcp_go_myisam"
	a.credentials.Username = a.User
	a.Grants = []GrantConfig{{"go_nontransactional", []string{"SELECT", "UPDATE"}}}
	a.SchemaChecks = nil
	bad := *a.Tools[1]
	bad.SQL = strings.ReplaceAll(bad.SQL, "items", "go_nontransactional")
	bad.policy, _ = validateSQL(a, &bad)
	a.Tools = []*Tool{&bad}
	if e = checkApp(context.Background(), a); e == nil {
		t.Fatal("nontransactional write allowed")
	}
}
