package agent

import (
	"os"
	"testing"
)

func queryFixture(s string) (*App, *Tool) {
	return &App{Grants: []GrantConfig{{"sensors", []string{"SELECT"}}, {"measurements", []string{"SELECT"}}}}, &Tool{Kind: "query", SQL: s, Fields: []Field{{Name: "id", Type: "string"}, {Name: "name", Type: "string"}}, Bindings: []Binding{{Source: "runtime", Name: "fetch_limit", DBType: "integer"}}}
}
func TestSQLPolicy(t *testing.T) {
	for _, s := range []string{"SELECT id,name FROM sensors ORDER BY id LIMIT ?", "WITH latest AS (SELECT id,name FROM sensors) SELECT id,name FROM latest ORDER BY id LIMIT ?", "SELECT '?' AS id,'/*!literal*/' AS name FROM sensors ORDER BY id LIMIT ?", "SELECT CAST(COUNT(*) AS CHAR) AS id,'count' AS name FROM sensors ORDER BY id LIMIT ?"} {
		a, q := queryFixture(s)
		if _, e := validateSQL(a, q); e != nil {
			t.Fatal(s, e)
		}
	}
	for _, s := range []string{"SELECT * FROM sensors ORDER BY id LIMIT ?", "SELECT id,name FROM sensors;DELETE FROM sensors", "SELECT id,name FROM sensors LIMIT ?", "SELECT id,name FROM sensors ORDER BY id LIMIT 10", "SELECT id,name FROM sensors ORDER BY id LIMIT ? OFFSET 0", "SELECT id,name FROM other ORDER BY id LIMIT ?", "SELECT id,name FROM mysql.user ORDER BY id LIMIT ?", "SELECT id,name FROM sensors ORDER BY id LIMIT ? FOR UPDATE", "SELECT secret_udf(id) AS id,name FROM sensors ORDER BY id LIMIT ?", "SELECT id,name FROM sensors /*!50000 INTO OUTFILE '/tmp/bad' */ ORDER BY id LIMIT ?", "SELECT id,name FROM sensors /*M! INTO OUTFILE '/tmp/bad' */ ORDER BY id LIMIT ?", "SELECT id,name FROM sensors WHERE id IN(SELECT * FROM measurements) ORDER BY id LIMIT ?", "SELECT id,name FROM sensors WHERE id IN(WITH other AS(SELECT id FROM measurements) SELECT id FROM other) AND id IN(SELECT id FROM other) ORDER BY id LIMIT ?"} {
		a, q := queryFixture(s)
		if _, e := validateSQL(a, q); e == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestExistingApps(t *testing.T) {
	for _, p := range []string{"../../tests/fixtures/tapo-app.json", "../../examples/apps.d/inventory.example.json"} {
		b, e := os.ReadFile(p)
		if e != nil {
			t.Fatal(e)
		}
		var a App
		if e = decode(b, &a); e != nil {
			t.Fatal(e)
		}
		if e = a.validate(); e != nil {
			t.Fatal(p, e)
		}
	}
}
