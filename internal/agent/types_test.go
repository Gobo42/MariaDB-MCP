package agent

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestTypes(t *testing.T) {
	cases := []struct {
		k   string
		in  any
		out any
	}{{"integer", json.Number("9007199254740991"), int64(9007199254740991)}, {"integer", json.Number("1.20e1"), int64(12)}, {"bigint", "18446744073709551615", "18446744073709551615"}, {"decimal", "-0.0012300", "-0.0012300"}, {"timestamp", "2026-10-12T12:00:00.123456+02:00", "2026-10-12 10:00:00.123456"}, {"datetime", "2026-10-12T12:00:00.1", "2026-10-12 12:00:00.1"}, {"date", "2024-02-29", "2024-02-29"}, {"duration", "-838:59:59.999999", "-838:59:59.999999"}, {"time", "23:59:59.1", "23:59:59.1"}, {"boolean", true, int64(1)}, {"binary", "AP8=", []byte{0, 255}}, {"string", "hello", "hello"}}
	for _, c := range cases {
		v, e := bindValue(c.k, c.in, false)
		if e != nil || !reflect.DeepEqual(v, c.out) {
			t.Fatalf("%s: %v %v", c.k, v, e)
		}
	}
	for _, c := range []struct {
		k  string
		in any
	}{{"integer", json.Number("9007199254740992")}, {"integer", json.Number("1.1")}, {"bigint", "18446744073709551616"}, {"bigint", "-0"}, {"decimal", "01.0"}, {"date", "2023-02-29"}, {"timestamp", "2026-01-01T00:00:00.1234567Z"}, {"time", "24:00:00"}, {"duration", "839:00:00"}, {"binary", "AP8"}, {"integer", nil}} {
		if _, e := bindValue(c.k, c.in, false); e == nil {
			t.Fatal("accepted", c)
		}
	}
	f := Field{Name: "payload", Type: "json"}
	v, e := convertField(f, []byte(`{"n":900719925474099312345,"x":null}`))
	if e != nil || v.(map[string]any)["n"].(json.Number).String() != "900719925474099312345" {
		t.Fatal(v, e)
	}
	f.JSONSchema = map[string]any{"type": "object"}
	if _, e = convertField(f, []byte("null")); e == nil {
		t.Fatal("JSON null skipped schema")
	}
	f.Nullable = true
	if v, e = convertField(f, nil); e != nil || v != nil {
		t.Fatal(v, e)
	}
}
func TestSchemaDefaults(t *testing.T) {
	s := map[string]any{"type": "object", "properties": map[string]any{"required": map[string]any{"type": "string", "default": "x"}, "optional": map[string]any{"type": "integer", "default": json.Number("2")}}, "required": []any{"required"}, "additionalProperties": false}
	c, e := compileSchema(s, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = arguments(&Tool{InputSchema: s, validator: c}, map[string]any{}); e == nil {
		t.Fatal("default bypassed required")
	}
	v, e := arguments(&Tool{InputSchema: s, validator: c}, map[string]any{"required": "ok"})
	if e != nil || v["optional"] != json.Number("2") {
		t.Fatal(v, e)
	}
	for _, bad := range []map[string]any{{"$ref": "https://invalid.test"}, {"pattern": "(?i)test"}, {"format": "email"}, {"type": []any{"string", "number"}}} {
		if _, e = compileSchema(bad, false); e == nil {
			t.Fatal("accepted unsupported", bad)
		}
	}
}
func TestTimestampRejectsInvalidOffset(t *testing.T) {
	for _, v := range []string{"2026-01-01T00:00:00+24:00", "2026-01-01T00:00:00+00:60"} {
		if _, e := bindValue("timestamp", v, false); e == nil {
			t.Fatal("invalid offset accepted")
		}
	}
}
