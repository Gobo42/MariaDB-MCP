package agent

import (
	"encoding/json"
	js "github.com/santhosh-tekuri/jsonschema/v6"
	"strings"
	"time"
)

func supportedSchema(s map[string]any, depth int) error {
	if depth >= 32 {
		return errConfig
	}
	allowed := " type properties required additionalProperties minProperties maxProperties items minItems maxItems uniqueItems minLength maxLength pattern format minimum maximum exclusiveMinimum exclusiveMaximum multipleOf enum const title description default examples $schema "
	for k := range s {
		if !strings.Contains(allowed, " "+k+" ") {
			return errConfig
		}
	}
	if v, ok := s["$schema"]; ok && v != "https://json-schema.org/draft/2020-12/schema" {
		return errConfig
	}
	if v, ok := s["type"]; ok {
		valid := func(v any) bool {
			s, ok := v.(string)
			return ok && strings.Contains(" object array string integer number boolean null ", " "+s+" ")
		}
		switch v := v.(type) {
		case string:
			if !valid(v) {
				return errConfig
			}
		case []any:
			if len(v) != 2 || !valid(v[0]) || !valid(v[1]) || (v[0] == "null") == (v[1] == "null") {
				return errConfig
			}
		default:
			return errConfig
		}
	}
	if v, ok := s["format"]; ok {
		if str, ok := v.(string); !ok || !strings.Contains(" date time date-time uuid ", " "+str+" ") {
			return errConfig
		}
	}
	if p, ok := s["pattern"].(string); ok {
		for _, bad := range []string{"(?P", "(?i", "(?m", "(?s", "(?x", "(?>", "(?#", "\\A", "\\z"} {
			if strings.Contains(p, bad) {
				return errConfig
			}
		}
	}
	if p, ok := s["properties"]; ok {
		o, ok := p.(map[string]any)
		if !ok {
			return errConfig
		}
		for _, v := range o {
			m, ok := v.(map[string]any)
			if !ok {
				return errConfig
			}
			if e := supportedSchema(m, depth+1); e != nil {
				return e
			}
		}
	}
	for _, k := range []string{"items", "additionalProperties"} {
		if v, ok := s[k]; ok {
			if _, ok := v.(bool); ok && k == "additionalProperties" {
				continue
			}
			m, ok := v.(map[string]any)
			if !ok {
				return errConfig
			}
			if e := supportedSchema(m, depth+1); e != nil {
				return e
			}
		}
	}
	return nil
}
func compileSchema(s map[string]any, input bool) (*js.Schema, error) {
	if s == nil {
		return nil, errConfig
	}
	if _, e := parseJSON(jsonBytes(s)); e != nil {
		return nil, e
	}
	if e := supportedSchema(s, 0); e != nil {
		return nil, e
	}
	if input {
		p, ok := s["properties"].(map[string]any)
		if !ok || s["type"] != "object" || s["additionalProperties"] != false {
			return nil, errConfig
		}
		for k := range p {
			if !identifier(k, 64) {
				return nil, errConfig
			}
		}
		if v, ok := s["required"]; ok {
			a, ok := v.([]any)
			if !ok {
				return nil, errConfig
			}
			for _, k := range a {
				n, ok := k.(string)
				if !ok {
					return nil, errConfig
				}
				if _, ok = p[n]; !ok {
					return nil, errConfig
				}
			}
		}
	}
	c := js.NewCompiler()
	c.DefaultDraft(js.Draft2020)
	c.AssertFormat()
	if e := c.AddResource("urn:mariadb-mcp:schema", s); e != nil {
		return nil, errConfig
	}
	v, e := c.Compile("urn:mariadb-mcp:schema")
	if e != nil {
		return nil, errConfig
	}
	if d, ok := s["default"]; ok && v.Validate(d) != nil {
		return nil, errConfig
	}
	for _, key := range []string{"properties", "items", "additionalProperties"} {
		if key == "properties" {
			if props, ok := s[key].(map[string]any); ok {
				for _, p := range props {
					if _, e := compileSchema(p.(map[string]any), false); e != nil {
						return nil, e
					}
				}
			}
		} else if m, ok := s[key].(map[string]any); ok {
			if _, e := compileSchema(m, false); e != nil {
				return nil, e
			}
		}
	}
	return v, nil
}
func effectiveLimit(t *Tool, args map[string]any) (int, error) {
	n := t.defaultLimit()
	if t.LimitArgument != nil {
		if v, ok := args[*t.LimitArgument]; ok {
			b, e := bindValue("integer", v, false)
			if e != nil {
				return 0, e
			}
			n = int(b.(int64))
		}
	}
	if n < 1 || n > t.maxRows() {
		return 0, errArgs
	}
	return n, nil
}
func arguments(t *Tool, args map[string]any) (map[string]any, error) {
	if args == nil {
		args = map[string]any{}
	}
	if _, e := parseJSON(jsonBytes(args)); e != nil {
		return nil, errArgs
	}
	result := map[string]any{}
	for k, v := range args {
		result[k] = v
	}
	req, _ := t.InputSchema["required"].([]any)
	props, _ := t.InputSchema["properties"].(map[string]any)
	for k, p := range props {
		m := p.(map[string]any)
		if _, ok := result[k]; !ok && !hasAny(req, k) {
			if d, ok := m["default"]; ok {
				result[k] = d
			}
		}
	}
	if t.validator == nil || t.validator.Validate(result) != nil {
		return nil, errArgs
	}
	for _, b := range t.Bindings {
		if b.Source == "argument" && !b.Nullable && result[b.Name] == nil {
			return nil, errArgs
		}
	}
	for _, r := range t.Constraints {
		s, ok := result[r.Start].(string)
		if !ok {
			return nil, errArgs
		}
		e, ok := result[r.End].(string)
		if !ok {
			return nil, errArgs
		}
		start, er := time.Parse(time.RFC3339Nano, s)
		if er != nil {
			return nil, errArgs
		}
		end, er := time.Parse(time.RFC3339Nano, e)
		if er != nil || !end.After(start) || end.Sub(start).Seconds() > float64(r.MaxSeconds) {
			return nil, errArgs
		}
	}
	if t.Kind == "query" {
		if _, e := effectiveLimit(t, result); e != nil {
			return nil, e
		}
	}
	return result, nil
}
func asNumber(v any) (json.Number, bool) {
	switch v := v.(type) {
	case json.Number:
		return v, true
	case int:
		return json.Number(strings.TrimSpace(string(jsonBytes(v)))), true
	case int64, uint64, float64, float32:
		return json.Number(string(jsonBytes(v))), true
	}
	return "", false
}
