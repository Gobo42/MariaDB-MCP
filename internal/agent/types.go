package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const safeInteger int64 = 9007199254740991

var plainInt = regexp.MustCompile("^(0|-?[1-9][0-9]*)$")
var plainDecimal = regexp.MustCompile("^-?(0|[1-9][0-9]*)([.][0-9]+)?$")
var timeRE = regexp.MustCompile("^(-?)([0-9]+):([0-9]{2}):([0-9]{2})([.][0-9]{1,6})?$")
var dateRE = regexp.MustCompile("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
var datetimeRE = regexp.MustCompile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?$")
var timestampRE = regexp.MustCompile("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})$")

func bindValue(k string, v any, nullable bool) (any, error) {
	if v == nil {
		if nullable {
			return nil, nil
		}
		return nil, errArgs
	}
	s, isString := v.(string)
	switch k {
	case "string":
		if isString && utf8.ValidString(s) {
			return s, nil
		}
	case "integer":
		n, ok := asNumber(v)
		if !ok || len(n) > 128 {
			return nil, errArgs
		}
		r, ok := new(big.Rat).SetString(string(n))
		if !ok || !r.IsInt() || !r.Num().IsInt64() {
			return nil, errArgs
		}
		i := r.Num().Int64()
		if i >= -safeInteger && i <= safeInteger {
			return i, nil
		}
	case "bigint":
		if isString && plainInt.MatchString(s) {
			z, ok := new(big.Int).SetString(s, 10)
			if ok && (z.Sign() < 0 && z.IsInt64() || z.Sign() >= 0 && z.BitLen() <= 64) {
				return s, nil
			}
		}
	case "decimal":
		if isString && plainDecimal.MatchString(s) {
			return s, nil
		}
	case "number":
		if n, ok := asNumber(v); ok {
			f, e := strconv.ParseFloat(string(n), 64)
			if e == nil && !math.IsInf(f, 0) && !math.IsNaN(f) {
				return f, nil
			}
		}
	case "boolean":
		if b, ok := v.(bool); ok {
			if b {
				return int64(1), nil
			}
			return int64(0), nil
		}
	case "date", "datetime", "timestamp":
		if !isString {
			return nil, errArgs
		}
		layout := "2006-01-02"
		re := dateRE
		if k == "datetime" {
			layout = "2006-01-02T15:04:05.999999"
			re = datetimeRE
		}
		if k == "timestamp" {
			layout = time.RFC3339Nano
			re = timestampRE
		}
		if !re.MatchString(s) {
			return nil, errArgs
		}
		if k == "timestamp" && !strings.HasSuffix(s, "Z") {
			zone := s[len(s)-6:]
			h, _ := strconv.Atoi(zone[1:3])
			m, _ := strconv.Atoi(zone[4:])
			if h > 23 || m > 59 {
				return nil, errArgs
			}
		}
		dt, e := time.Parse(layout, s)
		if e != nil || dt.Year() < 1000 || dt.Year() > 9999 {
			return nil, errArgs
		}
		if k == "date" {
			return s, nil
		}
		if k == "timestamp" {
			dt = dt.UTC()
			if dt.Year() < 1000 || dt.Year() > 9999 {
				return nil, errArgs
			}
		}
		return dt.Format("2006-01-02 15:04:05.999999"), nil
	case "time", "duration":
		if isString {
			m := timeRE.FindStringSubmatch(s)
			if m != nil {
				h, e := strconv.Atoi(m[2])
				mi, _ := strconv.Atoi(m[3])
				sec, _ := strconv.Atoi(m[4])
				if e == nil && mi < 60 && sec < 60 && (k == "duration" && h <= 838 || k == "time" && m[1] == "" && len(m[2]) == 2 && h < 24) {
					return s, nil
				}
			}
		}
	case "json":
		b, e := json.Marshal(v)
		if e == nil {
			if _, e = parseJSON(b); e == nil {
				return string(b), nil
			}
		}
	case "binary":
		if isString {
			b, e := base64.StdEncoding.DecodeString(s)
			if e == nil && base64.StdEncoding.EncodeToString(b) == s {
				return b, nil
			}
		}
	}
	return nil, errArgs
}
func convertField(f Field, v any) (any, error) {
	if v == nil {
		if f.Nullable {
			return nil, nil
		}
		return nil, errType
	}
	var out any
	var e error
	s := ""
	if b, ok := v.([]byte); ok {
		if f.Type != "binary" && !utf8.Valid(b) {
			return nil, errType
		}
		s = string(b)
	} else if b, ok := v.(string); ok {
		s = b
	} else {
		s = fmt.Sprint(v)
	}
	switch f.Type {
	case "string":
		switch v.(type) {
		case string, []byte:
			out = s
		default:
			return nil, errType
		}
	case "binary":
		b, ok := v.([]byte)
		if !ok {
			return nil, errType
		}
		out = base64.StdEncoding.EncodeToString(b)
	case "json":
		out, e = parseJSON([]byte(s))
	case "decimal", "bigint":
		_, e = bindValue(f.Type, s, false)
		out = s
	case "integer":
		out, e = bindValue("integer", json.Number(s), false)
	case "number":
		_, e = bindValue("number", json.Number(s), false)
		out = json.Number(s)
	case "boolean":
		if s == "0" {
			out = false
		} else if s == "1" {
			out = true
		} else {
			e = errType
		}
	case "date", "datetime", "timestamp":
		raw := strings.Replace(s, " ", "T", 1)
		if f.Type == "timestamp" {
			raw += "Z"
		}
		_, e = bindValue(f.Type, raw, false)
		if e == nil {
			if f.Type == "date" {
				out = raw
			} else {
				layout := "2006-01-02T15:04:05.999999"
				if f.Type == "timestamp" {
					layout = time.RFC3339Nano
				}
				dt, er := time.Parse(layout, raw)
				e = er
				out = dt.Format(layout)
			}
		}
	case "time", "duration":
		_, e = bindValue(f.Type, s, false)
		if e == nil {
			m := timeRE.FindStringSubmatch(s)
			h, _ := strconv.Atoi(m[2])
			out = fmt.Sprintf("%s%02d:%s:%s%s", m[1], h, m[3], m[4], strings.TrimRight(m[5], "0"))
			if strings.HasSuffix(out.(string), ".") {
				out = strings.TrimSuffix(out.(string), ".")
			}
		}
	default:
		e = errType
	}
	if e != nil {
		return nil, errType
	}
	if f.JSONSchema != nil {
		sch, e := compileSchema(f.JSONSchema, false)
		if e != nil || sch.Validate(out) != nil {
			return nil, errType
		}
	}
	return out, nil
}
func parameters(a *App, t *Tool, args map[string]any, now time.Time, limit int) ([]any, error) {
	out := []any{}
	for _, b := range t.Bindings {
		var v any
		switch b.Source {
		case "argument":
			v = args[b.Name]
		case "constant":
			v = a.Constants[b.Name]
		case "runtime":
			if b.Name == "now_utc" {
				v = now.UTC().Truncate(time.Microsecond).Format("2006-01-02T15:04:05.000000Z")
			} else if b.Name == "fetch_limit" {
				v = json.Number(strconv.Itoa(limit + 1))
			} else {
				return nil, errArgs
			}
		}
		val, e := bindValue(b.DBType, v, b.Nullable)
		if e != nil {
			return nil, e
		}
		out = append(out, val)
	}
	return out, nil
}
