package agent

import (
	sp "github.com/dolthub/vitess/go/vt/sqlparser"
	"reflect"
	"strings"
)

type SQLPolicy struct {
	ReadTables, WriteTables, Aliases []string
	Parameters                       int
}

func lexicalSQL(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case 39, 34, 96:
			q := s[i]
			closed := false
			for i++; i < len(s); i++ {
				if s[i] == 92 && q != 96 {
					i++
					continue
				}
				if s[i] == q {
					if i+1 < len(s) && s[i+1] == q {
						i++
						continue
					}
					closed = true
					break
				}
			}
			if !closed {
				return 0, errConfig
			}
		case 47:
			if i+1 < len(s) && s[i+1] == 42 {
				if strings.HasPrefix(s[i+2:], "!") || strings.HasPrefix(s[i+2:], "M!") {
					return 0, errConfig
				}
				end := strings.Index(s[i+2:], "*/")
				if end < 0 {
					return 0, errConfig
				}
				i += end + 3
			}
		case 45:
			if i+2 < len(s) && s[i+1] == 45 && s[i+2] <= 32 {
				for i < len(s) && s[i] != 10 {
					i++
				}
			}
		case 35:
			for i < len(s) && s[i] != 10 {
				i++
			}
		case 64:
			return 0, errConfig
		case 58:
			if i+1 < len(s) && (s[i+1] == 61 || s[i+1] >= 65 && s[i+1] <= 122) {
				return 0, errConfig
			}
		case 63:
			n++
		}
	}
	return n, nil
}
func tableName(t sp.TableName) (string, error) {
	if !t.DbQualifier.IsEmpty() || !t.SchemaQualifier.IsEmpty() || !sqlIdentifier(t.Name.String()) {
		return "", errConfig
	}
	return t.Name.String(), nil
}
func writeTable(ts sp.TableExprs) (string, error) {
	if len(ts) != 1 {
		return "", errConfig
	}
	a, ok := ts[0].(*sp.AliasedTableExpr)
	if !ok {
		return "", errConfig
	}
	n, ok := a.Expr.(sp.TableName)
	if !ok {
		return "", errConfig
	}
	return tableName(n)
}
func projection(q sp.SelectStatement) ([]string, error) {
	switch q := q.(type) {
	case *sp.Select:
		out := []string{}
		for _, item := range q.SelectExprs {
			a, ok := item.(*sp.AliasedExpr)
			if !ok {
				return nil, errConfig
			}
			n := a.As.String()
			if n == "" {
				c, ok := a.Expr.(*sp.ColName)
				if !ok {
					return nil, errConfig
				}
				n = c.Name.String()
			}
			out = append(out, n)
		}
		return out, nil
	case *sp.ParenSelect:
		return projection(q.Select)
	case *sp.SetOp:
		a, e := projection(q.Left)
		if e != nil {
			return nil, e
		}
		b, e := projection(q.Right)
		if e != nil || !reflect.DeepEqual(a, b) {
			return nil, errConfig
		}
		return a, nil
	}
	return nil, errConfig
}
func queryParts(q sp.SelectStatement) (*sp.With, *sp.Limit, sp.OrderBy, error) {
	switch q := q.(type) {
	case *sp.Select:
		if q.Into != nil || q.Lock != nil && q.Lock.Type != "" {
			return nil, nil, nil, errConfig
		}
		return q.With, q.Limit, q.OrderBy, nil
	case *sp.SetOp:
		if q.Into != nil || q.Lock != nil && q.Lock.Type != "" {
			return nil, nil, nil, errConfig
		}
		return q.With, q.Limit, q.OrderBy, nil
	case *sp.ParenSelect:
		return queryParts(q.Select)
	}
	return nil, nil, nil, errConfig
}
func validateSQL(a *App, t *Tool) (*SQLPolicy, error) {
	n, e := lexicalSQL(t.SQL)
	if e != nil || n != len(t.Bindings) {
		return nil, errConfig
	}
	stmt, e := sp.Parse(t.SQL)
	if e != nil {
		return nil, errConfig
	}
	p := &SQLPolicy{Parameters: n}
	writes := map[string]bool{}
	reads := map[string]bool{}
	switch s := stmt.(type) {
	case sp.SelectStatement:
		if t.Kind != "query" {
			return nil, errConfig
		}
		_, lim, order, e := queryParts(s)
		if e != nil || lim == nil || lim.Offset != nil || len(order) == 0 {
			return nil, errConfig
		}
		v, ok := lim.Rowcount.(*sp.SQLVal)
		if !ok || v.Type != sp.ValArg {
			return nil, errConfig
		}
		if n == 0 || t.Bindings[n-1].Source != "runtime" || t.Bindings[n-1].Name != "fetch_limit" {
			return nil, errConfig
		}
		p.Aliases, e = projection(s)
		if e != nil || len(p.Aliases) != len(t.Fields) {
			return nil, errConfig
		}
		for i, f := range t.Fields {
			col := f.Column
			if col == "" {
				col = f.Name
			}
			if p.Aliases[i] != col {
				return nil, errConfig
			}
		}
	case *sp.Insert:
		if t.Kind != "execute" || a.Access != "read_write" || s.Action == sp.ReplaceStr || s.Ignore != "" || len(s.Returning) > 0 || len(s.ConflictTarget) > 0 {
			return nil, errConfig
		}
		target, e := tableName(s.Table)
		if e != nil || !a.allowed(target, "INSERT") || len(s.OnDup) > 0 && !a.allowed(target, "UPDATE") {
			return nil, errConfig
		}
		writes[target] = true
	case *sp.Update:
		if t.Kind != "execute" || a.Access != "read_write" || s.Where == nil || s.Ignore != "" || len(s.Returning) > 0 || t.ReturnLastInsertID != nil {
			return nil, errConfig
		}
		target, e := writeTable(s.TableExprs)
		if e != nil || !a.allowed(target, "UPDATE") {
			return nil, errConfig
		}
		writes[target] = true
	case *sp.Delete:
		if t.Kind != "execute" || a.Access != "read_write" || s.Where == nil || len(s.Targets) > 0 || len(s.Returning) > 0 || t.ReturnLastInsertID != nil {
			return nil, errConfig
		}
		target, e := writeTable(s.TableExprs)
		if e != nil || !a.allowed(target, "DELETE") {
			return nil, errConfig
		}
		writes[target] = true
	default:
		return nil, errConfig
	}
	var walk func(sp.SQLNode, map[string]bool, int) error
	walk = func(node sp.SQLNode, scope map[string]bool, depth int) error {
		if depth > 32 {
			return errConfig
		}
		return sp.Walk(func(node sp.SQLNode) (bool, error) {
			if q, ok := node.(sp.SelectStatement); ok {
				with, lim, _, e := queryParts(q)
				if e != nil || lim != nil && lim.Offset != nil {
					return false, errConfig
				}
				local := map[string]bool{}
				for k, v := range scope {
					local[k] = v
				}
				if with != nil {
					for _, c := range with.Ctes {
						local[strings.ToLower(c.As.String())] = true
					}
					for _, c := range with.Ctes {
						if e := walk(c.Expr, local, depth+1); e != nil {
							return false, e
						}
					}
				}
				switch q := q.(type) {
				case *sp.Select:
					for _, p := range q.SelectExprs {
						if _, ok := p.(*sp.StarExpr); ok {
							return false, errConfig
						}
					}
					for _, n := range []sp.SQLNode{q.SelectExprs, q.From, q.Where, q.GroupBy, q.Having, q.Window, q.OrderBy, q.Limit} {
						if e := walk(n, local, depth+1); e != nil {
							return false, e
						}
					}
				case *sp.SetOp:
					for _, n := range []sp.SQLNode{q.Left, q.Right, q.OrderBy, q.Limit} {
						if e := walk(n, local, depth+1); e != nil {
							return false, e
						}
					}
				case *sp.ParenSelect:
					if e := walk(q.Select, local, depth+1); e != nil {
						return false, e
					}
				}
				return false, nil
			}
			switch v := node.(type) {
			case *sp.AliasedTableExpr:
				if v.AsOf != nil || v.Lateral {
					return false, errConfig
				}
				if n, ok := v.Expr.(sp.TableName); ok {
					name, e := tableName(n)
					if e != nil {
						return false, e
					}
					if !scope[strings.ToLower(name)] && !writes[name] {
						if !a.allowed(name, "SELECT") {
							return false, errConfig
						}
						reads[name] = true
					}
				}
			case *sp.FuncExpr:
				if !v.Qualifier.IsEmpty() || !strings.Contains(" "+allowedFunctions+" ", " "+strings.ToUpper(v.Name.String())+" ") {
					return false, errConfig
				}
			case *sp.Nextval:
				return false, errConfig
			}
			return true, nil
		}, node)
	}
	if e := walk(stmt, map[string]bool{}, 0); e != nil {
		return nil, e
	}
	for k := range reads {
		p.ReadTables = append(p.ReadTables, k)
	}
	for k := range writes {
		p.WriteTables = append(p.WriteTables, k)
	}
	return p, nil
}

const allowedFunctions = "ABS ACOS ASIN ATAN ATAN2 CEIL CEILING COS COT DEGREES EXP FLOOR LN LOG LOG2 LOG10 MOD PI POW POWER RADIANS ROUND SIGN SIN SQRT TAN TRUNCATE AVG BIT_AND BIT_OR BIT_XOR COUNT GROUP_CONCAT MAX MIN STD STDDEV STDDEV_POP STDDEV_SAMP SUM VAR_POP VAR_SAMP VARIANCE COALESCE IF IFNULL NULLIF ASCII BIN CHAR CHAR_LENGTH CHARACTER_LENGTH CONCAT CONCAT_WS ELT FIELD FIND_IN_SET FORMAT HEX INSTR LCASE LEFT LENGTH LOCATE LOWER LPAD LTRIM OCT OCTET_LENGTH REPEAT REPLACE REVERSE RIGHT RPAD RTRIM SPACE STRCMP SUBSTR SUBSTRING SUBSTRING_INDEX TRIM UCASE UNHEX UPPER ADDDATE ADDTIME CONVERT_TZ CURDATE CURRENT_DATE CURRENT_TIME CURRENT_TIMESTAMP CURTIME DATE DATEDIFF DATE_ADD DATE_FORMAT DATE_SUB DAY DAYNAME DAYOFMONTH DAYOFWEEK DAYOFYEAR EXTRACT FROM_DAYS FROM_UNIXTIME HOUR LAST_DAY MAKEDATE MAKETIME MICROSECOND MINUTE MONTH MONTHNAME NOW PERIOD_ADD PERIOD_DIFF QUARTER SECOND SEC_TO_TIME STR_TO_DATE SUBDATE SUBTIME SYSDATE TIME TIMEDIFF TIMESTAMP TIMESTAMPADD TIMESTAMPDIFF TIME_FORMAT TIME_TO_SEC TO_DAYS TO_SECONDS UNIX_TIMESTAMP UTC_DATE UTC_TIME UTC_TIMESTAMP WEEK WEEKDAY WEEKOFYEAR YEAR YEARWEEK JSON_ARRAY JSON_ARRAYAGG JSON_CONTAINS JSON_CONTAINS_PATH JSON_DEPTH JSON_EXTRACT JSON_INSERT JSON_KEYS JSON_LENGTH JSON_MERGE JSON_MERGE_PATCH JSON_MERGE_PRESERVE JSON_OBJECT JSON_OBJECTAGG JSON_QUERY JSON_QUOTE JSON_REMOVE JSON_REPLACE JSON_SEARCH JSON_SET JSON_TYPE JSON_UNQUOTE JSON_VALID JSON_VALUE JSON_COMPACT JSON_DETAILED JSON_EQUALS JSON_EXISTS JSON_NORMALIZE JSON_PRETTY JSON_LOOSE JSON_OVERLAPS VALUES ROW_NUMBER RANK DENSE_RANK LAG LEAD FIRST_VALUE LAST_VALUE NTH_VALUE NTILE CUME_DIST PERCENT_RANK"
