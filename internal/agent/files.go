package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"
)

var errConfig = errors.New("invalid_configuration")
var errPersistence = errors.New("persistence_failed")
var errArgs = errors.New("invalid_arguments")
var errType = errors.New("result_type_mismatch")
var errAuth = errors.New("unauthorized")

func normalizeDir(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", errConfig
	}
	if !filepath.IsAbs(p) {
		cwd, e := os.Getwd()
		if e != nil {
			return "", errConfig
		}
		p = cwd + string(os.PathSeparator) + p
	}
	cur := string(os.PathSeparator)
	for _, part := range strings.Split(p, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			cur = filepath.Dir(cur)
		} else {
			cur = filepath.Join(cur, part)
		}
		m, e := os.Lstat(cur)
		if e == nil && m.Mode()&os.ModeSymlink != 0 {
			return "", errConfig
		}
		if e != nil && !os.IsNotExist(e) {
			return "", errConfig
		}
	}
	return filepath.Clean(cur), nil
}
func normalizeFile(p string) (string, error) {
	if strings.HasSuffix(p, string(os.PathSeparator)) {
		return "", errConfig
	}
	return normalizeDir(p)
}
func resolve(file, ref string, dir bool) (string, error) {
	if !filepath.IsAbs(ref) {
		ref = filepath.Dir(file) + string(os.PathSeparator) + ref
	}
	if dir {
		return normalizeDir(ref)
	}
	return normalizeFile(ref)
}
func privateDir(p string) (string, error) {
	p, e := normalizeDir(p)
	if e != nil {
		return "", e
	}
	m, e := os.Lstat(p)
	if e != nil || !m.IsDir() || m.Mode().Perm() != 0700 {
		return "", errConfig
	}
	return p, nil
}
func ensureDir(p string) (string, error) {
	p, e := normalizeDir(p)
	if e != nil {
		return "", e
	}
	if _, e = os.Lstat(p); os.IsNotExist(e) {
		if e = os.Mkdir(p, 0700); e != nil {
			return "", errPersistence
		}
	}
	return privateDir(p)
}
func syncDir(p string) error {
	f, e := os.Open(p)
	if e != nil {
		return errPersistence
	}
	defer f.Close()
	if e = f.Sync(); e != nil {
		return errPersistence
	}
	return nil
}
func openFile(p string, flags int) (*os.File, error) {
	fd, e := syscall.Open(p, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, errConfig
	}
	return os.NewFile(uintptr(fd), p), nil
}
func createPrivate(p string, b []byte) error {
	p, e := normalizeFile(p)
	if e != nil {
		return e
	}
	parent, e := privateDir(filepath.Dir(p))
	if e != nil {
		return e
	}
	f, e := openFile(p, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL)
	if e != nil {
		return errPersistence
	}
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return errPersistence
	}
	if e = f.Sync(); e != nil {
		return errPersistence
	}
	return syncDir(parent)
}
func readPrivate(p string, max int) ([]byte, error) {
	p, e := normalizeFile(p)
	if e != nil {
		return nil, e
	}
	if _, e = privateDir(filepath.Dir(p)); e != nil {
		return nil, e
	}
	f, e := openFile(p, syscall.O_RDONLY)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	m, e := f.Stat()
	if e != nil || !m.Mode().IsRegular() || m.Mode().Perm() != 0600 || m.Size() > int64(max) {
		return nil, errConfig
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if e != nil || len(b) > max {
		return nil, errConfig
	}
	return b, nil
}
func parseJSON(b []byte) (any, error) {
	if !utf8.Valid(b) || !validSurrogates(b) {
		return nil, errConfig
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := jsonValue(d, 0)
	if e != nil {
		return nil, errConfig
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errConfig
	}
	return v, nil
}
func jsonValue(d *json.Decoder, depth int) (any, error) {
	tok, e := d.Token()
	if e != nil {
		return nil, e
	}
	del, ok := tok.(json.Delim)
	if !ok {
		if n, yes := tok.(json.Number); yes {
			if i := strings.IndexAny(string(n), "eE"); i >= 0 {
				exponent, e := strconv.ParseInt(string(n)[i+1:], 10, 64)
				if e != nil || exponent < -10000 || exponent > 10000 {
					return nil, errConfig
				}
			}
		}
		return tok, nil
	}
	if depth >= 32 {
		return nil, errConfig
	}
	switch del {
	case 123:
		m := map[string]any{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return nil, e
			}
			key, ok := k.(string)
			if !ok || key == "$serde_json::private::Number" {
				return nil, errConfig
			}
			if _, ok = m[key]; ok {
				return nil, errConfig
			}
			m[key], e = jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
		}
		if t, e := d.Token(); e != nil || t != json.Delim(125) {
			return nil, errConfig
		}
		return m, nil
	case 91:
		a := []any{}
		for d.More() {
			v, e := jsonValue(d, depth+1)
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		if t, e := d.Token(); e != nil || t != json.Delim(93) {
			return nil, errConfig
		}
		return a, nil
	}
	return nil, errConfig
}
func decode(b []byte, v any) error {
	parsed, e := parseJSON(b)
	if e != nil {
		return e
	}
	if e := typedJSON(parsed, reflect.TypeOf(v)); e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errConfig
	}
	return nil
}
func readJSON(p string, v any) error {
	b, e := readPrivate(p, 1048576)
	if e != nil {
		return e
	}
	return decode(b, v)
}

// encoding/json replaces lone surrogates; configuration and payloads must preserve text exactly.
func validSurrogates(b []byte) bool {
	for i := 0; i < len(b); i++ {
		if b[i] != 92 {
			continue
		}
		if i+1 >= len(b) {
			return false
		}
		if b[i+1] != 117 {
			i++
			continue
		}
		if i+6 > len(b) {
			return false
		}
		u, e := strconv.ParseUint(string(b[i+2:i+6]), 16, 16)
		if e != nil {
			return false
		}
		if u >= 0xdc00 && u <= 0xdfff {
			return false
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+12 > len(b) || b[i+6] != 92 || b[i+7] != 117 {
				return false
			}
			low, e := strconv.ParseUint(string(b[i+8:i+12]), 16, 16)
			if e != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 11
		} else {
			i += 5
		}
	}
	return true
}

func typedJSON(value any, typ reflect.Type) error {
	if typ.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		return typedJSON(value, typ.Elem())
	}
	if typ.PkgPath() == "time" && typ.Name() == "Time" {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		obj, ok := value.(map[string]any)
		if !ok {
			return errConfig
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			key := strings.Split(f.Tag.Get("json"), ",")[0]
			if key == "" || key == "-" {
				continue
			}
			v, present := obj[key]
			if !present {
				if f.Tag.Get("required") == "true" {
					return errConfig
				}
				continue
			}
			if v == nil {
				if f.Type.Kind() != reflect.Pointer && key != "fields" && key != "json_schema" {
					return errConfig
				}
				continue
			}
			if e := typedJSON(v, f.Type); e != nil {
				return e
			}
		}
	case reflect.Slice:
		if values, ok := value.([]any); ok {
			for _, v := range values {
				if v == nil {
					return errConfig
				}
				if e := typedJSON(v, typ.Elem()); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
