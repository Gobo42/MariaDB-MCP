package agent

import (
	"encoding/binary"
	"net"
	"sync"
)

type columnInfo struct {
	name string
	kind byte
}
type metadataConn struct {
	net.Conn
	mu                               sync.Mutex
	active                           bool
	buffer                           []byte
	packet, params, columns, skipped int
	infos                            []columnInfo
	invalid                          bool
}

func (c *metadataConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if len(b) >= 5 {
		c.active = b[4] == 0x16
		c.buffer = nil
		c.packet = 0
		c.params = 0
		c.columns = 0
		c.skipped = 0
		c.infos = nil
		c.invalid = false
	}
	c.mu.Unlock()
	return c.Conn.Write(b)
}
func (c *metadataConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active {
		return n, e
	}
	if len(c.buffer)+n > 1048576 {
		c.invalid = true
		c.active = false
		return n, e
	}
	c.buffer = append(c.buffer, b[:n]...)
	for len(c.buffer) >= 4 {
		size := int(c.buffer[0]) | int(c.buffer[1])<<8 | int(c.buffer[2])<<16
		if size > 1048576 {
			c.invalid = true
			c.active = false
			break
		}
		if len(c.buffer) < size+4 {
			break
		}
		p := c.buffer[4 : 4+size]
		c.capture(p)
		c.buffer = c.buffer[4+size:]
		c.packet++
	}
	return n, e
}
func (c *metadataConn) capture(b []byte) {
	if c.packet == 0 {
		if len(b) < 12 || b[0] != 0 {
			c.invalid = true
			c.active = false
			return
		}
		c.columns = int(binary.LittleEndian.Uint16(b[5:7]))
		c.params = int(binary.LittleEndian.Uint16(b[7:9]))
		return
	}
	if len(b) > 0 && b[0] == 254 && len(b) < 9 {
		return
	}
	if c.skipped < c.params {
		c.skipped++
		return
	}
	if len(c.infos) >= c.columns {
		return
	}
	offset := 0
	name := ""
	for i := 0; i < 6; i++ {
		v, rest, ok := lengthString(b[offset:])
		if !ok {
			c.invalid = true
			return
		}
		offset = len(b) - len(rest)
		if i == 4 {
			name = string(v)
		}
	}
	if len(b)-offset < 13 || b[offset] != 12 {
		c.invalid = true
		return
	}
	c.infos = append(c.infos, columnInfo{name, b[offset+7]})
}
func lengthString(b []byte) ([]byte, []byte, bool) {
	if len(b) == 0 {
		return nil, nil, false
	}
	n := uint64(b[0])
	head := 1
	switch b[0] {
	case 251, 255:
		return nil, nil, false
	case 252:
		if len(b) < 3 {
			return nil, nil, false
		}
		n = uint64(binary.LittleEndian.Uint16(b[1:3]))
		head = 3
	case 253:
		if len(b) < 4 {
			return nil, nil, false
		}
		n = uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16
		head = 4
	case 254:
		if len(b) < 9 {
			return nil, nil, false
		}
		n = binary.LittleEndian.Uint64(b[1:9])
		head = 9
	}
	if n > uint64(len(b)-head) {
		return nil, nil, false
	}
	end := head + int(n)
	return b[head:end], b[end:], true
}
func compatible(f Field, kind byte) bool {
	if kind == 6 {
		return f.Nullable
	}
	integer := kind == 1 || kind == 2 || kind == 3 || kind == 8 || kind == 9 || kind == 13
	text := kind == 15 || kind >= 247
	decimal := kind == 0 || kind == 246
	switch f.Type {
	case "string", "binary":
		return text
	case "integer", "boolean":
		return integer
	case "bigint":
		return integer || text
	case "decimal":
		return decimal || text
	case "number":
		return integer || decimal || text || kind == 4 || kind == 5
	case "json":
		return text || kind == 245
	case "date":
		return kind == 10 || kind == 14
	case "datetime":
		return kind == 12 || kind == 18
	case "timestamp":
		return kind == 7 || kind == 12 || kind == 17 || kind == 18
	case "time", "duration":
		return kind == 11 || kind == 19
	}
	return false
}
