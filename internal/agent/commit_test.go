package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func readPacket(c net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, e := io.ReadFull(c, header); e != nil {
		return nil, e
	}
	size := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if size > 1048576 {
		return nil, errLarge
	}
	b := make([]byte, 4+size)
	copy(b, header)
	_, e := io.ReadFull(c, b[4:])
	return b, e
}
func TestUnknownCommitIsNotRetried(t *testing.T) {
	admin := fixtureAdmin(t)
	adminExec(t, admin, "INSERT INTO inventory.items VALUES(3001,'Before',1,NULL,'2026-10-12',1) ON DUPLICATE KEY UPDATE label='Before',version=1")
	socket := filepath.Join(t.TempDir(), "proxy.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	var connections sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			down, e := listener.Accept()
			if e != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer down.Close()
				up, e := net.Dial("unix", "/tmp/mcp-mariadb-data/test.sock")
				if e != nil {
					return
				}
				defer up.Close()
				var committing atomic.Bool
				clientDone := make(chan struct{})
				go func() {
					defer close(clientDone)
					for {
						p, e := readPacket(down)
						if e != nil {
							return
						}
						if bytes.Equal(p[4:], append([]byte{3}, []byte("COMMIT")...)) {
							committing.Store(true)
						}
						if _, e = up.Write(p); e != nil {
							return
						}
					}
				}()
				for {
					p, e := readPacket(up)
					if e != nil || committing.Load() {
						break
					}
					if _, e = down.Write(p); e != nil {
						break
					}
				}
				down.Close()
				up.Close()
				<-clientDone
			}()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; connections.Wait() })
	app := inventoryApp(t)
	app.connection.Socket = socket
	db, e := connectDatabase(context.Background(), &Registry{Apps: []*App{app}})
	if e != nil {
		t.Fatal(e)
	}
	defer db.close()
	_, e = db.execute(context.Background(), app, app.Tools[1], map[string]any{"id": "3001", "label": "Committed", "expected_version": json.Number("1")})
	if e != errUnknown {
		t.Fatal("lost acknowledgement", e)
	}
	var label string
	var version int
	if e = admin.QueryRow("SELECT label,version FROM inventory.items WHERE id=3001").Scan(&label, &version); e != nil {
		t.Fatal(e)
	}
	if label != "Committed" || version != 2 {
		t.Fatal("write was retried or commit not applied")
	}
	time.Sleep(time.Millisecond)
}
