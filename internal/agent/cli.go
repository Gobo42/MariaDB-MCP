package agent

import (
	"context"
	"fmt"
	"golang.org/x/term"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const help = "MariaDB MCP\n\nUsage:\n  mariadb-mcp prepare-auth --output FILE --username NAME\n  mariadb-mcp init-state [--config FILE]\n  mariadb-mcp check [--config FILE]\n  mariadb-mcp serve [--config FILE]\n\nDefault config: /etc/mariadb-mcp/mcp.json\nBuild locally; deploy only the compiled binary.\n"

func Run(args []string) error {
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Print(help)
		return nil
	}
	command := args[0]
	if command != "prepare-auth" && command != "init-state" && command != "check" && command != "serve" {
		return errArgs
	}
	values := map[string]string{}
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" || arg == "-h" {
			if len(args) != 2 {
				return errArgs
			}
			fmt.Print(help)
			return nil
		}
		allowed := arg == "--config" && command != "prepare-auth" || (arg == "--output" || arg == "--username") && command == "prepare-auth"
		if !allowed || i+1 >= len(args) || values[arg] != "" {
			return errArgs
		}
		i++
		values[arg] = args[i]
		if values[arg] == "" {
			return errArgs
		}
	}
	if command == "prepare-auth" {
		path, username := values["--output"], values["--username"]
		if path == "" || !validText(username, 128) {
			return errArgs
		}
		return prepareAuth(path, username)
	}
	path := values["--config"]
	if path == "" {
		path = "/etc/mariadb-mcp/mcp.json"
	}
	registry, e := loadRegistry(path)
	if e != nil {
		return e
	}
	id := identity(registry)
	if command == "init-state" {
		if e = initStore(registry.Server.OAuth.StateDirectory, id); e == nil {
			fmt.Println("Initialized protected OAuth state.")
		}
		return e
	}
	upstream, e := newOIDCLogin(context.Background(), registry, nil)
	if e != nil {
		return e
	}
	store, e := openStore(registry.Server.OAuth.StateDirectory, id)
	if e != nil {
		return e
	}
	defer store.close()
	db, e := connectDatabase(context.Background(), registry)
	if e != nil {
		return e
	}
	defer db.close()
	if command == "check" {
		fmt.Println("Configuration, database permissions, schemas and OAuth state verified.")
		return nil
	}
	auth := newOAuth(registry, store)
	auth.oidc = upstream
	handler := auth.routes(db)
	srv := &http.Server{Addr: registry.Server.Listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	listener, e := net.Listen("tcp", registry.Server.Listen)
	if e != nil {
		return errConfig
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	select {
	case e = <-done:
		if e != http.ErrServerClosed {
			return errDB
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		if e = srv.Shutdown(shutdown); e != nil {
			srv.Close()
		}
		<-done
	}
	return nil
}
func prepareAuth(path, username string) error {
	p, e := normalizeFile(path)
	if e != nil {
		return e
	}
	if _, e = readPrivate(p, 1048576); e == nil {
		return errPersistence
	}
	if _, e = os.Lstat(p); !os.IsNotExist(e) {
		return errPersistence
	}
	fmt.Fprint(os.Stderr, "Login password (at least 12 characters): ")
	password, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return errArgs
	}
	if !utf8.Valid(password) || utf8.RuneCount(password) < 12 || len(password) > 1024 {
		return errArgs
	}
	fmt.Fprint(os.Stderr, "Confirm login password: ")
	confirmation, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil || !equal(string(password), string(confirmation)) {
		return errArgs
	}
	hash, e := newPasswordHash(string(password))
	for i := range password {
		password[i] = 0
	}
	for i := range confirmation {
		confirmation[i] = 0
	}
	if e != nil {
		return e
	}
	id, e := randomSecret()
	if e != nil {
		return e
	}
	secret, e := randomSecret()
	if e != nil {
		return e
	}
	if strings.TrimSpace(username) == "" {
		return errArgs
	}
	if e = createPrivate(p, jsonBytes(AuthConfig{username, hash, id, secret})); e != nil {
		return e
	}
	fmt.Println("Created protected OAuth credentials.")
	return nil
}

func ExitCode(err error) int {
	switch err {
	case nil:
		return 0
	case errArgs:
		return 64
	case errDB, errTimeout:
		return 69
	default:
		return 78
	}
}
