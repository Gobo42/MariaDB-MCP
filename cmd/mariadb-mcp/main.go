package main

import (
	"fmt"
	"mariadb-mcp/internal/agent"
	"os"
)

func main() {
	if e := agent.Run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(agent.ExitCode(e))
	}
}
