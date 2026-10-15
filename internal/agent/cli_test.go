package agent

import (
	"testing"
)

func TestCLIRejectsUnknownArguments(t *testing.T) {
	for _, args := range [][]string{{"unknown"}, {"serve", "--config"}, {"serve", "--bogus"}, {"init-state", "--config", "file", "extra"}, {"prepare-auth", "--output", "file"}, {"prepare-auth", "--output", "file", "--username", "owner", "--config", "other"}} {
		if e := Run(args); e == nil {
			t.Fatal("accepted", args)
		}
	}
}
func TestCLIExitCodes(t *testing.T) {
	for _, c := range []struct {
		e    error
		want int
	}{{nil, 0}, {errArgs, 64}, {errDB, 69}, {errTimeout, 69}, {errConfig, 78}, {errPersistence, 78}} {
		if got := ExitCode(c.e); got != c.want {
			t.Fatalf("got %d want %d", got, c.want)
		}
	}
}
