package runner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestExecReturnsOutput(t *testing.T) {
	out, err := Exec(context.Background(), "sh", "-c", "echo hello; echo err 1>&2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "hello") || !strings.Contains(string(out), "err") {
		t.Errorf("combined output = %q", out)
	}
}

func TestExecWrapsFailures(t *testing.T) {
	out, err := Exec(context.Background(), "sh", "-c", "echo boom; exit 3")
	var cmdErr *CommandError
	if !errors.As(err, &cmdErr) {
		t.Fatalf("error = %T %v, want *CommandError", err, err)
	}
	if cmdErr.Name != "sh" || !strings.Contains(cmdErr.Output, "boom") || !strings.Contains(string(out), "boom") {
		t.Errorf("CommandError = %+v", cmdErr)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Errorf("exit code not preserved: %v", err)
	}
	if !strings.Contains(err.Error(), "runner: sh failed") {
		t.Errorf("Error() = %q", err.Error())
	}

	if _, err := Exec(context.Background(), "/nonexistent/binary"); !errors.As(err, &cmdErr) {
		t.Errorf("missing binary error = %T", err)
	}
}
