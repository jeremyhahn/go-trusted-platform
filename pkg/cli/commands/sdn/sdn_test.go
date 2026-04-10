package sdn

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func testGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}
}

func TestNewCommand(t *testing.T) {
	cmd := NewCommand(testGetFlags())
	if cmd == nil {
		t.Fatal("NewCommand returned nil")
	}
	if cmd.Use != "sdn" {
		t.Errorf("expected Use 'sdn', got %s", cmd.Use)
	}
	if cmd.Short != "SDN networking operations" {
		t.Errorf("unexpected Short: %s", cmd.Short)
	}
	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}
}

func TestNewCommandSubcommands(t *testing.T) {
	cmd := NewCommand(testGetFlags())

	expectedSubs := []string{
		"bridge", "port", "flow", "vlan",
		"overlay", "gateway", "ipam", "policy",
	}

	commands := cmd.Commands()
	if len(commands) != len(expectedSubs) {
		t.Errorf("expected %d subcommands, got %d", len(expectedSubs), len(commands))
	}

	for _, expected := range expectedSubs {
		found := false
		for _, subcmd := range commands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", expected)
		}
	}
}

func TestNewCLIContext(t *testing.T) {
	ctx, cancel := newCLIContext()
	defer cancel()

	if ctx == nil {
		t.Fatal("context should not be nil")
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("context should have a deadline")
	}

	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > defaultCLITimeout+time.Second {
		t.Errorf("unexpected deadline: %v remaining", remaining)
	}
}

func TestNewCLIContextCancellation(t *testing.T) {
	ctx, cancel := newCLIContext()
	cancel()

	select {
	case <-ctx.Done():
		// expected
	default:
		t.Error("context should be done after cancel")
	}

	if ctx.Err() != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", ctx.Err())
	}
}

func TestDefaultCLITimeout(t *testing.T) {
	if defaultCLITimeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", defaultCLITimeout)
	}
}
