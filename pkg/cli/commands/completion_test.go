// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package commands

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

func TestNewCompletionCommand(t *testing.T) {
	cmd := NewCompletionCommand()

	if cmd == nil {
		t.Fatal("NewCompletionCommand returned nil")
	}

	if cmd.Use != "completion [bash|zsh|fish|powershell]" {
		t.Errorf("unexpected Use: %s", cmd.Use)
	}

	if cmd.Short != "Generate shell completion scripts" {
		t.Errorf("unexpected Short: %s", cmd.Short)
	}

	if len(cmd.ValidArgs) != 4 {
		t.Errorf("expected 4 valid args, got %d", len(cmd.ValidArgs))
	}

	// Verify valid args contains expected shells
	expected := []string{"bash", "zsh", "fish", "powershell"}
	for _, exp := range expected {
		found := false
		for _, arg := range cmd.ValidArgs {
			if arg == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s in ValidArgs", exp)
		}
	}
}

func TestCompletionCommandLongDescription(t *testing.T) {
	cmd := NewCompletionCommand()

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	// Verify documentation mentions all supported shells
	shells := []string{"Bash", "Zsh", "Fish", "PowerShell"}
	for _, shell := range shells {
		if !containsString(cmd.Long, shell) {
			t.Errorf("Long description should mention %s", shell)
		}
	}
}

func TestCompletionInvalidArg(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	root.SilenceUsage = true
	root.SilenceErrors = true

	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	root.SetArgs([]string{"completion", "invalid"})

	err := root.Execute()
	if err == nil {
		t.Error("expected error for invalid shell type")
	}
}

func TestCompletionNoArg(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	root.SilenceUsage = true
	root.SilenceErrors = true

	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	root.SetArgs([]string{"completion"})

	err := root.Execute()
	if err == nil {
		t.Error("expected error when no shell type provided")
	}
}

func TestCompletionTooManyArgs(t *testing.T) {
	root := &cobra.Command{Use: "test"}
	root.SilenceUsage = true
	root.SilenceErrors = true

	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	root.SetArgs([]string{"completion", "bash", "extra"})

	err := root.Execute()
	if err == nil {
		t.Error("expected error when too many args provided")
	}
}

func TestCompletionDisablesFlagsInUseLine(t *testing.T) {
	cmd := NewCompletionCommand()

	if !cmd.DisableFlagsInUseLine {
		t.Error("DisableFlagsInUseLine should be true")
	}
}

func TestCompletionRunENotNil(t *testing.T) {
	cmd := NewCompletionCommand()

	if cmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestCompletionArgsValidation(t *testing.T) {
	cmd := NewCompletionCommand()

	if cmd.Args == nil {
		t.Error("Args validation should not be nil")
	}
}

func TestCompletionCommandValidArgs(t *testing.T) {
	cmd := NewCompletionCommand()

	validArgs := map[string]bool{
		"bash":       true,
		"zsh":        true,
		"fish":       true,
		"powershell": true,
	}

	for _, arg := range cmd.ValidArgs {
		if !validArgs[arg] {
			t.Errorf("unexpected valid arg: %s", arg)
		}
	}
}

func TestCompletionCommandStructure(t *testing.T) {
	cmd := NewCompletionCommand()

	if cmd.Long == "" {
		t.Error("Long description should not be empty")
	}

	if cmd.Short == "" {
		t.Error("Short description should not be empty")
	}

	if cmd.Use == "" {
		t.Error("Use should not be empty")
	}
}

func TestCompletionCommandExactArgsRequired(t *testing.T) {
	// Verify Args validator is set correctly
	cmd := NewCompletionCommand()

	// Should have Args function defined
	if cmd.Args == nil {
		t.Error("Args validator should be defined")
	}
}

func TestCompletionBashGeneration(t *testing.T) {
	root := &cobra.Command{Use: "platformctl"}
	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	root.SetArgs([]string{"completion", "bash"})
	err := root.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("bash completion generation failed: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Error("bash completion output should not be empty")
	}

	// Verify it contains bash completion directives
	if !strings.Contains(output, "bash completion") {
		t.Error("output should contain bash completion directives")
	}
}

func TestCompletionZshGeneration(t *testing.T) {
	root := &cobra.Command{Use: "platformctl"}
	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	root.SetArgs([]string{"completion", "zsh"})
	err := root.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("zsh completion generation failed: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Error("zsh completion output should not be empty")
	}

	// Verify it contains zsh completion directives
	if !strings.Contains(output, "zsh completion") {
		t.Error("output should contain zsh completion directives")
	}
}

func TestCompletionFishGeneration(t *testing.T) {
	root := &cobra.Command{Use: "platformctl"}
	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	root.SetArgs([]string{"completion", "fish"})
	err := root.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("fish completion generation failed: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Error("fish completion output should not be empty")
	}

	// Verify it contains fish completion directives
	if !strings.Contains(output, "fish completion") {
		t.Error("output should contain fish completion directives")
	}
}

func TestCompletionPowerShellGeneration(t *testing.T) {
	root := &cobra.Command{Use: "platformctl"}
	completionCmd := NewCompletionCommand()
	root.AddCommand(completionCmd)

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	root.SetArgs([]string{"completion", "powershell"})
	err := root.Execute()

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("powershell completion generation failed: %v", err)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	if output == "" {
		t.Error("powershell completion output should not be empty")
	}
}

func TestGenerateCompletionInvalidShell(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}

	err := generateCompletion(cmd, "invalid-shell")

	if err == nil {
		t.Error("expected error for invalid shell type")
	}

	var invalidShellErr cli.ErrInvalidShellType
	if !errors.As(err, &invalidShellErr) {
		t.Errorf("expected ErrInvalidShellType, got %T", err)
	}

	if invalidShellErr.Shell != "invalid-shell" {
		t.Errorf("expected shell 'invalid-shell', got '%s'", invalidShellErr.Shell)
	}
}

func TestGenerateCompletionAllShells(t *testing.T) {
	tests := []struct {
		name  string
		shell string
	}{
		{"bash", "bash"},
		{"zsh", "zsh"},
		{"fish", "fish"},
		{"powershell", "powershell"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := &cobra.Command{Use: "platformctl"}

			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := generateCompletion(root, tt.shell)

			w.Close()
			os.Stdout = oldStdout

			if err != nil {
				t.Errorf("generateCompletion(%s) failed: %v", tt.shell, err)
			}

			var buf bytes.Buffer
			buf.ReadFrom(r)
			output := buf.String()

			if output == "" {
				t.Errorf("%s completion output should not be empty", tt.shell)
			}
		})
	}
}

func TestErrInvalidShellTypeMessage(t *testing.T) {
	err := cli.ErrInvalidShellType{Shell: "custom"}
	expected := "invalid shell type: custom (valid: bash, zsh, fish, powershell)"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestErrCompletionGenerationFailedMessage(t *testing.T) {
	innerErr := errors.New("write error")
	err := cli.ErrCompletionGenerationFailed{
		Shell: "bash",
		Err:   innerErr,
	}
	expected := "failed to generate bash completion script: write error"

	if err.Error() != expected {
		t.Errorf("expected error message '%s', got '%s'", expected, err.Error())
	}
}

func containsString(s, substr string) bool {
	return strings.Contains(s, substr)
}
