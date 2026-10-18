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

package container

import (
	"testing"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Tests for newCreateCommand edge cases
func TestNewCreateCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newCreateCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on create command")
	}
}

func TestNewCreateCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newCreateCommand(getFlags)

	// Test that all expected flags have usage strings
	expectedFlags := []string{
		"name", "image", "env", "label", "port", "mount",
		"privileged", "network-mode", "memory", "cpu",
		"cmd", "workdir", "tpm-access", "start",
	}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %q not found", flagName)
			continue
		}
		if flag.Usage == "" {
			t.Errorf("flag %q has no usage string", flagName)
		}
	}
}

// Tests for newStartCommand edge cases
func TestNewStartCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newStartCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on start command")
	}
}

func TestNewStartCommand_ValidateArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStartCommand(getFlags)

	// Test exact args validation
	err := cmd.Args(cmd, []string{"container-id"})
	if err != nil {
		t.Errorf("Args should accept exactly one arg: %v", err)
	}

	err = cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("Args should reject zero arguments")
	}

	err = cmd.Args(cmd, []string{"id1", "id2"})
	if err == nil {
		t.Error("Args should reject more than one argument")
	}
}

// Tests for newStopCommand edge cases
func TestNewStopCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatYAML,
		}
	}

	cmd := newStopCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on stop command")
	}
}

func TestNewStopCommand_TimeoutFlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newStopCommand(getFlags)

	timeoutFlag := cmd.Flags().Lookup("timeout")
	if timeoutFlag == nil {
		t.Fatal("timeout flag not found")
	}

	if timeoutFlag.Usage == "" {
		t.Error("timeout flag should have usage string")
	}
}

// Tests for newRemoveCommand edge cases
func TestNewRemoveCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newRemoveCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on remove command")
	}
}

func TestNewRemoveCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newRemoveCommand(getFlags)

	// Test force flag usage
	forceFlag := cmd.Flags().Lookup("force")
	if forceFlag == nil {
		t.Fatal("force flag not found")
	}
	if forceFlag.Usage == "" {
		t.Error("force flag should have usage string")
	}

	// Test volumes flag usage
	volumesFlag := cmd.Flags().Lookup("volumes")
	if volumesFlag == nil {
		t.Fatal("volumes flag not found")
	}
	if volumesFlag.Usage == "" {
		t.Error("volumes flag should have usage string")
	}
}

// Tests for newListCommand edge cases
func TestNewListCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newListCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on list command")
	}
}

func TestNewListCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newListCommand(getFlags)

	expectedFlags := []string{"all", "filter", "limit"}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %q not found", flagName)
			continue
		}
		if flag.Usage == "" {
			t.Errorf("flag %q has no usage string", flagName)
		}
	}
}

// Tests for newLogsCommand edge cases
func TestNewLogsCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}

	cmd := newLogsCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on logs command")
	}
}

func TestNewLogsCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newLogsCommand(getFlags)

	expectedFlags := []string{"follow", "tail", "timestamps", "stdout", "stderr"}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %q not found", flagName)
			continue
		}
		if flag.Usage == "" {
			t.Errorf("flag %q has no usage string", flagName)
		}
	}
}

// Tests for newAttestCommand edge cases
func TestNewAttestCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatTable,
		}
	}

	cmd := newAttestCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on attest command")
	}
}

func TestNewAttestCommand_FlagUsage(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newAttestCommand(getFlags)

	expectedFlags := []string{"nonce", "pcrs"}

	for _, flagName := range expectedFlags {
		flag := cmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %q not found", flagName)
			continue
		}
		if flag.Usage == "" {
			t.Errorf("flag %q has no usage string", flagName)
		}
	}
}

// Tests for newGetCommand edge cases
func TestNewGetCommand_RunEHandler(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatYAML,
		}
	}

	cmd := newGetCommand(getFlags)

	// Verify RunE is set
	if cmd.RunE == nil {
		t.Error("RunE should be set on get command")
	}
}

func TestNewGetCommand_ValidateArgs(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	cmd := newGetCommand(getFlags)

	// Test exact args validation
	err := cmd.Args(cmd, []string{"container-id"})
	if err != nil {
		t.Errorf("Args should accept exactly one arg: %v", err)
	}

	err = cmd.Args(cmd, []string{})
	if err == nil {
		t.Error("Args should reject zero arguments")
	}

	err = cmd.Args(cmd, []string{"id1", "id2"})
	if err == nil {
		t.Error("Args should reject more than one argument")
	}
}

// Test for parseFilters edge case - image filter
func TestParseFilters_ImageFilter(t *testing.T) {
	filters := []string{"image=nginx:latest"}

	got, err := parseFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(got.states) != 0 {
		t.Errorf("expected no states, got %d", len(got.states))
	}

	if val, ok := got.labels["image"]; !ok || val != "nginx:latest" {
		t.Errorf("expected image=nginx:latest in labels, got %v", got.labels)
	}
}

// Test for parseFilters with label key only (no value)
func TestParseFilters_LabelKeyOnly(t *testing.T) {
	filters := []string{"label=environment"}

	got, err := parseFilters(filters)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if val, ok := got.labels["environment"]; !ok || val != "" {
		t.Errorf("expected empty value for environment, got %q", val)
	}
}

// Test for runCreate with missing name validation
func TestRunCreate_MissingName(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &createOptions{
		name:  "",
		image: "nginx:latest",
	}

	err := runCreate(flags, opts)
	if err == nil {
		t.Error("expected error for missing name")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runCreate with missing image validation
func TestRunCreate_MissingImage(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &createOptions{
		name:  "mycontainer",
		image: "",
	}

	err := runCreate(flags, opts)
	if err == nil {
		t.Error("expected error for missing image")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runLogs with missing container ID validation
func TestRunLogs_MissingContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &logsOptions{
		follow:     false,
		tail:       0,
		timestamps: false,
		stdout:     true,
		stderr:     true,
	}

	err := runLogs(flags, "", opts)
	if err == nil {
		t.Error("expected error for missing container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runGet with missing container ID validation
func TestRunGet_MissingContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runGet(flags, "")
	if err == nil {
		t.Error("expected error for missing container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runAttest with missing container ID validation
func TestRunAttest_MissingContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &attestOptions{
		nonce: "",
		pcrs:  "",
	}

	err := runAttest(flags, "", opts)
	if err == nil {
		t.Error("expected error for missing container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runRemove with missing container ID validation
func TestRunRemove_MissingContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &removeOptions{
		force:         false,
		deleteVolumes: false,
	}

	err := runRemove(flags, "", opts)
	if err == nil {
		t.Error("expected error for missing container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runStop with missing container ID validation
func TestRunStop_MissingContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &stopOptions{
		timeout: 10,
	}

	err := runStop(flags, "", opts)
	if err == nil {
		t.Error("expected error for missing container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test for runStart with missing container ID validation
func TestRunStart_MissingContainerID(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runStart(flags, "")
	if err == nil {
		t.Error("expected error for missing container ID")
	}

	if _, ok := err.(ErrInvalidContainerConfig); !ok {
		t.Errorf("expected ErrInvalidContainerConfig, got %T", err)
	}
}

// Test that all commands have proper Long descriptions
func TestAllCommands_HaveLongDescriptions(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	commands := []struct {
		name string
		cmd  func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"create", newCreateCommand},
		{"start", newStartCommand},
		{"stop", newStopCommand},
		{"remove", newRemoveCommand},
		{"list", newListCommand},
		{"logs", newLogsCommand},
		{"attest", newAttestCommand},
		{"get", newGetCommand},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmd(getFlags)
			if cmd.Long == "" {
				t.Errorf("%s command should have Long description", tc.name)
			}
			if len(cmd.Long) < 50 {
				t.Errorf("%s command Long description should be at least 50 chars", tc.name)
			}
		})
	}
}

// Test that commands requiring args have proper Args validation
func TestCommandsWithArgs_HaveArgsValidation(t *testing.T) {
	getFlags := func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}

	argsCommands := []struct {
		name string
		cmd  func(func() *cli.CommonFlags) *cobra.Command
	}{
		{"start", newStartCommand},
		{"stop", newStopCommand},
		{"remove", newRemoveCommand},
		{"logs", newLogsCommand},
		{"attest", newAttestCommand},
		{"get", newGetCommand},
	}

	for _, tc := range argsCommands {
		t.Run(tc.name, func(t *testing.T) {
			cmd := tc.cmd(getFlags)
			if cmd.Args == nil {
				t.Errorf("%s command should have Args validation", tc.name)
			}
		})
	}
}
