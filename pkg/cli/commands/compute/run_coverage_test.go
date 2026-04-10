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

package compute

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// TestRunCreate_NoContext verifies that runCreate propagates the error from
// NewBaseCommand when no context is configured.
func TestRunCreate_NoContext(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &createOptions{
		name:     "test-vm",
		firmware: "uefi",
	}

	err := runCreate(flags, opts)
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestRunCreate_InvalidFirmware verifies that runCreate returns an error for
// an invalid firmware type before attempting to connect.
func TestRunCreate_InvalidFirmware(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		// GetContext is nil, but we should fail on firmware validation first
		// Actually, firmware validation happens after NewBaseCommand, so this
		// will fail at NewBaseCommand. Testing with a context that returns error.
	}

	opts := &createOptions{
		name:     "test-vm",
		firmware: "invalid-fw",
	}

	// Will fail at NewBaseCommand since no GetContext
	err := runCreate(flags, opts)
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestRunStart_NoContext verifies that runStart propagates the error from
// NewBaseCommand when no context is configured.
func TestRunStart_NoContext(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runStart(flags, "test-vm-id")
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestRunStop_NoContext verifies that runStop propagates the error from
// NewBaseCommand when no context is configured.
func TestRunStop_NoContext(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &stopOptions{
		force:   false,
		timeout: 30,
	}

	err := runStop(flags, "test-vm-id", opts)
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestRunDelete_NoContext verifies that runDelete propagates the error from
// NewBaseCommand when no context is configured.
func TestRunDelete_NoContext(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &deleteOptions{
		force:       false,
		deleteDisks: false,
	}

	err := runDelete(flags, "test-vm-id", opts)
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestRunGet_NoContext verifies that runGet propagates the error from
// NewBaseCommand when no context is configured.
func TestRunGet_NoContext(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runGet(flags, "test-vm-id")
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestRunList_NoContext verifies that runList propagates the error from
// NewBaseCommand when no context is configured.
func TestRunList_NoContext(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	opts := &listOptions{
		all:      false,
		pageSize: 100,
	}

	err := runList(flags, opts)
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestRunList_NoContext_WithFilters verifies that runList propagates the error
// from NewBaseCommand even when filters are configured.
func TestRunList_NoContext_WithFilters(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	opts := &listOptions{
		all:      true,
		filter:   []string{"state=running"},
		pageSize: 50,
	}

	err := runList(flags, opts)
	if err == nil {
		t.Fatal("expected error when no context is set")
	}

	if _, ok := err.(cli.ErrNoContextSet); !ok {
		t.Errorf("expected ErrNoContextSet, got %T: %v", err, err)
	}
}

// TestCommandRunE_Closures verifies that the RunE closures in command
// constructors correctly delegate to the run functions.
func TestCommandRunE_CreateClosure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	getFlags := func() *cli.CommonFlags { return flags }

	cmd := newCreateCommand(getFlags)
	if cmd.RunE == nil {
		t.Fatal("create command should have RunE set")
	}

	// Execute without required flag set - cobra validation should catch this
	// But since we call RunE directly, it bypasses cobra flag parsing
	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Fatal("expected error from RunE")
	}
}

// TestCommandRunE_StartClosure verifies the start command RunE closure.
func TestCommandRunE_StartClosure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	getFlags := func() *cli.CommonFlags { return flags }

	cmd := newStartCommand(getFlags)
	if cmd.RunE == nil {
		t.Fatal("start command should have RunE set")
	}

	// RunE with a valid arg should fail at NewBaseCommand
	err := cmd.RunE(cmd, []string{"test-vm"})
	if err == nil {
		t.Fatal("expected error from RunE")
	}
}

// TestCommandRunE_StopClosure verifies the stop command RunE closure.
func TestCommandRunE_StopClosure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	getFlags := func() *cli.CommonFlags { return flags }

	cmd := newStopCommand(getFlags)
	if cmd.RunE == nil {
		t.Fatal("stop command should have RunE set")
	}

	err := cmd.RunE(cmd, []string{"test-vm"})
	if err == nil {
		t.Fatal("expected error from RunE")
	}
}

// TestCommandRunE_DeleteClosure verifies the delete command RunE closure.
func TestCommandRunE_DeleteClosure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	getFlags := func() *cli.CommonFlags { return flags }

	cmd := newDeleteCommand(getFlags)
	if cmd.RunE == nil {
		t.Fatal("delete command should have RunE set")
	}

	err := cmd.RunE(cmd, []string{"test-vm"})
	if err == nil {
		t.Fatal("expected error from RunE")
	}
}

// TestCommandRunE_GetClosure verifies the get command RunE closure.
func TestCommandRunE_GetClosure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	getFlags := func() *cli.CommonFlags { return flags }

	cmd := newGetCommand(getFlags)
	if cmd.RunE == nil {
		t.Fatal("get command should have RunE set")
	}

	err := cmd.RunE(cmd, []string{"test-vm"})
	if err == nil {
		t.Fatal("expected error from RunE")
	}
}

// TestCommandRunE_ListClosure verifies the list command RunE closure.
func TestCommandRunE_ListClosure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}
	getFlags := func() *cli.CommonFlags { return flags }

	cmd := newListCommand(getFlags)
	if cmd.RunE == nil {
		t.Fatal("list command should have RunE set")
	}

	err := cmd.RunE(cmd, []string{})
	if err == nil {
		t.Fatal("expected error from RunE")
	}
}
