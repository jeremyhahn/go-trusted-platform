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

package qemu

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// snapshotNameRegex validates snapshot names.
// Names must start with a letter or underscore, contain only alphanumeric
// characters, underscores, hyphens, and dots, and be between 1-128 characters.
var snapshotNameRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_\-\.]{0,127}$`)

// SnapshotInfo represents information about a VM snapshot.
type SnapshotInfo struct {
	// Name is the human-readable name of the snapshot.
	Name string `json:"name"`

	// ID is the unique identifier assigned by QEMU.
	ID string `json:"id"`

	// VMStateSize is the size of the VM state in bytes.
	VMStateSize uint64 `json:"vm_state_size"`

	// Date is when the snapshot was created.
	Date time.Time `json:"date"`

	// VMClockSec is the VM clock time in seconds at snapshot creation.
	VMClockSec uint64 `json:"vm_clock_sec"`

	// VMClockNsec is the nanosecond component of the VM clock time.
	VMClockNsec uint64 `json:"vm_clock_nsec"`
}

// SnapshotManager provides operations for managing VM snapshots via QMP.
type SnapshotManager struct {
	monitor *Monitor
	logger  *logging.Logger
}

// NewSnapshotManager creates a new SnapshotManager that uses the provided
// Monitor for QMP communication.
func NewSnapshotManager(monitor *Monitor, logger *logging.Logger) (*SnapshotManager, error) {
	if monitor == nil {
		return nil, ErrSnapshotManagerNotInitialized{}
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &SnapshotManager{
		monitor: monitor,
		logger:  logger,
	}, nil
}

// Create creates a new VM snapshot with the given name.
// The snapshot captures the full VM state including memory and disk.
func (sm *SnapshotManager) Create(ctx context.Context, name string) error {
	if err := sm.validateName(name); err != nil {
		return err
	}

	if !sm.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	sm.logger.Infof("Creating VM snapshot: %s", name)

	// Use human-monitor-command for savevm
	cmdLine := "savevm " + name
	args := map[string]interface{}{
		"command-line": cmdLine,
	}

	resp, err := sm.monitor.Run(ctx, "human-monitor-command", args)
	if err != nil {
		return ErrSnapshotCreateFailed{Name: name, Cause: err}
	}

	// Parse the response to check for errors
	if err := sm.parseHumanMonitorResponse(resp, "savevm"); err != nil {
		return ErrSnapshotCreateFailed{Name: name, Cause: err}
	}

	sm.logger.Infof("Successfully created VM snapshot: %s", name)
	return nil
}

// Restore restores the VM to a previously saved snapshot.
func (sm *SnapshotManager) Restore(ctx context.Context, name string) error {
	if err := sm.validateName(name); err != nil {
		return err
	}

	if !sm.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	sm.logger.Infof("Restoring VM snapshot: %s", name)

	// Use human-monitor-command for loadvm
	cmdLine := "loadvm " + name
	args := map[string]interface{}{
		"command-line": cmdLine,
	}

	resp, err := sm.monitor.Run(ctx, "human-monitor-command", args)
	if err != nil {
		return ErrSnapshotRestoreFailed{Name: name, Cause: err}
	}

	// Parse the response to check for errors
	if err := sm.parseHumanMonitorResponse(resp, "loadvm"); err != nil {
		// Check if this is a "snapshot not found" error
		if strings.Contains(strings.ToLower(string(resp)), "not found") ||
			strings.Contains(strings.ToLower(string(resp)), "no snapshot") {
			return ErrSnapshotNotFound{Name: name}
		}
		return ErrSnapshotRestoreFailed{Name: name, Cause: err}
	}

	sm.logger.Infof("Successfully restored VM snapshot: %s", name)
	return nil
}

// Delete removes a snapshot from the VM.
func (sm *SnapshotManager) Delete(ctx context.Context, name string) error {
	if err := sm.validateName(name); err != nil {
		return err
	}

	if !sm.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	sm.logger.Infof("Deleting VM snapshot: %s", name)

	// Use human-monitor-command for delvm
	cmdLine := "delvm " + name
	args := map[string]interface{}{
		"command-line": cmdLine,
	}

	resp, err := sm.monitor.Run(ctx, "human-monitor-command", args)
	if err != nil {
		return ErrSnapshotDeleteFailed{Name: name, Cause: err}
	}

	// Parse the response to check for errors
	if err := sm.parseHumanMonitorResponse(resp, "delvm"); err != nil {
		// Check if this is a "snapshot not found" error
		if strings.Contains(strings.ToLower(string(resp)), "not found") ||
			strings.Contains(strings.ToLower(string(resp)), "no snapshot") {
			return ErrSnapshotNotFound{Name: name}
		}
		return ErrSnapshotDeleteFailed{Name: name, Cause: err}
	}

	sm.logger.Infof("Successfully deleted VM snapshot: %s", name)
	return nil
}

// List returns all snapshots for the VM.
func (sm *SnapshotManager) List(ctx context.Context) ([]SnapshotInfo, error) {
	if !sm.monitor.IsConnected() {
		return nil, ErrMonitorNotConnected{}
	}

	sm.logger.Debug("Listing VM snapshots")

	// Use human-monitor-command for info snapshots
	args := map[string]interface{}{
		"command-line": "info snapshots",
	}

	resp, err := sm.monitor.Run(ctx, "human-monitor-command", args)
	if err != nil {
		return nil, ErrSnapshotListFailed{Cause: err}
	}

	// Parse the human-readable output
	snapshots, err := sm.parseSnapshotList(resp)
	if err != nil {
		return nil, ErrSnapshotListFailed{Cause: err}
	}

	sm.logger.Debugf("Found %d VM snapshots", len(snapshots))
	return snapshots, nil
}

// Exists checks if a snapshot with the given name exists.
func (sm *SnapshotManager) Exists(ctx context.Context, name string) (bool, error) {
	if err := sm.validateName(name); err != nil {
		return false, err
	}

	snapshots, err := sm.List(ctx)
	if err != nil {
		return false, err
	}

	for _, snap := range snapshots {
		if snap.Name == name {
			return true, nil
		}
	}
	return false, nil
}

// Get retrieves information about a specific snapshot.
func (sm *SnapshotManager) Get(ctx context.Context, name string) (*SnapshotInfo, error) {
	if err := sm.validateName(name); err != nil {
		return nil, err
	}

	snapshots, err := sm.List(ctx)
	if err != nil {
		return nil, err
	}

	for i := range snapshots {
		if snapshots[i].Name == name {
			return &snapshots[i], nil
		}
	}
	return nil, ErrSnapshotNotFound{Name: name}
}

// validateName checks if a snapshot name is valid.
func (sm *SnapshotManager) validateName(name string) error {
	if name == "" {
		return ErrSnapshotInvalidName{Name: name, Reason: "name cannot be empty"}
	}

	if len(name) > 128 {
		return ErrSnapshotInvalidName{Name: name, Reason: "name exceeds maximum length of 128 characters"}
	}

	if !snapshotNameRegex.MatchString(name) {
		return ErrSnapshotInvalidName{
			Name:   name,
			Reason: "name must start with letter or underscore and contain only alphanumeric characters, underscores, hyphens, and dots",
		}
	}

	// Check for reserved names
	reserved := []string{"all", "none", "default"}
	nameLower := strings.ToLower(name)
	for _, r := range reserved {
		if nameLower == r {
			return ErrSnapshotInvalidName{Name: name, Reason: "name is reserved"}
		}
	}

	return nil
}

// parseHumanMonitorResponse parses the response from a human-monitor-command
// and checks for error messages.
func (sm *SnapshotManager) parseHumanMonitorResponse(resp []byte, command string) error {
	// The response is JSON with a "return" field containing the output string
	var result struct {
		Return string `json:"return"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return ErrMonitorInvalidResponse{Command: command, Cause: err}
	}

	// Check for error indicators in the response
	output := strings.ToLower(result.Return)
	if strings.Contains(output, "error") ||
		strings.Contains(output, "failed") ||
		strings.Contains(output, "cannot") ||
		strings.Contains(output, "no block device") ||
		strings.Contains(output, "not found") {
		return ErrMonitorCommandFailed{
			Command: command,
			Cause:   &humanMonitorError{message: result.Return},
		}
	}

	return nil
}

// humanMonitorError wraps an error message from human-monitor-command output.
type humanMonitorError struct {
	message string
}

func (e *humanMonitorError) Error() string {
	return strings.TrimSpace(e.message)
}

// parseSnapshotList parses the output of "info snapshots" command.
// Example output:
// ID        TAG               VM SIZE                DATE     VM CLOCK
// 1         snap1             256M 2024-01-15 10:30:00 00:05:30.123
func (sm *SnapshotManager) parseSnapshotList(resp []byte) ([]SnapshotInfo, error) {
	// Parse the JSON response first
	var result struct {
		Return string `json:"return"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "info snapshots", Cause: err}
	}

	output := result.Return
	if output == "" || strings.Contains(strings.ToLower(output), "no snapshots") {
		return []SnapshotInfo{}, nil
	}

	lines := strings.Split(output, "\n")
	var snapshots []SnapshotInfo

	// Skip header lines and empty lines
	headerFound := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Look for header line
		if strings.HasPrefix(line, "ID") || strings.Contains(line, "TAG") {
			headerFound = true
			continue
		}

		// Skip lines before header
		if !headerFound {
			continue
		}

		// Parse snapshot line
		snap, err := sm.parseSnapshotLine(line)
		if err != nil {
			sm.logger.Warnf("Failed to parse snapshot line: %s", line)
			continue
		}
		snapshots = append(snapshots, snap)
	}

	return snapshots, nil
}

// parseSnapshotLine parses a single line of snapshot info output.
// Format: ID TAG VM_SIZE DATE TIME VM_CLOCK
// Example: 1 snap1 256M 2024-01-15 10:30:00 00:05:30.123456789
func (sm *SnapshotManager) parseSnapshotLine(line string) (SnapshotInfo, error) {
	// Split on whitespace, but handle the date/time fields specially
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return SnapshotInfo{}, ErrSnapshotParseError{Line: line}
	}

	snap := SnapshotInfo{
		ID:   fields[0],
		Name: fields[1],
	}

	// Parse VM state size (e.g., "256M", "1G", "512K")
	if len(fields) > 2 {
		snap.VMStateSize = parseSize(fields[2])
	}

	// Parse date and time
	if len(fields) >= 5 {
		dateStr := fields[3] + " " + fields[4]
		// Try parsing with various formats
		formats := []string{
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"01/02/2006 15:04:05",
		}
		for _, format := range formats {
			if t, err := time.Parse(format, dateStr); err == nil {
				snap.Date = t
				break
			}
		}
	}

	// Parse VM clock time (e.g., "00:05:30.123456789")
	if len(fields) >= 6 {
		vmClock := fields[5]
		sec, nsec := parseVMClock(vmClock)
		snap.VMClockSec = sec
		snap.VMClockNsec = nsec
	}

	return snap, nil
}

// parseSize parses a human-readable size string (e.g., "256M") to bytes.
func parseSize(s string) uint64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}

	// Extract numeric part and suffix
	var numStr string
	var suffix string
	for i, c := range s {
		if c >= '0' && c <= '9' || c == '.' {
			numStr += string(c)
		} else {
			suffix = s[i:]
			break
		}
	}

	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0
	}

	multiplier := uint64(1)
	switch strings.ToUpper(strings.TrimSpace(suffix)) {
	case "K", "KB":
		multiplier = 1024
	case "M", "MB":
		multiplier = 1024 * 1024
	case "G", "GB":
		multiplier = 1024 * 1024 * 1024
	case "T", "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	}

	return uint64(num * float64(multiplier))
}

// parseVMClock parses a VM clock string (e.g., "00:05:30.123456789")
// into seconds and nanoseconds components.
func parseVMClock(s string) (uint64, uint64) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0
	}

	// Split on decimal point for nanoseconds
	parts := strings.SplitN(s, ".", 2)
	timePart := parts[0]

	var nsec uint64
	if len(parts) > 1 {
		// Parse fractional seconds
		fracStr := parts[1]
		// Pad or truncate to 9 digits
		for len(fracStr) < 9 {
			fracStr += "0"
		}
		if len(fracStr) > 9 {
			fracStr = fracStr[:9]
		}
		nsec, _ = strconv.ParseUint(fracStr, 10, 64)
	}

	// Parse HH:MM:SS
	timeParts := strings.Split(timePart, ":")
	var sec uint64
	if len(timeParts) >= 3 {
		hours, _ := strconv.ParseUint(timeParts[0], 10, 64)
		minutes, _ := strconv.ParseUint(timeParts[1], 10, 64)
		seconds, _ := strconv.ParseUint(timeParts[2], 10, 64)
		sec = hours*3600 + minutes*60 + seconds
	} else if len(timeParts) >= 1 {
		sec, _ = strconv.ParseUint(timeParts[0], 10, 64)
	}

	return sec, nsec
}

// IsValidSnapshotName validates a snapshot name without creating a manager.
func IsValidSnapshotName(name string) bool {
	if name == "" || len(name) > 128 {
		return false
	}

	if !snapshotNameRegex.MatchString(name) {
		return false
	}

	// Check for reserved names
	reserved := []string{"all", "none", "default"}
	nameLower := strings.ToLower(name)
	for _, r := range reserved {
		if nameLower == r {
			return false
		}
	}

	return true
}
