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
	"os"
	"sync/atomic"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// VMStatus represents the current status of a QEMU virtual machine.
type VMStatus string

const (
	// VMStatusRunning indicates the VM is running normally.
	VMStatusRunning VMStatus = "running"

	// VMStatusPaused indicates the VM execution is paused.
	VMStatusPaused VMStatus = "paused"

	// VMStatusShutdown indicates the VM has been shut down.
	VMStatusShutdown VMStatus = "shutdown"

	// VMStatusPrelaunch indicates the VM is in prelaunch state.
	VMStatusPrelaunch VMStatus = "prelaunch"

	// VMStatusIOError indicates the VM has encountered an I/O error.
	VMStatusIOError VMStatus = "io-error"

	// VMStatusInternalError indicates the VM has encountered an internal error.
	VMStatusInternalError VMStatus = "internal-error"

	// VMStatusSuspended indicates the VM is suspended.
	VMStatusSuspended VMStatus = "suspended"

	// VMStatusGuestPanicked indicates the guest has panicked.
	VMStatusGuestPanicked VMStatus = "guest-panicked"

	// VMStatusUnknown indicates an unknown status.
	VMStatusUnknown VMStatus = "unknown"
)

// BlockDevice represents a QEMU block device.
type BlockDevice struct {
	Device    string           `json:"device"`
	Locked    bool             `json:"locked"`
	Removable bool             `json:"removable"`
	QDev      string           `json:"qdev,omitempty"`
	Type      string           `json:"type"`
	Inserted  *BlockDeviceInfo `json:"inserted,omitempty"`
}

// BlockDeviceInfo represents detailed information about an inserted block device.
type BlockDeviceInfo struct {
	File             string `json:"file"`
	NodeName         string `json:"node-name"`
	RO               bool   `json:"ro"`
	DRV              string `json:"drv"`
	BackingFile      string `json:"backing_file,omitempty"`
	BackingFileDepth int    `json:"backing_file_depth,omitempty"`
	Encrypted        bool   `json:"encrypted"`
	DetectZeroes     string `json:"detect_zeroes"`
	BPS              int64  `json:"bps"`
	BPSRead          int64  `json:"bps_rd"`
	BPSWrite         int64  `json:"bps_wr"`
	IOPS             int64  `json:"iops"`
	IOPSRead         int64  `json:"iops_rd"`
	IOPSWrite        int64  `json:"iops_wr"`
	Image            *Image `json:"image,omitempty"`
	Cache            *Cache `json:"cache,omitempty"`
}

// Image represents block device image information.
type Image struct {
	Filename              string `json:"filename"`
	Format                string `json:"format"`
	VirtualSize           int64  `json:"virtual-size"`
	ActualSize            int64  `json:"actual-size,omitempty"`
	DirtyFlag             bool   `json:"dirty-flag"`
	ClusterSize           int64  `json:"cluster-size,omitempty"`
	BackingFilename       string `json:"backing-filename,omitempty"`
	FullBackingFilename   string `json:"full-backing-filename,omitempty"`
	BackingFilenameFormat string `json:"backing-filename-format,omitempty"`
}

// Cache represents block device cache settings.
type Cache struct {
	Writeback bool `json:"writeback"`
	Direct    bool `json:"direct"`
	NoFlush   bool `json:"no-flush"`
}

// EventHandler is a function type for handling QMP events.
type EventHandler func(event qmp.Event)

// Monitor provides a high-level interface to the QEMU Machine Protocol (QMP).
// It wraps the go-qemu library's SocketMonitor to provide a clean, type-safe
// API for controlling QEMU virtual machines.
type Monitor struct {
	socketPath string
	timeout    time.Duration
	logger     *logging.Logger
	monitor    *qmp.SocketMonitor
	connected  atomic.Bool

	// Event handling
	eventChan    <-chan qmp.Event
	eventHandler EventHandler
	eventCancel  context.CancelFunc
}

// NewMonitor creates a new QMP Monitor for the specified socket path.
// The timeout parameter specifies the connection timeout duration.
func NewMonitor(socketPath string, timeout time.Duration, logger *logging.Logger) *Monitor {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &Monitor{
		socketPath: socketPath,
		timeout:    timeout,
		logger:     logger,
	}
}

// Connect establishes a connection to the QMP socket and performs
// the capabilities handshake. The context can be used for cancellation.
func (m *Monitor) Connect(ctx context.Context) error {
	if m.connected.Load() {
		return ErrMonitorAlreadyConnected{}
	}

	// Check if socket exists
	if _, err := os.Stat(m.socketPath); err != nil {
		if os.IsNotExist(err) {
			return ErrMonitorSocketNotFound{SocketPath: m.socketPath}
		}
		return ErrMonitorConnectionFailed{SocketPath: m.socketPath, Cause: err}
	}

	m.logger.Debugf("Connecting to QMP socket: %s", m.socketPath)

	// Create socket monitor with timeout
	mon, err := qmp.NewSocketMonitor("unix", m.socketPath, m.timeout)
	if err != nil {
		return ErrMonitorConnectionFailed{SocketPath: m.socketPath, Cause: err}
	}

	// Perform QMP handshake
	if err := mon.Connect(); err != nil {
		_ = mon.Disconnect()
		return ErrMonitorHandshakeFailed{Cause: err}
	}

	m.monitor = mon
	m.connected.Store(true)

	m.logger.Infof("Connected to QMP socket: %s (QEMU %s)", m.socketPath, mon.Version.String())

	return nil
}

// Close disconnects from the QMP socket and cleans up resources.
func (m *Monitor) Close() error {
	if !m.connected.Load() {
		return nil
	}

	// Cancel event listener if running
	if m.eventCancel != nil {
		m.eventCancel()
		m.eventCancel = nil
	}

	m.logger.Debug("Disconnecting from QMP socket")

	if m.monitor != nil {
		if err := m.monitor.Disconnect(); err != nil {
			m.logger.Warnf("Error disconnecting from QMP: %v", err)
		}
		m.monitor = nil
	}

	m.connected.Store(false)
	m.logger.Info("Disconnected from QMP socket")

	return nil
}

// IsConnected returns true if the monitor is currently connected.
func (m *Monitor) IsConnected() bool {
	return m.connected.Load()
}

// Status returns the current VM status.
func (m *Monitor) Status(ctx context.Context) (VMStatus, error) {
	if !m.connected.Load() {
		return VMStatusUnknown, ErrMonitorNotConnected{}
	}

	cmd := qmp.Command{Execute: "query-status"}
	rawResp, err := m.runCommand(cmd)
	if err != nil {
		return VMStatusUnknown, err
	}

	var resp struct {
		Return struct {
			Running    bool   `json:"running"`
			Singlestep bool   `json:"singlestep"`
			Status     string `json:"status"`
		} `json:"return"`
	}

	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return VMStatusUnknown, ErrMonitorInvalidResponse{Command: "query-status", Cause: err}
	}

	return parseVMStatus(resp.Return.Status), nil
}

// SystemPowerdown sends an ACPI power button event to the VM,
// requesting a graceful shutdown.
func (m *Monitor) SystemPowerdown(ctx context.Context) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Sending system_powerdown command")

	cmd := qmp.Command{Execute: "system_powerdown"}
	_, err := m.runCommand(cmd)
	return err
}

// SystemReset performs a system reset of the VM.
func (m *Monitor) SystemReset(ctx context.Context) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Sending system_reset command")

	cmd := qmp.Command{Execute: "system_reset"}
	_, err := m.runCommand(cmd)
	return err
}

// Pause pauses VM execution.
func (m *Monitor) Pause(ctx context.Context) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Sending stop command to pause VM")

	cmd := qmp.Command{Execute: "stop"}
	_, err := m.runCommand(cmd)
	return err
}

// Resume resumes VM execution after being paused.
func (m *Monitor) Resume(ctx context.Context) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Sending cont command to resume VM")

	cmd := qmp.Command{Execute: "cont"}
	_, err := m.runCommand(cmd)
	return err
}

// BlockDevices returns a list of all block devices attached to the VM.
func (m *Monitor) BlockDevices(ctx context.Context) ([]BlockDevice, error) {
	if !m.connected.Load() {
		return nil, ErrMonitorNotConnected{}
	}

	cmd := qmp.Command{Execute: "query-block"}
	rawResp, err := m.runCommand(cmd)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Return []BlockDevice `json:"return"`
	}

	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "query-block", Cause: err}
	}

	return resp.Return, nil
}

// Version returns the QEMU version information.
func (m *Monitor) Version() (*qmp.Version, error) {
	if !m.connected.Load() {
		return nil, ErrMonitorNotConnected{}
	}

	return m.monitor.Version, nil
}

// Capabilities returns the QMP capabilities reported by QEMU.
func (m *Monitor) Capabilities() ([]string, error) {
	if !m.connected.Load() {
		return nil, ErrMonitorNotConnected{}
	}

	return m.monitor.Capabilities, nil
}

// QueryCommands returns a list of all QMP commands supported by this QEMU instance.
func (m *Monitor) QueryCommands(ctx context.Context) ([]string, error) {
	if !m.connected.Load() {
		return nil, ErrMonitorNotConnected{}
	}

	cmd := qmp.Command{Execute: "query-commands"}
	rawResp, err := m.runCommand(cmd)
	if err != nil {
		return nil, err
	}

	var resp struct {
		Return []struct {
			Name string `json:"name"`
		} `json:"return"`
	}

	if err := json.Unmarshal(rawResp, &resp); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "query-commands", Cause: err}
	}

	commands := make([]string, 0, len(resp.Return))
	for _, c := range resp.Return {
		commands = append(commands, c.Name)
	}

	return commands, nil
}

// SubscribeEvents starts listening for QMP events and calls the provided
// handler function for each event received. The subscription runs until
// the context is canceled or the monitor is closed.
func (m *Monitor) SubscribeEvents(ctx context.Context, handler EventHandler) error {
	if !m.connected.Load() {
		return ErrMonitorNotConnected{}
	}

	if handler == nil {
		return ErrMonitorCommandFailed{Command: "subscribe-events", Cause: nil}
	}

	m.logger.Debug("Subscribing to QMP events")

	// Get event channel from monitor
	eventCtx, cancel := context.WithCancel(ctx)
	events, err := m.monitor.Events(eventCtx)
	if err != nil {
		cancel()
		if err == qmp.ErrEventsNotSupported {
			return ErrMonitorEventsNotSupported{}
		}
		return ErrMonitorCommandFailed{Command: "subscribe-events", Cause: err}
	}

	m.eventChan = events
	m.eventHandler = handler
	m.eventCancel = cancel

	// Start event listener goroutine
	go m.listenEvents(eventCtx)

	return nil
}

// UnsubscribeEvents stops the event subscription.
func (m *Monitor) UnsubscribeEvents() {
	if m.eventCancel != nil {
		m.eventCancel()
		m.eventCancel = nil
	}
	m.eventHandler = nil
}

// Run executes an arbitrary QMP command and returns the raw response.
// This is useful for commands not covered by the high-level API.
func (m *Monitor) Run(ctx context.Context, command string, args map[string]interface{}) ([]byte, error) {
	if !m.connected.Load() {
		return nil, ErrMonitorNotConnected{}
	}

	cmd := qmp.Command{Execute: command, Args: args}
	return m.runCommand(cmd)
}

// runCommand executes a QMP command and returns the raw response.
func (m *Monitor) runCommand(cmd qmp.Command) ([]byte, error) {
	rawCmd, err := json.Marshal(cmd)
	if err != nil {
		return nil, ErrMonitorCommandFailed{Command: cmd.Execute, Cause: err}
	}

	resp, err := m.monitor.Run(rawCmd)
	if err != nil {
		return nil, ErrMonitorCommandFailed{Command: cmd.Execute, Cause: err}
	}

	return resp, nil
}

// listenEvents runs in a goroutine to dispatch events to the handler.
func (m *Monitor) listenEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			m.logger.Debug("Event listener stopped")
			return
		case event, ok := <-m.eventChan:
			if !ok {
				m.logger.Debug("Event channel closed")
				return
			}
			if m.eventHandler != nil {
				m.eventHandler(event)
			}
		}
	}
}

// parseVMStatus converts a QEMU status string to VMStatus.
func parseVMStatus(status string) VMStatus {
	switch status {
	case "running":
		return VMStatusRunning
	case "paused":
		return VMStatusPaused
	case "shutdown":
		return VMStatusShutdown
	case "prelaunch":
		return VMStatusPrelaunch
	case "io-error":
		return VMStatusIOError
	case "internal-error":
		return VMStatusInternalError
	case "suspended":
		return VMStatusSuspended
	case "guest-panicked":
		return VMStatusGuestPanicked
	default:
		return VMStatusUnknown
	}
}

// GetSocketPath returns the QMP socket path.
func (m *Monitor) GetSocketPath() string {
	return m.socketPath
}
