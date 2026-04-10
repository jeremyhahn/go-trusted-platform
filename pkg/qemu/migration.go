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
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// MigrationStatusType represents the current state of a migration.
type MigrationStatusType string

const (
	// MigrationStatusNone indicates no migration is active.
	MigrationStatusNone MigrationStatusType = "none"

	// MigrationStatusSetup indicates migration is being set up.
	MigrationStatusSetup MigrationStatusType = "setup"

	// MigrationStatusActive indicates migration is actively transferring data.
	MigrationStatusActive MigrationStatusType = "active"

	// MigrationStatusPostcopyActive indicates postcopy migration is active.
	MigrationStatusPostcopyActive MigrationStatusType = "postcopy-active"

	// MigrationStatusPostcopyPaused indicates postcopy migration is paused.
	MigrationStatusPostcopyPaused MigrationStatusType = "postcopy-paused"

	// MigrationStatusPostcopyRecover indicates postcopy is recovering.
	MigrationStatusPostcopyRecover MigrationStatusType = "postcopy-recover"

	// MigrationStatusCompleted indicates migration completed successfully.
	MigrationStatusCompleted MigrationStatusType = "completed"

	// MigrationStatusFailed indicates migration failed.
	MigrationStatusFailed MigrationStatusType = "failed"

	// MigrationStatusCancelling indicates migration is being cancelled.
	MigrationStatusCancelling MigrationStatusType = "cancelling"

	// MigrationStatusCancelled indicates migration was cancelled.
	MigrationStatusCancelled MigrationStatusType = "cancelled"

	// MigrationStatusPreSwitchover indicates migration is ready to switchover.
	MigrationStatusPreSwitchover MigrationStatusType = "pre-switchover"

	// MigrationStatusDevice indicates device state is being transferred.
	MigrationStatusDevice MigrationStatusType = "device"

	// MigrationStatusWaitUnplug indicates waiting for device unplug.
	MigrationStatusWaitUnplug MigrationStatusType = "wait-unplug"
)

// RAMStats contains statistics about RAM transfer during migration.
type RAMStats struct {
	// Transferred is the total bytes transferred.
	Transferred int64 `json:"transferred"`

	// Remaining is the bytes remaining to transfer.
	Remaining int64 `json:"remaining"`

	// Total is the total RAM size.
	Total int64 `json:"total"`

	// Duplicate is the number of duplicate pages.
	Duplicate int64 `json:"duplicate"`

	// Skipped is the number of skipped pages.
	Skipped int64 `json:"skipped"`

	// Normal is the number of normal pages transferred.
	Normal int64 `json:"normal"`

	// NormalBytes is the bytes of normal pages transferred.
	NormalBytes int64 `json:"normal-bytes"`

	// DirtyPagesRate is the rate of dirty pages per second.
	DirtyPagesRate int64 `json:"dirty-pages-rate"`

	// DirtySync is the number of dirty sync iterations.
	DirtySync int64 `json:"dirty-sync-count"`

	// Mbps is the transfer rate in megabits per second.
	Mbps float64 `json:"mbps"`

	// PageSize is the page size in bytes.
	PageSize int64 `json:"page-size"`

	// PostcopyRequests is the number of postcopy requests.
	PostcopyRequests int64 `json:"postcopy-requests"`
}

// DiskStats contains statistics about disk transfer during migration.
type DiskStats struct {
	// Transferred is the total bytes transferred.
	Transferred int64 `json:"transferred"`

	// Remaining is the bytes remaining to transfer.
	Remaining int64 `json:"remaining"`

	// Total is the total disk size.
	Total int64 `json:"total"`
}

// MigrationStatus contains the current state and statistics of a migration.
type MigrationStatus struct {
	// Status is the current migration status.
	Status MigrationStatusType `json:"status"`

	// TotalTime is the total migration time in milliseconds.
	TotalTime int64 `json:"total-time"`

	// SetupTime is the time spent in setup phase in milliseconds.
	SetupTime int64 `json:"setup-time"`

	// ExpectedDowntime is the expected downtime in milliseconds.
	ExpectedDowntime int64 `json:"expected-downtime"`

	// Downtime is the actual downtime in milliseconds (after completion).
	Downtime int64 `json:"downtime"`

	// RAM contains RAM transfer statistics.
	RAM *RAMStats `json:"ram,omitempty"`

	// Disk contains disk transfer statistics.
	Disk *DiskStats `json:"disk,omitempty"`

	// ErrorDescription contains error details if migration failed.
	ErrorDescription string `json:"error-desc,omitempty"`

	// Blocked indicates if migration is blocked.
	Blocked bool `json:"blocked"`

	// BlockedReasons contains the reasons migration is blocked.
	BlockedReasons []string `json:"blocked-reasons,omitempty"`
}

// MigrationCapability represents a single migration capability.
type MigrationCapability struct {
	// Capability is the name of the capability.
	Capability string `json:"capability"`

	// State indicates if the capability is enabled.
	State bool `json:"state"`
}

// MigrationCapabilities contains available migration capabilities.
type MigrationCapabilities struct {
	// XBZRLE enables XBZRLE compression.
	XBZRLE bool `json:"xbzrle"`

	// RDMA enables RDMA migration.
	RDMA bool `json:"rdma-pin-all"`

	// AutoConverge enables auto-convergence.
	AutoConverge bool `json:"auto-converge"`

	// ZeroBlocks enables zero block detection.
	ZeroBlocks bool `json:"zero-blocks"`

	// Compress enables compression.
	Compress bool `json:"compress"`

	// Events enables migration events.
	Events bool `json:"events"`

	// Postcopy enables postcopy migration.
	Postcopy bool `json:"postcopy-ram"`

	// XCopy enables x-colo capability.
	XColo bool `json:"x-colo"`

	// ReleaseRAM releases RAM after transfer.
	ReleaseRAM bool `json:"release-ram"`

	// ReturnPath enables return path.
	ReturnPath bool `json:"return-path"`

	// PauseBeforeSwitchover pauses before switchover.
	PauseBeforeSwitchover bool `json:"pause-before-switchover"`

	// Multifd enables multifd migration.
	Multifd bool `json:"multifd"`

	// DirtyBitmaps migrates dirty bitmaps.
	DirtyBitmaps bool `json:"dirty-bitmaps"`

	// LateBlockActivate activates blocks late.
	LateBlockActivate bool `json:"late-block-activate"`

	// ValidateUUID validates destination UUID.
	ValidateUUID bool `json:"validate-uuid"`

	// BackgroundSnapshot enables background snapshot.
	BackgroundSnapshot bool `json:"background-snapshot"`

	// ZeroPageDetection enables zero page detection.
	ZeroPageDetection bool `json:"zero-page-detection"`
}

// MigrationParams contains migration parameters.
type MigrationParams struct {
	// MaxBandwidth is the maximum bandwidth in bytes per second.
	MaxBandwidth int64 `json:"max-bandwidth,omitempty"`

	// DowntimeLimit is the maximum allowed downtime in milliseconds.
	DowntimeLimit int64 `json:"downtime-limit,omitempty"`

	// CompressLevel is the compression level (0-9).
	CompressLevel int `json:"compress-level,omitempty"`

	// CompressThreads is the number of compression threads.
	CompressThreads int `json:"compress-threads,omitempty"`

	// DecompressThreads is the number of decompression threads.
	DecompressThreads int `json:"decompress-threads,omitempty"`

	// CPUThrottleInitial is the initial CPU throttle percentage.
	CPUThrottleInitial int `json:"cpu-throttle-initial,omitempty"`

	// CPUThrottleIncrement is the CPU throttle increment percentage.
	CPUThrottleIncrement int `json:"cpu-throttle-increment,omitempty"`

	// CPUThrottleTailslow enables tail slow CPU throttle.
	CPUThrottleTailslow bool `json:"cpu-throttle-tailslow,omitempty"`

	// TLSCreds is the TLS credentials ID.
	TLSCreds string `json:"tls-creds,omitempty"`

	// TLSHostname is the TLS hostname for verification.
	TLSHostname string `json:"tls-hostname,omitempty"`

	// TLSAuthz is the TLS authorization ID.
	TLSAuthz string `json:"tls-authz,omitempty"`

	// MaxPostcopyBandwidth is the maximum postcopy bandwidth.
	MaxPostcopyBandwidth int64 `json:"max-postcopy-bandwidth,omitempty"`

	// MultifdChannels is the number of multifd channels.
	MultifdChannels int `json:"multifd-channels,omitempty"`

	// MultifdCompression is the multifd compression method.
	MultifdCompression string `json:"multifd-compression,omitempty"`

	// MultifdZlibLevel is the multifd zlib compression level.
	MultifdZlibLevel int `json:"multifd-zlib-level,omitempty"`

	// MultifdZstdLevel is the multifd zstd compression level.
	MultifdZstdLevel int `json:"multifd-zstd-level,omitempty"`

	// XBZRLECacheSize is the XBZRLE cache size.
	XBZRLECacheSize int64 `json:"xbzrle-cache-size,omitempty"`

	// BlockIncremental enables incremental block migration.
	BlockIncremental bool `json:"block-incremental,omitempty"`

	// AnnounceInitial is the initial self-announce delay.
	AnnounceInitial int `json:"announce-initial,omitempty"`

	// AnnounceMax is the maximum self-announce delay.
	AnnounceMax int `json:"announce-max,omitempty"`

	// AnnounceRounds is the number of self-announce rounds.
	AnnounceRounds int `json:"announce-rounds,omitempty"`

	// AnnounceStep is the self-announce step increase.
	AnnounceStep int `json:"announce-step,omitempty"`
}

// MigrationManager handles QEMU live migration operations.
type MigrationManager struct {
	monitor *Monitor
	logger  *logging.Logger
}

// NewMigrationManager creates a new MigrationManager using the provided Monitor.
func NewMigrationManager(monitor *Monitor, logger *logging.Logger) *MigrationManager {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &MigrationManager{
		monitor: monitor,
		logger:  logger,
	}
}

// Migrate initiates a live migration to the specified URI.
// The URI format depends on the migration protocol:
//   - TCP: tcp:host:port
//   - Unix socket: unix:path
//   - Exec: exec:command
//   - FD: fd:fdname
func (m *MigrationManager) Migrate(ctx context.Context, uri string) error {
	if err := m.validateURI(uri); err != nil {
		return err
	}

	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Infof("Starting migration to %s", uri)

	args := map[string]interface{}{
		"uri": uri,
	}

	_, err := m.monitor.Run(ctx, "migrate", args)
	if err != nil {
		return ErrMigrationFailed{URI: uri, Cause: err}
	}

	return nil
}

// MigrateIncoming prepares the destination VM to receive an incoming migration.
// The URI format should match the source migration URI.
func (m *MigrationManager) MigrateIncoming(ctx context.Context, uri string) error {
	if err := m.validateURI(uri); err != nil {
		return err
	}

	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Infof("Preparing for incoming migration on %s", uri)

	args := map[string]interface{}{
		"uri": uri,
	}

	_, err := m.monitor.Run(ctx, "migrate-incoming", args)
	if err != nil {
		return ErrMigrationSetupFailed{Operation: "migrate-incoming", Cause: err}
	}

	return nil
}

// Status queries the current migration status.
func (m *MigrationManager) Status(ctx context.Context) (*MigrationStatus, error) {
	if !m.monitor.IsConnected() {
		return nil, ErrMonitorNotConnected{}
	}

	resp, err := m.monitor.Run(ctx, "query-migrate", nil)
	if err != nil {
		return nil, ErrMonitorCommandFailed{Command: "query-migrate", Cause: err}
	}

	var result struct {
		Return struct {
			Status           string   `json:"status"`
			TotalTime        int64    `json:"total-time"`
			SetupTime        int64    `json:"setup-time"`
			ExpectedDowntime int64    `json:"expected-downtime"`
			Downtime         int64    `json:"downtime"`
			ErrorDesc        string   `json:"error-desc"`
			Blocked          bool     `json:"blocked"`
			BlockedReasons   []string `json:"blocked-reasons"`
			RAM              *struct {
				Transferred      int64   `json:"transferred"`
				Remaining        int64   `json:"remaining"`
				Total            int64   `json:"total"`
				Duplicate        int64   `json:"duplicate"`
				Skipped          int64   `json:"skipped"`
				Normal           int64   `json:"normal"`
				NormalBytes      int64   `json:"normal-bytes"`
				DirtyPagesRate   int64   `json:"dirty-pages-rate"`
				DirtySyncCount   int64   `json:"dirty-sync-count"`
				Mbps             float64 `json:"mbps"`
				PageSize         int64   `json:"page-size"`
				PostcopyRequests int64   `json:"postcopy-requests"`
			} `json:"ram"`
			Disk *struct {
				Transferred int64 `json:"transferred"`
				Remaining   int64 `json:"remaining"`
				Total       int64 `json:"total"`
			} `json:"disk"`
		} `json:"return"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "query-migrate", Cause: err}
	}

	status := &MigrationStatus{
		Status:           parseMigrationStatus(result.Return.Status),
		TotalTime:        result.Return.TotalTime,
		SetupTime:        result.Return.SetupTime,
		ExpectedDowntime: result.Return.ExpectedDowntime,
		Downtime:         result.Return.Downtime,
		ErrorDescription: result.Return.ErrorDesc,
		Blocked:          result.Return.Blocked,
		BlockedReasons:   result.Return.BlockedReasons,
	}

	if result.Return.RAM != nil {
		status.RAM = &RAMStats{
			Transferred:      result.Return.RAM.Transferred,
			Remaining:        result.Return.RAM.Remaining,
			Total:            result.Return.RAM.Total,
			Duplicate:        result.Return.RAM.Duplicate,
			Skipped:          result.Return.RAM.Skipped,
			Normal:           result.Return.RAM.Normal,
			NormalBytes:      result.Return.RAM.NormalBytes,
			DirtyPagesRate:   result.Return.RAM.DirtyPagesRate,
			DirtySync:        result.Return.RAM.DirtySyncCount,
			Mbps:             result.Return.RAM.Mbps,
			PageSize:         result.Return.RAM.PageSize,
			PostcopyRequests: result.Return.RAM.PostcopyRequests,
		}
	}

	if result.Return.Disk != nil {
		status.Disk = &DiskStats{
			Transferred: result.Return.Disk.Transferred,
			Remaining:   result.Return.Disk.Remaining,
			Total:       result.Return.Disk.Total,
		}
	}

	return status, nil
}

// Cancel cancels an in-progress migration.
func (m *MigrationManager) Cancel(ctx context.Context) error {
	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Cancelling migration")

	_, err := m.monitor.Run(ctx, "migrate_cancel", nil)
	if err != nil {
		return ErrMonitorCommandFailed{Command: "migrate_cancel", Cause: err}
	}

	return nil
}

// SetParameters sets migration parameters.
func (m *MigrationManager) SetParameters(ctx context.Context, params *MigrationParams) error {
	if params == nil {
		return ErrMigrationParameterInvalid{Parameter: "params", Value: nil}
	}

	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Debug("Setting migration parameters")

	args := make(map[string]interface{})

	if params.MaxBandwidth > 0 {
		args["max-bandwidth"] = params.MaxBandwidth
	}
	if params.DowntimeLimit > 0 {
		args["downtime-limit"] = params.DowntimeLimit
	}
	if params.CompressLevel > 0 {
		if params.CompressLevel > 9 {
			return ErrMigrationParameterInvalid{Parameter: "compress-level", Value: params.CompressLevel}
		}
		args["compress-level"] = params.CompressLevel
	}
	if params.CompressThreads > 0 {
		args["compress-threads"] = params.CompressThreads
	}
	if params.DecompressThreads > 0 {
		args["decompress-threads"] = params.DecompressThreads
	}
	if params.CPUThrottleInitial > 0 {
		args["cpu-throttle-initial"] = params.CPUThrottleInitial
	}
	if params.CPUThrottleIncrement > 0 {
		args["cpu-throttle-increment"] = params.CPUThrottleIncrement
	}
	if params.CPUThrottleTailslow {
		args["cpu-throttle-tailslow"] = params.CPUThrottleTailslow
	}
	if params.TLSCreds != "" {
		args["tls-creds"] = params.TLSCreds
	}
	if params.TLSHostname != "" {
		args["tls-hostname"] = params.TLSHostname
	}
	if params.TLSAuthz != "" {
		args["tls-authz"] = params.TLSAuthz
	}
	if params.MaxPostcopyBandwidth > 0 {
		args["max-postcopy-bandwidth"] = params.MaxPostcopyBandwidth
	}
	if params.MultifdChannels > 0 {
		args["multifd-channels"] = params.MultifdChannels
	}
	if params.MultifdCompression != "" {
		args["multifd-compression"] = params.MultifdCompression
	}
	if params.MultifdZlibLevel > 0 {
		args["multifd-zlib-level"] = params.MultifdZlibLevel
	}
	if params.MultifdZstdLevel > 0 {
		args["multifd-zstd-level"] = params.MultifdZstdLevel
	}
	if params.XBZRLECacheSize > 0 {
		args["xbzrle-cache-size"] = params.XBZRLECacheSize
	}
	if params.BlockIncremental {
		args["block-incremental"] = params.BlockIncremental
	}
	if params.AnnounceInitial > 0 {
		args["announce-initial"] = params.AnnounceInitial
	}
	if params.AnnounceMax > 0 {
		args["announce-max"] = params.AnnounceMax
	}
	if params.AnnounceRounds > 0 {
		args["announce-rounds"] = params.AnnounceRounds
	}
	if params.AnnounceStep > 0 {
		args["announce-step"] = params.AnnounceStep
	}

	if len(args) == 0 {
		return nil
	}

	_, err := m.monitor.Run(ctx, "migrate-set-parameters", args)
	if err != nil {
		return ErrMigrationSetupFailed{Operation: "set-parameters", Cause: err}
	}

	return nil
}

// GetParameters retrieves the current migration parameters.
func (m *MigrationManager) GetParameters(ctx context.Context) (*MigrationParams, error) {
	if !m.monitor.IsConnected() {
		return nil, ErrMonitorNotConnected{}
	}

	resp, err := m.monitor.Run(ctx, "query-migrate-parameters", nil)
	if err != nil {
		return nil, ErrMonitorCommandFailed{Command: "query-migrate-parameters", Cause: err}
	}

	var result struct {
		Return struct {
			MaxBandwidth         int64  `json:"max-bandwidth"`
			DowntimeLimit        int64  `json:"downtime-limit"`
			CompressLevel        int    `json:"compress-level"`
			CompressThreads      int    `json:"compress-threads"`
			DecompressThreads    int    `json:"decompress-threads"`
			CPUThrottleInitial   int    `json:"cpu-throttle-initial"`
			CPUThrottleIncrement int    `json:"cpu-throttle-increment"`
			CPUThrottleTailslow  bool   `json:"cpu-throttle-tailslow"`
			TLSCreds             string `json:"tls-creds"`
			TLSHostname          string `json:"tls-hostname"`
			TLSAuthz             string `json:"tls-authz"`
			MaxPostcopyBandwidth int64  `json:"max-postcopy-bandwidth"`
			MultifdChannels      int    `json:"multifd-channels"`
			MultifdCompression   string `json:"multifd-compression"`
			MultifdZlibLevel     int    `json:"multifd-zlib-level"`
			MultifdZstdLevel     int    `json:"multifd-zstd-level"`
			XBZRLECacheSize      int64  `json:"xbzrle-cache-size"`
			BlockIncremental     bool   `json:"block-incremental"`
			AnnounceInitial      int    `json:"announce-initial"`
			AnnounceMax          int    `json:"announce-max"`
			AnnounceRounds       int    `json:"announce-rounds"`
			AnnounceStep         int    `json:"announce-step"`
		} `json:"return"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "query-migrate-parameters", Cause: err}
	}

	return &MigrationParams{
		MaxBandwidth:         result.Return.MaxBandwidth,
		DowntimeLimit:        result.Return.DowntimeLimit,
		CompressLevel:        result.Return.CompressLevel,
		CompressThreads:      result.Return.CompressThreads,
		DecompressThreads:    result.Return.DecompressThreads,
		CPUThrottleInitial:   result.Return.CPUThrottleInitial,
		CPUThrottleIncrement: result.Return.CPUThrottleIncrement,
		CPUThrottleTailslow:  result.Return.CPUThrottleTailslow,
		TLSCreds:             result.Return.TLSCreds,
		TLSHostname:          result.Return.TLSHostname,
		TLSAuthz:             result.Return.TLSAuthz,
		MaxPostcopyBandwidth: result.Return.MaxPostcopyBandwidth,
		MultifdChannels:      result.Return.MultifdChannels,
		MultifdCompression:   result.Return.MultifdCompression,
		MultifdZlibLevel:     result.Return.MultifdZlibLevel,
		MultifdZstdLevel:     result.Return.MultifdZstdLevel,
		XBZRLECacheSize:      result.Return.XBZRLECacheSize,
		BlockIncremental:     result.Return.BlockIncremental,
		AnnounceInitial:      result.Return.AnnounceInitial,
		AnnounceMax:          result.Return.AnnounceMax,
		AnnounceRounds:       result.Return.AnnounceRounds,
		AnnounceStep:         result.Return.AnnounceStep,
	}, nil
}

// SetCapabilities enables the specified migration capabilities.
func (m *MigrationManager) SetCapabilities(ctx context.Context, caps []string) error {
	if len(caps) == 0 {
		return nil
	}

	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Debugf("Setting migration capabilities: %v", caps)

	capabilities := make([]map[string]interface{}, 0, len(caps))
	for _, cap := range caps {
		capabilities = append(capabilities, map[string]interface{}{
			"capability": cap,
			"state":      true,
		})
	}

	args := map[string]interface{}{
		"capabilities": capabilities,
	}

	_, err := m.monitor.Run(ctx, "migrate-set-capabilities", args)
	if err != nil {
		return ErrMigrationSetupFailed{Operation: "set-capabilities", Cause: err}
	}

	return nil
}

// GetCapabilities retrieves the current migration capabilities.
func (m *MigrationManager) GetCapabilities(ctx context.Context) ([]MigrationCapability, error) {
	if !m.monitor.IsConnected() {
		return nil, ErrMonitorNotConnected{}
	}

	resp, err := m.monitor.Run(ctx, "query-migrate-capabilities", nil)
	if err != nil {
		return nil, ErrMonitorCommandFailed{Command: "query-migrate-capabilities", Cause: err}
	}

	var result struct {
		Return []struct {
			Capability string `json:"capability"`
			State      bool   `json:"state"`
		} `json:"return"`
	}

	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, ErrMonitorInvalidResponse{Command: "query-migrate-capabilities", Cause: err}
	}

	capabilities := make([]MigrationCapability, 0, len(result.Return))
	for _, cap := range result.Return {
		capabilities = append(capabilities, MigrationCapability{
			Capability: cap.Capability,
			State:      cap.State,
		})
	}

	return capabilities, nil
}

// ContinueMigration continues a paused migration (e.g., after pre-switchover pause).
func (m *MigrationManager) ContinueMigration(ctx context.Context) error {
	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Continuing paused migration")

	_, err := m.monitor.Run(ctx, "migrate-continue", nil)
	if err != nil {
		return ErrMonitorCommandFailed{Command: "migrate-continue", Cause: err}
	}

	return nil
}

// StartPostcopy switches to postcopy migration mode.
func (m *MigrationManager) StartPostcopy(ctx context.Context) error {
	if !m.monitor.IsConnected() {
		return ErrMonitorNotConnected{}
	}

	m.logger.Info("Starting postcopy migration")

	_, err := m.monitor.Run(ctx, "migrate-start-postcopy", nil)
	if err != nil {
		return ErrMonitorCommandFailed{Command: "migrate-start-postcopy", Cause: err}
	}

	return nil
}

// validateURI validates the migration URI format.
func (m *MigrationManager) validateURI(uri string) error {
	if uri == "" {
		return ErrMigrationInvalidURI{URI: uri}
	}

	// Validate URI protocol prefix
	validPrefixes := []string{"tcp:", "unix:", "exec:", "fd:", "rdma:"}
	hasValidPrefix := false
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(uri, prefix) {
			hasValidPrefix = true
			break
		}
	}

	if !hasValidPrefix {
		return ErrMigrationInvalidURI{URI: uri}
	}

	return nil
}

// parseMigrationStatus converts a QEMU status string to MigrationStatusType.
func parseMigrationStatus(status string) MigrationStatusType {
	switch status {
	case "none":
		return MigrationStatusNone
	case "setup":
		return MigrationStatusSetup
	case "active":
		return MigrationStatusActive
	case "postcopy-active":
		return MigrationStatusPostcopyActive
	case "postcopy-paused":
		return MigrationStatusPostcopyPaused
	case "postcopy-recover":
		return MigrationStatusPostcopyRecover
	case "completed":
		return MigrationStatusCompleted
	case "failed":
		return MigrationStatusFailed
	case "cancelling":
		return MigrationStatusCancelling
	case "cancelled":
		return MigrationStatusCancelled
	case "pre-switchover":
		return MigrationStatusPreSwitchover
	case "device":
		return MigrationStatusDevice
	case "wait-unplug":
		return MigrationStatusWaitUnplug
	default:
		return MigrationStatusNone
	}
}

// GetMonitor returns the underlying Monitor instance.
func (m *MigrationManager) GetMonitor() *Monitor {
	return m.monitor
}
