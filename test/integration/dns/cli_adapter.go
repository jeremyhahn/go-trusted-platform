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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface using the platformctl CLI binary.

//go:build integration

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrCLICommandFailed is returned when a CLI command fails to execute.
type ErrCLICommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLICommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("CLI command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("CLI command %q failed: %v", e.Command, e.Err)
}

// ErrCLIOutputParseFailed is returned when CLI output cannot be parsed.
type ErrCLIOutputParseFailed struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("failed to parse CLI output for %s: %v (output: %s)", e.Operation, e.Err, e.Output)
}

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// =============================================================================
// CLI Adapter Implementation
// =============================================================================

// CLIAdapter implements DNSCommands using the platformctl CLI binary.
// This adapter executes CLI commands and parses JSON output to test
// the complete CLI workflow in integration tests.
type CLIAdapter struct {
	binaryPath     string
	socketPath     string
	commandTimeout time.Duration
}

// NewCLIAdapter creates a new CLI adapter for integration testing.
// It reads configuration from environment variables with sensible defaults.
func NewCLIAdapter() *CLIAdapter {
	binaryPath := os.Getenv(EnvPlatformctlBinary)
	if binaryPath == "" {
		binaryPath = DefaultPlatformctlBinary
	}

	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = DefaultPlatformdSocket
	}

	return &CLIAdapter{
		binaryPath:     binaryPath,
		socketPath:     socketPath,
		commandTimeout: DefaultCommandTimeout,
	}
}

// Name returns the protocol adapter identifier.
func (c *CLIAdapter) Name() string {
	return "CLI"
}

// Setup verifies the CLI binary exists and is executable.
func (c *CLIAdapter) Setup(ctx context.Context) error {
	// Check if binary exists
	if _, err := exec.LookPath(c.binaryPath); err != nil {
		return ErrCLIBinaryNotFound{Path: c.binaryPath}
	}

	// Verify binary works by running version command
	_, err := c.runCommand(ctx, "version")
	if err != nil {
		return fmt.Errorf("CLI binary verification failed: %w", err)
	}

	return nil
}

// Teardown performs cleanup (no-op for CLI adapter).
func (c *CLIAdapter) Teardown() error {
	return nil
}

// =============================================================================
// Command Execution
// =============================================================================

// runCommand executes a platformctl command and returns the output.
func (c *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	// Create context with timeout if not already set
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.commandTimeout)
		defer cancel()
	}

	// Build command with common flags
	fullArgs := []string{
		"--output", "json",
	}

	// Add socket path if specified and not default
	if c.socketPath != "" && c.socketPath != DefaultPlatformdSocket {
		fullArgs = append(fullArgs, "--socket", c.socketPath)
	}

	fullArgs = append(fullArgs, args...)

	cmd := exec.CommandContext(ctx, c.binaryPath, fullArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Include stderr in error for debugging
		output := stdout.String()
		if stderr.Len() > 0 {
			output += "\nstderr: " + stderr.String()
		}
		return nil, ErrCLICommandFailed{
			Command: strings.Join(fullArgs, " "),
			Output:  output,
			Err:     err,
		}
	}

	return stdout.Bytes(), nil
}

// =============================================================================
// Zone Management Commands
// =============================================================================

// CreateZone creates a new DNS zone via CLI.
func (c *CLIAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	args := []string{"dns", "zone", "create", opts.Name}

	if opts.TTL > 0 {
		args = append(args, "--ttl", strconv.FormatUint(uint64(opts.TTL), 10))
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	if opts.Internal {
		args = append(args, "--internal")
	}

	if opts.SOA != nil {
		if opts.SOA.MName != "" {
			args = append(args, "--soa-mname", opts.SOA.MName)
		}
		if opts.SOA.RName != "" {
			args = append(args, "--soa-rname", opts.SOA.RName)
		}
		if opts.SOA.Refresh > 0 {
			args = append(args, "--soa-refresh", strconv.FormatUint(uint64(opts.SOA.Refresh), 10))
		}
		if opts.SOA.Retry > 0 {
			args = append(args, "--soa-retry", strconv.FormatUint(uint64(opts.SOA.Retry), 10))
		}
		if opts.SOA.Expire > 0 {
			args = append(args, "--soa-expire", strconv.FormatUint(uint64(opts.SOA.Expire), 10))
		}
		if opts.SOA.MinimumTTL > 0 {
			args = append(args, "--soa-minimum", strconv.FormatUint(uint64(opts.SOA.MinimumTTL), 10))
		}
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliCreateZoneResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "CreateZone", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// GetZone retrieves zone information via CLI.
func (c *CLIAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	args := []string{"dns", "zone", "get", zoneName}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetZoneResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetZone", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// UpdateZone updates a zone via CLI.
func (c *CLIAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	args := []string{"dns", "zone", "update", zoneName}

	if opts.TTL > 0 {
		args = append(args, "--ttl", strconv.FormatUint(uint64(opts.TTL), 10))
	}

	if opts.Description != "" {
		args = append(args, "--description", opts.Description)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliUpdateZoneResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "UpdateZone", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// DeleteZone deletes a zone via CLI.
func (c *CLIAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	args := []string{"dns", "zone", "delete", zoneName, "--force"}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliDeleteZoneResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DeleteZone", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// ListZones lists zones via CLI.
func (c *CLIAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	args := []string{"dns", "zone", "list"}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(opts.Limit), 10))
	}

	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	if opts.Internal != nil {
		if *opts.Internal {
			args = append(args, "--internal")
		} else {
			args = append(args, "--external")
		}
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliListZonesResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "ListZones", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// Record Management Commands
// =============================================================================

// AddRecord adds a DNS record via CLI.
func (c *CLIAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	args := []string{"dns", "record", "add", opts.ZoneName, opts.Name, opts.RecordType, opts.Value}

	if opts.TTL > 0 {
		args = append(args, "--ttl", strconv.FormatUint(uint64(opts.TTL), 10))
	}

	if opts.Priority > 0 {
		args = append(args, "--priority", strconv.FormatUint(uint64(opts.Priority), 10))
	}

	if opts.Weight > 0 {
		args = append(args, "--weight", strconv.FormatUint(uint64(opts.Weight), 10))
	}

	if opts.Port > 0 {
		args = append(args, "--port", strconv.FormatUint(uint64(opts.Port), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliAddRecordResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "AddRecord", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// GetRecord retrieves a record via CLI.
func (c *CLIAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	args := []string{"dns", "record", "get", name, recordType}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliGetRecordResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "GetRecord", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// UpdateRecord updates a record via CLI.
func (c *CLIAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	args := []string{"dns", "record", "update", opts.ZoneName, opts.Name, opts.RecordType}

	if opts.Value != "" {
		args = append(args, "--value", opts.Value)
	}

	if opts.TTL > 0 {
		args = append(args, "--ttl", strconv.FormatUint(uint64(opts.TTL), 10))
	}

	if opts.Priority > 0 {
		args = append(args, "--priority", strconv.FormatUint(uint64(opts.Priority), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliUpdateRecordResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "UpdateRecord", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// DeleteRecord deletes a record via CLI.
func (c *CLIAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	args := []string{"dns", "record", "delete", name, recordType, "--force"}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliDeleteRecordResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "DeleteRecord", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// ListRecords lists records in a zone via CLI.
func (c *CLIAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	args := []string{"dns", "record", "list", zoneName}

	if opts.RecordType != "" {
		args = append(args, "--type", opts.RecordType)
	}

	if opts.Limit > 0 {
		args = append(args, "--limit", strconv.FormatInt(int64(opts.Limit), 10))
	}

	if opts.Cursor != "" {
		args = append(args, "--cursor", opts.Cursor)
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliListRecordsResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "ListRecords", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// Resolution Commands
// =============================================================================

// Resolve performs DNS resolution via CLI.
func (c *CLIAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	args := []string{"dns", "resolve", name, recordType}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliResolveResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "Resolve", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// TLSA/DANE Commands
// =============================================================================

// AddTLSARecord adds a TLSA record via CLI.
func (c *CLIAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	args := []string{"dns", "tlsa", "add", opts.ZoneName, opts.Name}

	args = append(args, "--usage", strconv.FormatUint(uint64(opts.Usage), 10))
	args = append(args, "--selector", strconv.FormatUint(uint64(opts.Selector), 10))
	args = append(args, "--matching-type", strconv.FormatUint(uint64(opts.MatchingType), 10))
	args = append(args, "--data", opts.Data)

	if opts.TTL > 0 {
		args = append(args, "--ttl", strconv.FormatUint(uint64(opts.TTL), 10))
	}

	output, err := c.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var result cliAddTLSARecordResponse
	if err := json.Unmarshal(output, &result); err != nil {
		return nil, ErrCLIOutputParseFailed{Operation: "AddTLSARecord", Output: string(output), Err: err}
	}

	return result.toResult(), nil
}

// =============================================================================
// CLI Response Types and Conversion
// =============================================================================

// Zone response types

type cliCreateZoneResponse struct {
	Name      string `json:"name,omitempty"`
	ID        string `json:"id,omitempty"`
	TTL       uint32 `json:"ttl,omitempty"`
	Internal  bool   `json:"internal,omitempty"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

func (r *cliCreateZoneResponse) toResult() *CreateZoneResult {
	return &CreateZoneResult{
		Name:      r.Name,
		ID:        r.ID,
		TTL:       r.TTL,
		Internal:  r.Internal,
		CreatedAt: time.Unix(r.CreatedAt, 0),
	}
}

type cliGetZoneResponse struct {
	Name        string        `json:"name,omitempty"`
	ID          string        `json:"id,omitempty"`
	TTL         uint32        `json:"ttl,omitempty"`
	Description string        `json:"description,omitempty"`
	Internal    bool          `json:"internal,omitempty"`
	SOA         *cliSOARecord `json:"soa,omitempty"`
	RecordCount int           `json:"record_count,omitempty"`
	CreatedAt   int64         `json:"created_at,omitempty"`
	UpdatedAt   int64         `json:"updated_at,omitempty"`
}

type cliSOARecord struct {
	Name       string `json:"name,omitempty"`
	MName      string `json:"mname,omitempty"`
	RName      string `json:"rname,omitempty"`
	Serial     uint32 `json:"serial,omitempty"`
	Refresh    uint32 `json:"refresh,omitempty"`
	Retry      uint32 `json:"retry,omitempty"`
	Expire     uint32 `json:"expire,omitempty"`
	MinimumTTL uint32 `json:"minimum_ttl,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
}

func (r *cliGetZoneResponse) toResult() *GetZoneResult {
	result := &GetZoneResult{
		Name:        r.Name,
		ID:          r.ID,
		TTL:         r.TTL,
		Description: r.Description,
		Internal:    r.Internal,
		RecordCount: r.RecordCount,
		CreatedAt:   time.Unix(r.CreatedAt, 0),
		UpdatedAt:   time.Unix(r.UpdatedAt, 0),
	}

	if r.SOA != nil {
		result.SOA = &SOARecordInfo{
			Name:       r.SOA.Name,
			MName:      r.SOA.MName,
			RName:      r.SOA.RName,
			Serial:     r.SOA.Serial,
			Refresh:    r.SOA.Refresh,
			Retry:      r.SOA.Retry,
			Expire:     r.SOA.Expire,
			MinimumTTL: r.SOA.MinimumTTL,
			TTL:        r.SOA.TTL,
		}
	}

	return result
}

type cliUpdateZoneResponse struct {
	Name      string `json:"name,omitempty"`
	TTL       uint32 `json:"ttl,omitempty"`
	UpdatedAt int64  `json:"updated_at,omitempty"`
}

func (r *cliUpdateZoneResponse) toResult() *UpdateZoneResult {
	return &UpdateZoneResult{
		Name:      r.Name,
		TTL:       r.TTL,
		UpdatedAt: time.Unix(r.UpdatedAt, 0),
	}
}

type cliDeleteZoneResponse struct {
	Name    string `json:"name,omitempty"`
	Deleted bool   `json:"deleted,omitempty"`
}

func (r *cliDeleteZoneResponse) toResult() *DeleteZoneResult {
	return &DeleteZoneResult{
		Name:    r.Name,
		Deleted: r.Deleted,
	}
}

type cliListZonesResponse struct {
	Zones      []cliZoneSummary `json:"zones,omitempty"`
	TotalCount int32            `json:"total_count,omitempty"`
	HasMore    bool             `json:"has_more,omitempty"`
	NextCursor string           `json:"next_cursor,omitempty"`
}

type cliZoneSummary struct {
	Name        string `json:"name,omitempty"`
	ID          string `json:"id,omitempty"`
	TTL         uint32 `json:"ttl,omitempty"`
	Internal    bool   `json:"internal,omitempty"`
	RecordCount int    `json:"record_count,omitempty"`
	CreatedAt   int64  `json:"created_at,omitempty"`
}

func (r *cliListZonesResponse) toResult() *ListZonesResult {
	result := &ListZonesResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}

	for _, z := range r.Zones {
		result.Zones = append(result.Zones, ZoneSummary{
			Name:        z.Name,
			ID:          z.ID,
			TTL:         z.TTL,
			Internal:    z.Internal,
			RecordCount: z.RecordCount,
			CreatedAt:   time.Unix(z.CreatedAt, 0),
		})
	}

	return result
}

// Record response types

type cliAddRecordResponse struct {
	Name       string `json:"name,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Value      string `json:"value,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
}

func (r *cliAddRecordResponse) toResult() *AddRecordResult {
	return &AddRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Value:      r.Value,
		TTL:        r.TTL,
		CreatedAt:  time.Unix(r.CreatedAt, 0),
	}
}

type cliGetRecordResponse struct {
	Name       string `json:"name,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Value      string `json:"value,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
	Priority   uint16 `json:"priority,omitempty"`
	Weight     uint16 `json:"weight,omitempty"`
	Port       uint16 `json:"port,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (r *cliGetRecordResponse) toResult() *GetRecordResult {
	return &GetRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Value:      r.Value,
		TTL:        r.TTL,
		Priority:   r.Priority,
		Weight:     r.Weight,
		Port:       r.Port,
		CreatedAt:  time.Unix(r.CreatedAt, 0),
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type cliUpdateRecordResponse struct {
	Name       string `json:"name,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Value      string `json:"value,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
	UpdatedAt  int64  `json:"updated_at,omitempty"`
}

func (r *cliUpdateRecordResponse) toResult() *UpdateRecordResult {
	return &UpdateRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Value:      r.Value,
		TTL:        r.TTL,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type cliDeleteRecordResponse struct {
	Name       string `json:"name,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Deleted    bool   `json:"deleted,omitempty"`
}

func (r *cliDeleteRecordResponse) toResult() *DeleteRecordResult {
	return &DeleteRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Deleted:    r.Deleted,
	}
}

type cliListRecordsResponse struct {
	Records    []cliRecordSummary `json:"records,omitempty"`
	TotalCount int32              `json:"total_count,omitempty"`
	HasMore    bool               `json:"has_more,omitempty"`
	NextCursor string             `json:"next_cursor,omitempty"`
}

type cliRecordSummary struct {
	Name       string `json:"name,omitempty"`
	RecordType string `json:"record_type,omitempty"`
	Value      string `json:"value,omitempty"`
	TTL        uint32 `json:"ttl,omitempty"`
	Priority   uint16 `json:"priority,omitempty"`
}

func (r *cliListRecordsResponse) toResult() *ListRecordsResult {
	result := &ListRecordsResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}

	for _, rec := range r.Records {
		result.Records = append(result.Records, RecordSummary{
			Name:       rec.Name,
			RecordType: rec.RecordType,
			Value:      rec.Value,
			TTL:        rec.TTL,
			Priority:   rec.Priority,
		})
	}

	return result
}

// Resolution response types

type cliResolveResponse struct {
	Name       string   `json:"name,omitempty"`
	RecordType string   `json:"record_type,omitempty"`
	Values     []string `json:"values,omitempty"`
	TTL        uint32   `json:"ttl,omitempty"`
	Timestamp  int64    `json:"timestamp,omitempty"`
}

func (r *cliResolveResponse) toResult() *ResolveResult {
	return &ResolveResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Values:     r.Values,
		TTL:        r.TTL,
		Timestamp:  time.Unix(r.Timestamp, 0),
	}
}

// TLSA response types

type cliAddTLSARecordResponse struct {
	Name         string `json:"name,omitempty"`
	Usage        uint8  `json:"usage,omitempty"`
	Selector     uint8  `json:"selector,omitempty"`
	MatchingType uint8  `json:"matching_type,omitempty"`
	Data         string `json:"data,omitempty"`
	TTL          uint32 `json:"ttl,omitempty"`
	CreatedAt    int64  `json:"created_at,omitempty"`
}

func (r *cliAddTLSARecordResponse) toResult() *AddTLSARecordResult {
	return &AddTLSARecordResult{
		Name:         r.Name,
		Usage:        r.Usage,
		Selector:     r.Selector,
		MatchingType: r.MatchingType,
		Data:         r.Data,
		TTL:          r.TTL,
		CreatedAt:    time.Unix(r.CreatedAt, 0),
	}
}

// Ensure CLIAdapter implements DNSCommands interface.
var _ DNSCommands = (*CLIAdapter)(nil)
