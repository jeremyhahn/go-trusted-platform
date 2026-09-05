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

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// formatUint64ID renders a uint64 identifier as a decimal string per the
// repo-wide convention for uint64 IDs on the wire (JSON numbers lose
// precision past 2^53).
func formatUint64ID(id uint64) string {
	return strconv.FormatUint(id, 10)
}

// =============================================================================
// Device profile CRUD tool wiring
// =============================================================================
//
// These executors back the profile_create / profile_get_by_id /
// profile_list_all / profile_update_by_id / profile_delete_by_id tools
// registered in registerDeviceToolsV2, giving the MCP transport the same
// device-profile field surface as gRPC, REST, and QUIC — including the
// hardware-EK prestage fields (ek_serial, ek_cert, mac_address), the full
// merged platform config, and the assignment state.
//
// The MCP server stays decoupled from the daemon: the underlying profile
// service is exposed via the optional DeviceProfileProvider interface,
// satisfied by the daemon's MCPServiceProvider when the device profile
// service is configured.

// ErrDeviceProfileNotConfigured indicates the device profile backend is not
// wired into the MCP tool registry.
var ErrDeviceProfileNotConfigured = errors.New("device_profile: profile service not configured")

// ErrDeviceProfileIdentityRequired indicates a profile assignment request
// carried neither an EK serial nor a MAC address.
var ErrDeviceProfileIdentityRequired = errors.New("device_profile: ek_serial or mac_address is required")

// ErrDeviceProfileInvalidArgs indicates the tool arguments did not decode
// into the device profile request shape.
type ErrDeviceProfileInvalidArgs struct {
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrDeviceProfileInvalidArgs) Error() string {
	return "device_profile: invalid tool arguments: " + e.Cause.Error()
}

// Unwrap exposes the underlying decode error for errors.Is/As.
func (e ErrDeviceProfileInvalidArgs) Unwrap() error {
	return e.Cause
}

// DeviceProfileProvider is the optional interface a ServiceProvider can
// satisfy to unlock the profile_* CRUD MCP tools. Implementations delegate
// to the platform device profile service (the same backing implementation
// that powers the gRPC DeviceService profile RPCs) so the MCP and gRPC
// surfaces remain in lockstep.
type DeviceProfileProvider interface {
	// DeviceProfileCreate persists a new device profile, generating an ID
	// when the profile carries none, and returns the stored profile.
	DeviceProfileCreate(ctx context.Context, profile *entities.DeviceProfile) (*entities.DeviceProfile, error)

	// DeviceProfileGet retrieves a device profile by ID.
	DeviceProfileGet(ctx context.Context, id uint64) (*entities.DeviceProfile, error)

	// DeviceProfileList returns a page of device profiles and the total
	// profile count.
	DeviceProfileList(ctx context.Context, page, pageSize int) ([]*entities.DeviceProfile, int, error)

	// DeviceProfileUpdate replaces an existing device profile.
	DeviceProfileUpdate(ctx context.Context, profile *entities.DeviceProfile) (*entities.DeviceProfile, error)

	// DeviceProfileDelete removes a device profile by ID.
	DeviceProfileDelete(ctx context.Context, id uint64) error

	// DeviceProfileAssign binds a profile to a device identity (EK serial
	// and/or MAC address), optionally prestaging the device's PEM-encoded
	// EK certificate, and returns the updated profile.
	DeviceProfileAssign(ctx context.Context, profileID uint64, ekSerial, macAddress, ekCertPEM string) (*entities.DeviceProfile, error)

	// DeviceProfileUnassign clears a profile's device binding and returns
	// the updated profile.
	DeviceProfileUnassign(ctx context.Context, profileID uint64) (*entities.DeviceProfile, error)
}

// deviceProfileProvider returns the DeviceProfileProvider interface if the
// ServiceProvider implements it, else nil.
func (r *ToolRegistry) deviceProfileProvider() DeviceProfileProvider {
	if p, ok := r.service.(DeviceProfileProvider); ok {
		return p
	}
	return nil
}

// deviceProfileToolRequest is the JSON shape of the profile_create and
// profile_update_by_id tool arguments. The field tags match the MCP tool
// schemas (and the domain entities.DeviceProfile JSON encoding) so nested
// networks and match_rules decode directly into their entity types.
// EventLog is standard base64 per the tool schema. Assigned and AssignedAt
// use pointer types so "not sent" and "set to the zero value" are
// distinguishable during partial updates.
type deviceProfileToolRequest struct {
	Name                  string                                  `json:"name"`
	Model                 string                                  `json:"model"`
	Role                  string                                  `json:"role"`
	Zone                  string                                  `json:"zone"`
	EventLog              string                                  `json:"event_log"`
	Networks              map[string]*entities.NetworkPhaseConfig `json:"networks"`
	EnrollmentNetwork     string                                  `json:"enrollment_network"`
	PostEnrollmentNetwork string                                  `json:"post_enrollment_network"`
	FailureNetwork        string                                  `json:"failure_network"`
	MatchRules            *entities.ProfileMatchRules             `json:"match_rules"`
	EKSerial              string                                  `json:"ek_serial"`
	EKCert                string                                  `json:"ek_cert"`
	MACAddress            string                                  `json:"mac_address"`
	Config                any                                     `json:"config"`
	Assigned              *bool                                   `json:"assigned"`
	AssignedAt            *time.Time                              `json:"assigned_at"`
	// TLSServerName is the certificate name the attestation collector
	// verifies a node of this profile against (#430). There is deliberately
	// no pcr_baseline field: the baseline is read-only, so a pcr_baseline
	// argument is dropped by the typed decode and never reaches the entity
	// (#373, #448).
	TLSServerName string `json:"tls_server_name"`
}

// decodeDeviceProfileToolRequest binds the raw tool arguments onto the
// typed request via a JSON round trip so nested objects (networks,
// match_rules, config) decode into their entity types.
func decodeDeviceProfileToolRequest(args map[string]interface{}) (*deviceProfileToolRequest, error) {
	encoded, err := json.Marshal(args)
	if err != nil {
		return nil, ErrDeviceProfileInvalidArgs{Cause: err}
	}
	var req deviceProfileToolRequest
	if err := json.Unmarshal(encoded, &req); err != nil {
		return nil, ErrDeviceProfileInvalidArgs{Cause: err}
	}
	return &req, nil
}

// decodeDeviceProfileEventLog decodes the base64 event_log argument.
func decodeDeviceProfileEventLog(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, nil
	}
	eventLog, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrDeviceProfileInvalidArgs{Cause: err}
	}
	return eventLog, nil
}

// deviceProfileToolResult renders a device profile as the MCP tool result.
// The entity's JSON encoding is preserved (numbers decode via
// json.Number so nothing round-trips through float64), and the uint64
// profile ID is emitted as a decimal string per the repo-wide convention
// for uint64 IDs on the wire (JSON numbers lose precision past 2^53).
// The prestaged EK certificate is included deliberately: an EK
// certificate is public key material carrying no secrets, so echoing it
// back lets operators audit which certificate is prestaged.
func deviceProfileToolResult(profile *entities.DeviceProfile) (interface{}, error) {
	encoded, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var result map[string]interface{}
	if err := decoder.Decode(&result); err != nil {
		return nil, err
	}
	result["id"] = formatUint64ID(profile.ID)
	return result, nil
}

// =============================================================================
// Map-based dispatch
// =============================================================================

// deviceProfileToolHandler dispatches a device profile tool by name.
// Map-based dispatch keeps routing O(1) per project conventions.
type deviceProfileToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

var deviceProfileToolDispatch = map[string]deviceProfileToolHandler{
	"profile_create":               (*ToolRegistry).executeDeviceProfileCreate,
	"profile_get_by_id":            (*ToolRegistry).executeDeviceProfileGet,
	"profile_list_all":             (*ToolRegistry).executeDeviceProfileList,
	"profile_update_by_id":         (*ToolRegistry).executeDeviceProfileUpdate,
	"profile_delete_by_id":         (*ToolRegistry).executeDeviceProfileDelete,
	"profile_assign_to_device":     (*ToolRegistry).executeDeviceProfileAssign,
	"profile_unassign_from_device": (*ToolRegistry).executeDeviceProfileUnassign,
}

// dispatchDeviceProfileTool looks up a device profile tool and invokes it.
// Returns (result, handled, err) so the caller can fall through when
// handled is false (tool name doesn't belong to device profiles).
func (r *ToolRegistry) dispatchDeviceProfileTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	fn, ok := deviceProfileToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Executors
// =============================================================================

func (r *ToolRegistry) executeDeviceProfileCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}

	req, err := decodeDeviceProfileToolRequest(args)
	if err != nil {
		return nil, err
	}
	if req.Name == "" {
		return nil, ErrProfileNameRequired
	}
	// A prestaged EK certificate binds config delivery and remote UKI
	// signing to the hardware EK; an unparseable value can never match a
	// presented certificate, so reject it at the boundary.
	if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
		return nil, err
	}
	eventLog, err := decodeDeviceProfileEventLog(req.EventLog)
	if err != nil {
		return nil, err
	}

	profile := &entities.DeviceProfile{
		Name:                  req.Name,
		Model:                 req.Model,
		Role:                  entities.DeviceRole(req.Role),
		Zone:                  req.Zone,
		EventLog:              eventLog,
		Networks:              req.Networks,
		EnrollmentNetwork:     req.EnrollmentNetwork,
		PostEnrollmentNetwork: req.PostEnrollmentNetwork,
		FailureNetwork:        req.FailureNetwork,
		MatchRules:            req.MatchRules,
		EKSerial:              req.EKSerial,
		EKCert:                req.EKCert,
		MACAddress:            req.MACAddress,
		Config:                req.Config,
		TLSServerName:         req.TLSServerName,
	}
	if req.Assigned != nil {
		profile.Assigned = *req.Assigned
	}
	if req.AssignedAt != nil {
		profile.AssignedAt = *req.AssignedAt
	}

	created, err := p.DeviceProfileCreate(ctx, profile)
	if err != nil {
		return nil, err
	}
	return deviceProfileToolResult(created)
}

func (r *ToolRegistry) executeDeviceProfileGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}
	id := uint64(getInt64(args, "id"))
	if id == 0 {
		return nil, ErrProfileIDRequired
	}
	profile, err := p.DeviceProfileGet(ctx, id)
	if err != nil {
		return nil, err
	}
	return deviceProfileToolResult(profile)
}

func (r *ToolRegistry) executeDeviceProfileList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}

	page := getInt(args, "page")
	if page <= 0 {
		page = 1
	}
	pageSize := getInt(args, "page_size")
	if pageSize <= 0 {
		pageSize = 50
	}

	profiles, total, err := p.DeviceProfileList(ctx, page, pageSize)
	if err != nil {
		return nil, err
	}

	results := make([]interface{}, 0, len(profiles))
	for _, profile := range profiles {
		result, err := deviceProfileToolResult(profile)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	return map[string]interface{}{
		"profiles":  results,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	}, nil
}

func (r *ToolRegistry) executeDeviceProfileUpdate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}
	id := uint64(getInt64(args, "id"))
	if id == 0 {
		return nil, ErrProfileIDRequired
	}

	req, err := decodeDeviceProfileToolRequest(args)
	if err != nil {
		return nil, err
	}

	profile, err := p.DeviceProfileGet(ctx, id)
	if err != nil {
		return nil, err
	}

	// Partial update: only supplied non-zero fields replace the stored
	// values; the pointer-typed assignment fields are tri-state.
	if req.Name != "" {
		profile.Name = req.Name
	}
	if req.Model != "" {
		profile.Model = req.Model
	}
	if req.Role != "" {
		profile.Role = entities.DeviceRole(req.Role)
	}
	if req.Zone != "" {
		profile.Zone = req.Zone
	}
	if req.EventLog != "" {
		eventLog, err := decodeDeviceProfileEventLog(req.EventLog)
		if err != nil {
			return nil, err
		}
		profile.EventLog = eventLog
	}
	if len(req.Networks) > 0 {
		profile.Networks = req.Networks
	}
	if req.EnrollmentNetwork != "" {
		profile.EnrollmentNetwork = req.EnrollmentNetwork
	}
	if req.PostEnrollmentNetwork != "" {
		profile.PostEnrollmentNetwork = req.PostEnrollmentNetwork
	}
	if req.FailureNetwork != "" {
		profile.FailureNetwork = req.FailureNetwork
	}
	if req.MatchRules != nil {
		profile.MatchRules = req.MatchRules
	}
	if req.EKSerial != "" {
		profile.EKSerial = req.EKSerial
	}
	if req.EKCert != "" {
		// Same EK-certificate boundary validation as profile_create.
		if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
			return nil, err
		}
		profile.EKCert = req.EKCert
	}
	if req.MACAddress != "" {
		profile.MACAddress = req.MACAddress
	}
	if req.Config != nil {
		profile.Config = req.Config
	}
	if req.Assigned != nil {
		profile.Assigned = *req.Assigned
	}
	if req.AssignedAt != nil {
		profile.AssignedAt = *req.AssignedAt
	}
	if req.TLSServerName != "" {
		profile.TLSServerName = req.TLSServerName
	}

	updated, err := p.DeviceProfileUpdate(ctx, profile)
	if err != nil {
		return nil, err
	}
	return deviceProfileToolResult(updated)
}

func (r *ToolRegistry) executeDeviceProfileDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}
	id := uint64(getInt64(args, "id"))
	if id == 0 {
		return nil, ErrProfileIDRequired
	}
	if err := p.DeviceProfileDelete(ctx, id); err != nil {
		return nil, err
	}
	return map[string]interface{}{"success": true, "id": formatUint64ID(id)}, nil
}

// executeDeviceProfileAssign binds a profile to a device identity (EK
// serial and/or MAC address), optionally prestaging the device's EK
// certificate. The EK certificate is source-agnostic (swtpm-backed vTPM
// or physical hardware TPM) and validated as a generic PEM X.509
// certificate at the boundary.
func (r *ToolRegistry) executeDeviceProfileAssign(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}

	profileID := uint64(getInt64(args, "profile_id"))
	if profileID == 0 {
		return nil, ErrProfileIDRequired
	}

	ekSerial := getString(args, "ek_serial")
	macAddress := getString(args, "mac_address")
	if ekSerial == "" && macAddress == "" {
		return nil, ErrDeviceProfileIdentityRequired
	}

	ekCert := getString(args, "ek_cert")
	if err := entities.ValidateEKCertPEM(ekCert); err != nil {
		return nil, err
	}

	profile, err := p.DeviceProfileAssign(ctx, profileID, ekSerial, macAddress, ekCert)
	if err != nil {
		return nil, err
	}
	return deviceProfileToolResult(profile)
}

// executeDeviceProfileUnassign clears a profile's device binding.
func (r *ToolRegistry) executeDeviceProfileUnassign(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.deviceProfileProvider()
	if p == nil {
		return nil, ErrDeviceProfileNotConfigured
	}

	profileID := uint64(getInt64(args, "profile_id"))
	if profileID == 0 {
		return nil, ErrProfileIDRequired
	}

	profile, err := p.DeviceProfileUnassign(ctx, profileID)
	if err != nil {
		return nil, err
	}
	return deviceProfileToolResult(profile)
}
