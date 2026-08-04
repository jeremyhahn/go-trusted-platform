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

package device

import "time"

// ContextKey is a custom type for context keys in the device package.
type ContextKey string

// ContextKeyDeviceSerial is the context key for the device serial number.
const ContextKeyDeviceSerial ContextKey = "device_serial"

// DeviceRequest represents the request body for device creation/update.
//
// Two shapes are accepted to bridge the legacy REST contract and the SDK
// contract:
//
//  1. Flat: {"id", "serial", "model", ...} — original REST shape used
//     by the v1 integration tests.
//  2. Nested: {"device": {"name", "serial", ...}} — shape produced by
//     the JS SDK's `createDevice({device: {...}})` and the React form.
//
// All fields below are optional: the handler infers the canonical
// representation from whichever subtree carries data. Unknown extra
// fields produced by the WebUI (name, description, tpmVersion, etc.)
// are tolerated rather than rejected.
type DeviceRequest struct {
	// Flat fields (legacy REST contract).
	ID         uint64 `json:"id,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	SwitchName string `json:"switch_name,omitempty"`
	SwitchPort string `json:"switch_port,omitempty"`

	// Nested SDK envelope. When present, fields here override the flat
	// fields above so the REST contract aligns with the JS SDK.
	Device *DeviceRequestPayload `json:"device,omitempty"`

	// UI-only fields tolerated for forwards-compatibility with WebUI
	// forms. The server captures Name into the Device record's serial
	// when no other identifier is supplied; the rest are informational.
	Name               string `json:"name,omitempty"`
	Type               string `json:"type,omitempty"`
	DeviceType         string `json:"device_type,omitempty"`
	Description        string `json:"description,omitempty"`
	Manufacturer       string `json:"manufacturer,omitempty"`
	Version            string `json:"version,omitempty"`
	TPMManufacturer    string `json:"tpm_manufacturer,omitempty"`
	TPMVersion         string `json:"tpm_version,omitempty"`
	TPMFirmwareVersion string `json:"tpm_firmware_version,omitempty"`
}

// DeviceRequestPayload mirrors DeviceRequest's flat fields plus a Name
// alias. The nested {device: {...}} envelope produced by the JS SDK is
// decoded into this struct.
type DeviceRequestPayload struct {
	ID         uint64 `json:"id,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Name       string `json:"name,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	SwitchName string `json:"switch_name,omitempty"`
	SwitchPort string `json:"switch_port,omitempty"`
}

// DeviceResponse represents a device in API responses.
//
// IDs are emitted as JSON strings (`json:"...,string"`) because the
// platform mints them above 2^53; encoding them as plain JSON numbers
// would silently lose precision in JavaScript clients (the WebUI
// truncates the value and then can't navigate to the detail page).
type DeviceResponse struct {
	ID         uint64 `json:"id,string"`
	AttestPub  string `json:"attest_pub,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
	Model      string `json:"model,omitempty"`
	Serial     string `json:"serial,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	SwitchName string `json:"switch_name,omitempty"`
	SwitchPort string `json:"switch_port,omitempty"`
}

// DeviceListResponse represents a paginated list of devices
type DeviceListResponse struct {
	Devices    []DeviceResponse   `json:"devices"`
	Pagination PaginationResponse `json:"pagination"`
}

// ProfileRequest represents the request body for profile creation/update.
// Networks maps logical phase names (e.g. "provisioning", "trusted",
// "quarantine") to their configurations. EnrollmentNetwork,
// PostEnrollmentNetwork, and FailureNetwork name the active phases.
type ProfileRequest struct {
	ID                    uint64                          `json:"id"`
	Name                  string                          `json:"name"`
	Zone                  string                          `json:"zone,omitempty"`
	Model                 string                          `json:"model,omitempty"`
	Role                  string                          `json:"role,omitempty"`
	EventLog              []byte                          `json:"event_log,omitempty"`
	Networks              map[string]*NetworkPhaseRequest `json:"networks,omitempty"`
	EnrollmentNetwork     string                          `json:"enrollment_network,omitempty"`
	PostEnrollmentNetwork string                          `json:"post_enrollment_network,omitempty"`
	FailureNetwork        string                          `json:"failure_network,omitempty"`
	PlatformdConfig       *PlatformdConfigRequest         `json:"platformd_config,omitempty"`
	MatchRules            *MatchRulesRequest              `json:"match_rules,omitempty"`

	// EKSerial is the exact TPM EK certificate serial number used for
	// device identity resolution at boot time.
	EKSerial string `json:"ek_serial,omitempty"`
	// EKCert prestages the PEM-encoded TPM EK certificate that binds
	// pre-enrollment config delivery and remote UKI signing to the
	// device's hardware EK. A non-empty value must parse as a PEM
	// X.509 certificate or the request is rejected with 400.
	EKCert string `json:"ek_cert,omitempty"`
	// MACAddress is the exact MAC address for non-TPM device identification.
	MACAddress string `json:"mac_address,omitempty"`
	// Config is the full merged platform config delivered to the device.
	Config any `json:"config,omitempty"`
	// Assigned marks the profile as bound to a specific device.
	Assigned bool `json:"assigned,omitempty"`
	// AssignedAt is the timestamp of the device assignment.
	AssignedAt time.Time `json:"assigned_at,omitempty"`
}

// NetworkPhaseRequest represents network configuration for a phase.
// Zone is the SDN zone name for this network phase (e.g. "trusted").
type NetworkPhaseRequest struct {
	VLAN       uint16           `json:"vlan"`
	DHCPPool   *DHCPPoolRequest `json:"dhcp_pool,omitempty"`
	StaticIP   string           `json:"static_ip,omitempty"`
	Gateway    string           `json:"gateway,omitempty"`
	DNS        []string         `json:"dns,omitempty"`
	AuthMethod string           `json:"auth_method,omitempty"`
	ACLs       []ACLRequest     `json:"acls,omitempty"`
	Subnet     string           `json:"subnet,omitempty"`
	DNSServers []string         `json:"dns_servers,omitempty"`
	DHCP       bool             `json:"dhcp"`
	Zone       string           `json:"zone,omitempty"`
}

// DHCPPoolRequest represents DHCP pool configuration
type DHCPPoolRequest struct {
	Network    string `json:"network"`
	RangeStart string `json:"range_start"`
	RangeEnd   string `json:"range_end"`
	LeaseTime  int    `json:"lease_time"`
}

// ACLRequest represents an ACL entry
type ACLRequest struct {
	Priority int    `json:"priority"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Action   string `json:"action"`
}

// PlatformdConfigRequest represents platformd configuration reference
type PlatformdConfigRequest struct {
	ConfigType string `json:"config_type"`
	Reference  string `json:"reference,omitempty"`
	ConfigName string `json:"config_name,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	Version    string `json:"version,omitempty"`
}

// MatchRulesRequest represents profile matching rules
type MatchRulesRequest struct {
	MACPrefix         string            `json:"mac_prefix,omitempty"`
	SerialPrefix      string            `json:"serial_prefix,omitempty"`
	Model             string            `json:"model,omitempty"`
	ModelPattern      string            `json:"model_pattern,omitempty"`
	SerialPattern     string            `json:"serial_pattern,omitempty"`
	ManufacturerMatch string            `json:"manufacturer_match,omitempty"`
	TPMVendor         string            `json:"tpm_vendor,omitempty"`
	CustomAttributes  map[string]string `json:"custom_attributes,omitempty"`
}

// ProfileListResponse represents a paginated list of profiles
type ProfileListResponse struct {
	Profiles   []ProfileFullResponse `json:"profiles"`
	Pagination PaginationResponse    `json:"pagination"`
}

// ProfileFullResponse represents a complete device profile.
// See DeviceResponse for why ID is encoded as a JSON string.
// Networks maps logical phase names to their configurations.
type ProfileFullResponse struct {
	ID                    uint64                           `json:"id,string"`
	Name                  string                           `json:"name"`
	Zone                  string                           `json:"zone,omitempty"`
	Model                 string                           `json:"model,omitempty"`
	Role                  string                           `json:"role,omitempty"`
	EventLog              []byte                           `json:"event_log,omitempty"`
	Networks              map[string]*NetworkPhaseResponse `json:"networks,omitempty"`
	EnrollmentNetwork     string                           `json:"enrollment_network,omitempty"`
	PostEnrollmentNetwork string                           `json:"post_enrollment_network,omitempty"`
	FailureNetwork        string                           `json:"failure_network,omitempty"`
	PlatformdConfig       *PlatformdConfigResponse         `json:"platformd_config,omitempty"`
	MatchRules            *MatchRulesResponse              `json:"match_rules,omitempty"`

	// EKSerial is the exact TPM EK certificate serial number bound to
	// this profile.
	EKSerial string `json:"ek_serial,omitempty"`
	// EKCert is the prestaged PEM-encoded TPM EK certificate. It is
	// echoed back deliberately: an EK certificate is public key
	// material (an X.509 certificate carrying no secrets), so exposing
	// it lets operators audit which certificate is prestaged.
	EKCert string `json:"ek_cert,omitempty"`
	// MACAddress is the exact MAC address bound to this profile.
	MACAddress string `json:"mac_address,omitempty"`
	// Config is the full merged platform config for this device.
	Config any `json:"config,omitempty"`
	// Assigned reports whether the profile is bound to a device.
	Assigned bool `json:"assigned"`
	// AssignedAt is the timestamp of the device assignment (zero when
	// unassigned).
	AssignedAt time.Time `json:"assigned_at,omitempty"`
}

// NetworkPhaseResponse represents network configuration in response.
// Zone is the SDN zone name for this network phase.
type NetworkPhaseResponse struct {
	VLAN       uint16            `json:"vlan"`
	DHCPPool   *DHCPPoolResponse `json:"dhcp_pool,omitempty"`
	StaticIP   string            `json:"static_ip,omitempty"`
	Gateway    string            `json:"gateway,omitempty"`
	DNS        []string          `json:"dns,omitempty"`
	AuthMethod string            `json:"auth_method,omitempty"`
	ACLs       []ACLResponse     `json:"acls,omitempty"`
	Subnet     string            `json:"subnet,omitempty"`
	DNSServers []string          `json:"dns_servers,omitempty"`
	DHCP       bool              `json:"dhcp"`
	Zone       string            `json:"zone,omitempty"`
}

// DHCPPoolResponse represents DHCP pool in response
type DHCPPoolResponse struct {
	Network    string `json:"network"`
	RangeStart string `json:"range_start"`
	RangeEnd   string `json:"range_end"`
	LeaseTime  int    `json:"lease_time"`
}

// ACLResponse represents an ACL entry in response
type ACLResponse struct {
	Priority int    `json:"priority"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip,omitempty"`
	DstIP    string `json:"dst_ip,omitempty"`
	SrcPort  uint16 `json:"src_port,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Action   string `json:"action"`
}

// PlatformdConfigResponse represents platformd configuration in response
type PlatformdConfigResponse struct {
	ConfigType string `json:"config_type"`
	Reference  string `json:"reference,omitempty"`
	ConfigName string `json:"config_name,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	Version    string `json:"version,omitempty"`
}

// MatchRulesResponse represents profile matching rules in response
type MatchRulesResponse struct {
	MACPrefix         string            `json:"mac_prefix,omitempty"`
	SerialPrefix      string            `json:"serial_prefix,omitempty"`
	Model             string            `json:"model,omitempty"`
	ModelPattern      string            `json:"model_pattern,omitempty"`
	SerialPattern     string            `json:"serial_pattern,omitempty"`
	ManufacturerMatch string            `json:"manufacturer_match,omitempty"`
	TPMVendor         string            `json:"tpm_vendor,omitempty"`
	CustomAttributes  map[string]string `json:"custom_attributes,omitempty"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	Total      int  `json:"total"`
	TotalPages int  `json:"total_pages"`
	HasMore    bool `json:"has_more"`
}

// CountResponse represents a count response
type CountResponse struct {
	Count int `json:"count"`
}

// ActivationRequest represents device activation request
type ActivationRequest struct {
	Serial     string `json:"serial"`
	MACAddress string `json:"mac_address,omitempty"`
}

// ActivationResponse represents device activation response
type ActivationResponse struct {
	Status         string    `json:"status"`
	VLAN           uint16    `json:"vlan"`
	TransitionedAt time.Time `json:"transitioned_at"`
}

// FindMatchingProfileRequest represents the request for finding matching profile
type FindMatchingProfileRequest struct {
	MACAddress string `json:"mac_address,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Model      string `json:"model,omitempty"`
}
