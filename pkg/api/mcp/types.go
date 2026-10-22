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

// Package mcp implements the Model Context Protocol (MCP) transport layer for Trusted Platform.
// MCP is a protocol for exposing tools and resources to AI/LLM systems using JSON-RPC 2.0.
//
// The MCP server provides:
// - JSON-RPC 2.0 protocol over stdio or HTTP transport
// - Platform operations exposed as MCP "tools"
// - Data exposed as MCP "resources"
// - Full integration with Platform Daemon
// - Authorization enforcement for all tool executions
//
// Reference: https://modelcontextprotocol.io/
package mcp

import (
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// AuthErrorType categorizes authorization errors.
type AuthErrorType int

const (
	// AuthErrorNone indicates no error.
	AuthErrorNone AuthErrorType = iota
	// AuthErrorMissingToken indicates no token was provided.
	AuthErrorMissingToken
	// AuthErrorInvalidToken indicates the token is invalid.
	AuthErrorInvalidToken
	// AuthErrorPermissionDenied indicates insufficient permissions.
	AuthErrorPermissionDenied
	// AuthErrorServiceUnavailable indicates auth service is not configured.
	AuthErrorServiceUnavailable
	// AuthErrorToolNotClassified indicates the tool has no entry in the
	// permission map. Distinct from AuthErrorPermissionDenied: the caller may
	// well hold sufficient permissions, but nobody has yet decided what this
	// tool requires, so it cannot be authorized. Diagnosing it as "permission
	// denied" would send an operator hunting their own grants for a gap that
	// is in the platform's configuration (#300).
	AuthErrorToolNotClassified
)

// AuthorizationError represents an authorization failure.
type AuthorizationError struct {
	Type    AuthErrorType
	Message string
}

func (e *AuthorizationError) Error() string {
	return e.Message
}

// CAIssueRequest represents a certificate issuance request for MCP.
type CAIssueRequest struct {
	CommonName         string   `json:"common_name"`
	Organization       string   `json:"organization,omitempty"`
	OrganizationalUnit string   `json:"organizational_unit,omitempty"`
	Country            string   `json:"country,omitempty"`
	Province           string   `json:"province,omitempty"`
	Locality           string   `json:"locality,omitempty"`
	Address            string   `json:"address,omitempty"`
	PostalCode         string   `json:"postal_code,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	URIs               []string `json:"uris,omitempty"`
	ValidDays          int      `json:"valid_days,omitempty"`
	Algorithm          string   `json:"algorithm,omitempty"`
	StoreType          string   `json:"store_type,omitempty"`
	KeyUsage           []string `json:"key_usage,omitempty"`
	ExtKeyUsage        []string `json:"ext_key_usage,omitempty"`
	IsCA               bool     `json:"is_ca,omitempty"`
	MaxPathLen         int      `json:"max_path_len,omitempty"`
}

// CASignCSRRequest certifies a KMS key for code signing from a CSR the KMS
// signed; the CSR's common name is the key ID.
type CASignCSRRequest struct {
	CSRPEM    string `json:"csr_pem"`
	ValidDays int    `json:"valid_days,omitempty"`
}

// DeviceRegisterRequest carries the device_register tool arguments. The
// fields match the device record every other transport creates: Serial is
// required, the server assigns the id.
type DeviceRegisterRequest struct {
	Serial     string `json:"serial"`
	Model      string `json:"model,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	AttestCert string `json:"attest_cert,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
}

// IAMCreateUserRequest represents a user creation request for MCP.
type IAMCreateUserRequest struct {
	TenantID   string            `json:"tenant_id"`
	Email      string            `json:"email"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// IAMUpdateUserRequest represents a user update request for MCP, the
// fields of gRPC UpdateIAMUserRequest.
type IAMUpdateUserRequest struct {
	TenantID   string            `json:"tenant_id"`
	UserID     string            `json:"user_id"`
	Email      string            `json:"email,omitempty"`
	Name       string            `json:"name,omitempty"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// IAMCreateRoleRequest represents a role creation request for MCP.
type IAMCreateRoleRequest struct {
	TenantID    string   `json:"tenant_id"`
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// IAMAuthenticateRequest represents an authentication request for MCP.
type IAMAuthenticateRequest struct {
	TenantID    string `json:"tenant_id"`
	Email       string `json:"email"`
	Password    string `json:"password" secret:"true"`
	TOTPCode    string `json:"totp_code,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}

// IAMCreateGroupRequest represents a group creation request for MCP.
type IAMCreateGroupRequest struct {
	TenantID    string `json:"tenant_id"`
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// IAMUpdateGroupRequest represents a group update request for MCP, the
// fields of gRPC UpdateIAMGroupRequest.
type IAMUpdateGroupRequest struct {
	TenantID    string `json:"tenant_id"`
	GroupID     string `json:"group_id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// IAMCreateTenantRequest represents a tenant creation request for MCP.
type IAMCreateTenantRequest struct {
	ID       string             `json:"id"`
	Name     string             `json:"name,omitempty"`
	Settings *IAMTenantSettings `json:"settings,omitempty"`
}

// IAMTenantSettings represents tenant configuration settings.
type IAMTenantSettings struct {
	MaxUsers    int32 `json:"max_users,omitempty"`
	MFARequired bool  `json:"mfa_required,omitempty"`
}

// IAMCreateTokenRequest represents a token creation request for MCP.
type IAMCreateTokenRequest struct {
	TenantID    string   `json:"tenant_id"`
	UserID      string   `json:"user_id"`
	Scopes      []string `json:"scopes,omitempty"`
	ExpiresIn   int64    `json:"expires_in,omitempty"`
	Description string   `json:"description,omitempty"`
}

// IAMPagination is the page an IAM list tool asks for, the gRPC
// PaginationRequest: Page counts from 1, and a zero PageSize takes the
// service default.
type IAMPagination struct {
	Page     uint32 `json:"page,omitempty"`
	PageSize uint32 `json:"page_size,omitempty"`
}

// IAMListUsersRequest represents a user listing request for MCP, with the
// same fields as the gRPC ListIAMUsersRequest.
type IAMListUsersRequest struct {
	TenantID    string        `json:"tenant_id"`
	Pagination  IAMPagination `json:"pagination,omitempty"`
	EmailFilter string        `json:"email_filter,omitempty"`
	RoleFilter  string        `json:"role_filter,omitempty"`
	GroupFilter string        `json:"group_filter,omitempty"`
}

// IAMCheckPermissionRequest represents a policy decision request for MCP,
// with the same fields as the gRPC CheckIAMPermissionRequest.
type IAMCheckPermissionRequest struct {
	TenantID   string            `json:"tenant_id"`
	SubjectID  string            `json:"subject_id"`
	Roles      []string          `json:"roles,omitempty"`
	Groups     []string          `json:"groups,omitempty"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource"`
	Context    map[string]string `json:"context,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// KMSCreateKeyRequest represents a key creation request for MCP.
type KMSCreateKeyRequest struct {
	Name               string            `json:"name"`
	Description        string            `json:"description,omitempty"`
	Algorithm          string            `json:"algorithm"`
	KeyUsage           []string          `json:"key_usage"`
	KeySize            int               `json:"key_size,omitempty"`
	Curve              string            `json:"curve,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Exportable         bool              `json:"exportable,omitempty"`
	DeletionProtection bool              `json:"deletion_protection,omitempty"`
	Owner              string            `json:"owner,omitempty"`
}

// KMSExportPublicKeyRequest represents a public key export request for MCP.
type KMSExportPublicKeyRequest struct {
	KeyID   string `json:"key_id"`
	Format  string `json:"format,omitempty"`
	Version uint64 `json:"version,omitempty"`
}

// KMSUpdateKeyMetadataRequest represents a key metadata update request for MCP.
type KMSUpdateKeyMetadataRequest struct {
	KeyID       string            `json:"key_id"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	RemoveTags  []string          `json:"remove_tags,omitempty"`
}

// KMSSetKeyPolicyRequest represents a key policy update request for MCP.
type KMSSetKeyPolicyRequest struct {
	KeyID             string   `json:"key_id"`
	AllowedOperations []string `json:"allowed_operations,omitempty"`
	AllowedPrincipals []string `json:"allowed_principals,omitempty"`
	DeniedPrincipals  []string `json:"denied_principals,omitempty"`
	ExpiresAt         int64    `json:"expires_at,omitempty"`
	RotationRequired  bool     `json:"rotation_required,omitempty"`
	MaxUsageCount     uint64   `json:"max_usage_count,omitempty"`
	RequireMFA        bool     `json:"require_mfa,omitempty"`
}

// SecretStoreRequest represents a secret storage request for MCP.
type SecretStoreRequest struct {
	SecretID string            `json:"secret_id"`
	Data     []byte            `json:"data"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// SecretSetRotationPolicyRequest represents a secret rotation-policy
// update request for MCP.
type SecretSetRotationPolicyRequest struct {
	SecretID        string `json:"secret_id"`
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int64  `json:"interval_seconds,omitempty"`
	RetainVersions  int    `json:"retain_versions,omitempty"`
}

// SecretRotateRequest is the decoded input of the secret_rotate tool.
type SecretRotateRequest struct {
	SecretID string            `json:"secret_id"`
	NewData  []byte            `json:"new_data"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// DEKCreateRequest is the decoded input of the dek_create tool. Its fields
// are the quicbaas.kms.v1 CreateDEKRequest fields; Algorithm is the
// quicbaas.kms.v1 KeyAlgorithm number.
type DEKCreateRequest struct {
	Path           string            `json:"path"`
	Algorithm      int32             `json:"algorithm,omitempty"`
	Description    string            `json:"description,omitempty"`
	MaxOperations  uint64            `json:"max_operations,omitempty"`
	MaxBytes       uint64            `json:"max_bytes,omitempty"`
	WarningPercent int32             `json:"warning_percent,omitempty"`
	Tags           map[string]string `json:"tags,omitempty"`
}

// DEKListRequest is the decoded input of the dek_list tool.
type DEKListRequest struct {
	Prefix    string `json:"prefix,omitempty"`
	Recursive bool   `json:"recursive,omitempty"`
	Limit     int32  `json:"limit,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
}

// DEKDeleteRequest is the decoded input of the dek_delete tool.
type DEKDeleteRequest struct {
	Path      string `json:"path"`
	Force     bool   `json:"force,omitempty"`
	MigrateTo string `json:"migrate_to,omitempty"`
}

// KMSEncryptRequest represents an encryption request for MCP.
type KMSEncryptRequest struct {
	KeyID     string `json:"key_id"`
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context,omitempty"`
	Nonce     []byte `json:"nonce,omitempty"`
}

// KMSDecryptRequest represents a decryption request for MCP.
type KMSDecryptRequest struct {
	KeyID      string `json:"key_id"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce,omitempty"`
	Context    []byte `json:"context,omitempty"`
	KeyVersion int    `json:"key_version,omitempty"`
}

// KMSSignRequest represents a signing request for MCP.
type KMSSignRequest struct {
	KeyID         string `json:"key_id"`
	Message       []byte `json:"message"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	PreHashed     bool   `json:"pre_hashed,omitempty"`
}

// KMSVerifyRequest represents a verification request for MCP.
type KMSVerifyRequest struct {
	KeyID         string `json:"key_id"`
	Message       []byte `json:"message"`
	Signature     []byte `json:"signature"`
	HashAlgorithm string `json:"hash_algorithm,omitempty"`
	KeyVersion    int    `json:"key_version,omitempty"`
}

// KMSHashRequest represents a keyless hash request for MCP. HashAlgorithm
// is a platform.v1 HashAlgorithm value; zero selects SHA-256.
type KMSHashRequest struct {
	Data          []byte `json:"data"`
	HashAlgorithm int32  `json:"algorithm,omitempty"`
}

// KMSHMACRequest represents an HMAC generation request for MCP.
type KMSHMACRequest struct {
	KeyID         string `json:"key_id"`
	Message       []byte `json:"message"`
	HashAlgorithm int32  `json:"hash_algorithm,omitempty"`
}

// KMSVerifyHMACRequest represents an HMAC verification request for MCP.
type KMSVerifyHMACRequest struct {
	KeyID         string `json:"key_id"`
	Message       []byte `json:"message"`
	HMAC          []byte `json:"hmac"`
	HashAlgorithm int32  `json:"hash_algorithm,omitempty"`
	KeyVersion    uint64 `json:"key_version,omitempty"`
}

// KMSRewrapRequest represents a rewrap request for MCP. SourceVersion must
// be zero: the SDK rewrap request has no source version, so a non-zero value
// is refused rather than ignored.
type KMSRewrapRequest struct {
	KeyID         string `json:"key_id"`
	Ciphertext    []byte `json:"ciphertext"`
	Context       []byte `json:"context,omitempty"`
	Nonce         []byte `json:"nonce,omitempty"`
	SourceVersion uint64 `json:"source_version,omitempty"`
}

// KMSImportKeyRequest imports existing key material. Algorithm and Usage carry
// the platform.v1 KMSKeyAlgorithm and KeyUsage numbers, as in the gRPC
// ImportKeyRequest key_spec.
type KMSImportKeyRequest struct {
	Name               string            `json:"name,omitempty"`
	Description        string            `json:"description,omitempty"`
	KeyMaterial        []byte            `json:"key_material"`
	WrappingKeyID      string            `json:"wrapping_key_id,omitempty"`
	Algorithm          int32             `json:"algorithm,omitempty"`
	KeySize            int32             `json:"key_size,omitempty"`
	Usage              []int32           `json:"usage,omitempty"`
	Exportable         bool              `json:"exportable,omitempty"`
	DeletionProtection bool              `json:"deletion_protection,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
}

// KMSUpdateKeyStatusRequest sets the platform.v1 KeyStatus of a key, or of
// one key version when Version is non-zero.
type KMSUpdateKeyStatusRequest struct {
	KeyID   string `json:"key_id"`
	Version uint64 `json:"version,omitempty"`
	Status  int32  `json:"status"`
}

// KMSListKeyVersionsRequest lists a key's versions with offset-cursor
// pagination.
type KMSListKeyVersionsRequest struct {
	KeyID  string `json:"key_id"`
	Limit  int32  `json:"limit,omitempty"`
	Cursor string `json:"cursor,omitempty"`
}

// KMSBatchEncryptItem is one plaintext of a batch encrypt request.
type KMSBatchEncryptItem struct {
	ItemID    string `json:"item_id,omitempty"`
	Plaintext []byte `json:"plaintext"`
	Context   []byte `json:"context,omitempty"`
	Nonce     []byte `json:"nonce,omitempty"`
}

// KMSBatchEncryptRequest encrypts every item under one key.
type KMSBatchEncryptRequest struct {
	KeyID string                `json:"key_id"`
	Items []KMSBatchEncryptItem `json:"items"`
}

// KMSBatchDecryptItem is one ciphertext of a batch decrypt request.
type KMSBatchDecryptItem struct {
	ItemID     string `json:"item_id,omitempty"`
	Ciphertext []byte `json:"ciphertext"`
	Context    []byte `json:"context,omitempty"`
	Nonce      []byte `json:"nonce,omitempty"`
	KeyVersion uint64 `json:"key_version,omitempty"`
}

// KMSBatchDecryptRequest decrypts every item under one key.
type KMSBatchDecryptRequest struct {
	KeyID string                `json:"key_id"`
	Items []KMSBatchDecryptItem `json:"items"`
}

// TPMVerifyQuoteRequest represents a TPM quote verification request for MCP,
// with the same fields as the gRPC VerifyQuoteRequest. AKPublic is the
// attestation key's PKIX DER; when it is empty the platform IAK verifies.
// SignatureAlgorithm is the scheme the quote declares (#482).
type TPMVerifyQuoteRequest struct {
	Quote              []byte `json:"quote"`
	Signature          []byte `json:"signature"`
	Nonce              []byte `json:"nonce"`
	ChannelBinding     []byte `json:"channel_binding,omitempty"`
	AKPublic           []byte `json:"ak_public,omitempty"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

// KMSGenerateDataKeyRequest represents a data key generation request for MCP.
// Data keys are used for envelope encryption where:
// 1. A data encryption key (DEK) is generated
// 2. Data is encrypted locally using the DEK
// 3. The DEK is encrypted (wrapped) by a KMS-managed key (KEK)
// 4. Both encrypted data and wrapped DEK are stored together
type KMSGenerateDataKeyRequest struct {
	// KeyID is the ID of the key encryption key (KEK) to wrap the DEK
	KeyID string `json:"key_id"`
	// Algorithm is the DEK algorithm (default: aes-256-gcm)
	Algorithm string `json:"algorithm,omitempty"`
	// Context is optional encryption context (AAD) for additional authentication
	Context string `json:"context,omitempty"`
}

// KMSGenerateWrappedDataKeyRequest represents a wrapped-only data key generation request.
// This generates only the wrapped DEK without exposing the plaintext version.
type KMSGenerateWrappedDataKeyRequest struct {
	// KeyID is the ID of the key encryption key (KEK) to wrap the DEK
	KeyID string `json:"key_id"`
	// Algorithm is the DEK algorithm (default: aes-256-gcm)
	Algorithm string `json:"algorithm,omitempty"`
	// Context is optional encryption context (AAD) for additional authentication
	Context string `json:"context,omitempty"`
}

// IPAMPoolCreateRequest represents an IPAM pool creation request for MCP.
// PortRates are the rate limits SDNSetPortState applies to a port: ingress
// policing on what it receives and egress shaping on what it sends, each a
// rate in bits per second and a burst in bits. A zero rate leaves that
// direction as it is; a zero burst lets Open vSwitch pick its default.
type PortRates struct {
	IngressRate  uint64
	IngressBurst uint64
	EgressRate   uint64
	EgressBurst  uint64
}

type IPAMPoolCreateRequest struct {
	Name                 string `json:"name"`
	CIDR                 string `json:"cidr"`
	Gateway              string `json:"gateway,omitempty"`
	Zone                 string `json:"zone,omitempty"`
	Description          string `json:"description,omitempty"`
	LeaseDurationSeconds int64  `json:"lease_duration_seconds,omitempty"`
	// Reserved lists never-allocatable prefixes in CIDR notation.
	Reserved []string `json:"reserved,omitempty"`
	// RangeStart and RangeEnd bound dynamic allocation; set both or neither.
	RangeStart string `json:"range_start,omitempty"`
	RangeEnd   string `json:"range_end,omitempty"`
}

// IPAMPoolUpdateRequest represents an IPAM pool update request for MCP.
// CIDR is immutable and must not be specified.
type IPAMPoolUpdateRequest struct {
	Name                 string `json:"name,omitempty"`
	Gateway              string `json:"gateway,omitempty"`
	Zone                 string `json:"zone,omitempty"`
	Description          string `json:"description,omitempty"`
	LeaseDurationSeconds int64  `json:"lease_duration_seconds,omitempty"`
	// Reserved replaces the never-allocatable prefixes when non-nil (an
	// empty list clears them); nil keeps them.
	Reserved []string `json:"reserved,omitempty"`
	// RangeStart and RangeEnd replace the dynamic window bounds when
	// non-nil ("" clears a bound); nil keeps them.
	RangeStart *string `json:"range_start,omitempty"`
	RangeEnd   *string `json:"range_end,omitempty"`
}

// NetworkZonePathRequest represents a directed traffic path for zone creation/update.
type NetworkZonePathRequest struct {
	Zone     string   `json:"zone"`
	Services []string `json:"services,omitempty"`
}

// NetworkZonePrivilegedAccessRequest is the audited override a zone carries
// when it opens a path into control-plane or management beyond the
// reference defaults.
type NetworkZonePrivilegedAccessRequest struct {
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

// NetworkZoneCreateRequest represents an owner-defined zone creation request
// for MCP.
type NetworkZoneCreateRequest struct {
	Name             string                              `json:"name"`
	Offset           uint8                               `json:"offset,omitempty"`
	PortClasses      []string                            `json:"port_classes,omitempty"`
	InternetIngress  bool                                `json:"internet_ingress,omitempty"`
	IsolateFrom      []string                            `json:"isolate_from,omitempty"`
	AllowTo          []*NetworkZonePathRequest           `json:"allow_to,omitempty"`
	Services         []string                            `json:"services,omitempty"`
	Isolate          bool                                `json:"isolate,omitempty"`
	OOB              bool                                `json:"oob,omitempty"`
	LifecycleRole    string                              `json:"lifecycle_role,omitempty"`
	PrivilegedAccess *NetworkZonePrivilegedAccessRequest `json:"privileged_access,omitempty"`
}

// NetworkZoneUpdateRequest represents a network zone update request for MCP:
// a built-in zone's tuned policy or an owner-defined zone's replacement. The
// zone name is passed separately and never changes.
type NetworkZoneUpdateRequest struct {
	Offset           uint8                               `json:"offset,omitempty"`
	PortClasses      []string                            `json:"port_classes,omitempty"`
	InternetIngress  bool                                `json:"internet_ingress,omitempty"`
	IsolateFrom      []string                            `json:"isolate_from,omitempty"`
	AllowTo          []*NetworkZonePathRequest           `json:"allow_to,omitempty"`
	Services         []string                            `json:"services,omitempty"`
	Isolate          bool                                `json:"isolate,omitempty"`
	OOB              bool                                `json:"oob,omitempty"`
	LifecycleRole    string                              `json:"lifecycle_role,omitempty"`
	PrivilegedAccess *NetworkZonePrivilegedAccessRequest `json:"privileged_access,omitempty"`
}

// ZoneConfig converts the create request to a zone.ZoneConfig.
func (r *NetworkZoneCreateRequest) ZoneConfig() zone.ZoneConfig {
	return buildMCPZoneConfig(r.Name, r.Offset, r.PortClasses, r.InternetIngress, r.IsolateFrom,
		r.AllowTo, r.Services, r.Isolate, r.OOB, r.LifecycleRole, r.PrivilegedAccess)
}

// ZoneConfig converts the update request for zone name to a zone.ZoneConfig.
func (r *NetworkZoneUpdateRequest) ZoneConfig(name string) zone.ZoneConfig {
	return buildMCPZoneConfig(name, r.Offset, r.PortClasses, r.InternetIngress, r.IsolateFrom,
		r.AllowTo, r.Services, r.Isolate, r.OOB, r.LifecycleRole, r.PrivilegedAccess)
}

// buildMCPZoneConfig assembles a zone.ZoneConfig from MCP request fields; the
// create and update requests share it so the two paths cannot drift.
func buildMCPZoneConfig(name string, offset uint8, portClasses []string, internetIngress bool,
	isolateFrom []string, allowTo []*NetworkZonePathRequest, services []string, isolate, oob bool,
	lifecycleRole string, pa *NetworkZonePrivilegedAccessRequest) zone.ZoneConfig {
	cfg := zone.ZoneConfig{
		Name:            zone.Zone(name),
		Offset:          zone.Offset(offset),
		InternetIngress: internetIngress,
		Services:        services,
		Isolate:         isolate,
		OOB:             oob,
		LifecycleRole:   zone.LifecycleRole(lifecycleRole),
	}
	for _, c := range portClasses {
		cfg.PortClasses = append(cfg.PortClasses, zone.PortClass(c))
	}
	for _, z := range isolateFrom {
		cfg.IsolateFrom = append(cfg.IsolateFrom, zone.Zone(z))
	}
	for _, p := range allowTo {
		if p == nil {
			continue
		}
		cfg.AllowTo = append(cfg.AllowTo, zone.ZonePath{Zone: zone.Zone(p.Zone), Services: p.Services})
	}
	if pa != nil {
		cfg.PrivilegedAccess = &zone.PrivilegedAccess{Reason: pa.Reason, ApprovedBy: pa.ApprovedBy}
	}
	return cfg
}

// ServiceProvider is the interface that MCP uses to access platform services.
// This allows the MCP server to call platform operations.
type ServiceProvider interface {
	// vTPM bundle CRUD operations
	VTPMCreate(ctx context.Context, name string, algorithm string, secureBoot bool, labels map[string]string) (interface{}, error)
	VTPMDelete(ctx context.Context, name string) error
	VTPMList(ctx context.Context, opts *vtpm.ListOptions) ([]interface{}, error)
	VTPMGet(ctx context.Context, name string) (interface{}, error)
	VTPMValidate(ctx context.Context, name string) (interface{}, error)
	VTPMExport(ctx context.Context, name string) (interface{}, error)
	VTPMImport(ctx context.Context, data []byte) (interface{}, error)

	// vTPM template operations
	VTPMCreateTemplate(ctx context.Context, id string, description string, algorithm string, secureBoot bool) (interface{}, error)
	VTPMGetTemplate(ctx context.Context, id string) (interface{}, error)
	VTPMDeleteTemplate(ctx context.Context, id string) error
	VTPMListTemplates(ctx context.Context) (interface{}, error)
	VTPMCloneTemplate(ctx context.Context, templateID string, hostname string, labels map[string]string) (interface{}, error)

	// vTPM path operations
	VTPMGetBundlePath(ctx context.Context, name string) (interface{}, error)
	VTPMGetTPMSocketPath(ctx context.Context, name string) (interface{}, error)
	VTPMGetNVRAMPath(ctx context.Context, name string) (interface{}, error)

	// vTPM runtime TPM operations
	// VTPMStart starts the bundle's vTPM and returns the start reply:
	// bundle_id, running and socket_path, as gRPC StartVTPM answers.
	VTPMStart(ctx context.Context, name string) (interface{}, error)
	VTPMStop(ctx context.Context, name string) error
	VTPMIsRunning(ctx context.Context, name string) (interface{}, error)
	VTPMQuote(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error)
	VTPMSeal(ctx context.Context, name string, data []byte, pcrs []int, authValue string) ([]byte, error)
	VTPMUnseal(ctx context.Context, name string, sealed []byte, authValue string) ([]byte, error)
	VTPMExtendPCR(ctx context.Context, name string, pcr int, data []byte) error
	VTPMReadPCR(ctx context.Context, name string, pcr int) ([]byte, error)

	// DNS operations
	DNSAddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error
	DNSDeleteRecord(ctx context.Context, name string, recordType string) error
	DNSGetRecord(ctx context.Context, name string, recordType string) (interface{}, error)
	DNSListRecords(ctx context.Context, zone string) ([]interface{}, error)
	DNSResolve(ctx context.Context, name string, recordType string) ([]string, error)
	DNSCreateZone(ctx context.Context, zone string) error
	DNSDeleteZone(ctx context.Context, zone string) error
	DNSListZones(ctx context.Context) ([]string, error)

	// Device operations
	DeviceRegister(ctx context.Context, req *DeviceRegisterRequest) (interface{}, error)
	DeviceGet(ctx context.Context, deviceID string) (interface{}, error)
	DeviceFindBySerial(ctx context.Context, serial string) (interface{}, error)
	DeviceList(ctx context.Context, filter map[string]string) ([]interface{}, error)
	DeviceDelete(ctx context.Context, deviceID string) error
	DeviceUpdate(ctx context.Context, deviceID string, updates map[string]interface{}) error
	DeviceAttest(ctx context.Context, deviceID string, evidence []byte) (interface{}, error)
	// DeviceRecordAttestCert records the device's attestation certificate on
	// its platform record without re-enrolling it (fail-closed; see
	// device.AttestCertRecorder). reissue lets the CA issue a fresh
	// certificate over the enrolled attestation key. clearOnRefusal clears
	// the stored certificate when every candidate is refused, so the
	// device reads as absent instead of quarantined.
	DeviceRecordAttestCert(ctx context.Context, deviceID string, reissue, clearOnRefusal bool) (interface{}, error)
	// DeviceDisable blocks the device's switch port and records it
	// suspended (see device.LifecycleService).
	DeviceDisable(ctx context.Context, deviceID, reason string) (interface{}, error)
	// DeviceEnable re-admits a disabled device to the quarantine zone
	// pending a re-attestation.
	DeviceEnable(ctx context.Context, deviceID string) (interface{}, error)
	// DeviceBootCertificate and DeviceBootDelivery serve a diskless node's
	// boot requests through the shared boot service, which enforces the
	// proof of possession and the channel binding. A transport with no TLS
	// connection (MCP) cannot satisfy that binding and is refused.
	DeviceBootCertificate(ctx context.Context, identity string, signature []byte) (interface{}, error)
	DeviceBootDelivery(ctx context.Context, evidence []byte) (interface{}, error)
	DeviceProvision(ctx context.Context, deviceID string, profile string) error

	// SDN Bridge operations
	SDNGetPortState(ctx context.Context, bridgeName string, portName string) (interface{}, error)
	// SDNSetPortState sets a port's admin state (up or down) and the rate
	// limits in rates, and returns the updated port.
	SDNSetPortState(ctx context.Context, bridgeName string, portName string, state string, rates PortRates) (interface{}, error)
	SDNListBridges(ctx context.Context) ([]interface{}, error)
	SDNCreateBridge(ctx context.Context, bridgeName string) error
	SDNDeleteBridge(ctx context.Context, bridgeName string) error
	SDNAddPort(ctx context.Context, bridgeName string, portName string, portType string) error
	SDNDeletePort(ctx context.Context, bridgeName string, portName string) error
	// SDNApplyPolicy creates or replaces a policy. The document is the REST
	// create-policy body (docs/sdn/api-reference-rest.md), so a policy has one
	// shape on every transport.
	SDNApplyPolicy(ctx context.Context, policy json.RawMessage) (interface{}, error)
	SDNGetPolicy(ctx context.Context, policyID string) (interface{}, error)
	SDNListPolicies(ctx context.Context, policyType string, targetID string) ([]interface{}, error)
	SDNDeletePolicy(ctx context.Context, policyID string) error

	// SDN Flow operations
	SDNAddFlow(ctx context.Context, bridgeName string, flow map[string]interface{}) (interface{}, error)
	SDNDeleteFlow(ctx context.Context, bridgeName string, flowID string) error
	SDNListFlows(ctx context.Context, bridgeName string) ([]interface{}, error)
	SDNFlushFlows(ctx context.Context, bridgeName string) (uint32, error)

	// SDN VLAN operations
	SDNCreateVLAN(ctx context.Context, bridgeName string, vlanID int, name string) (interface{}, error)
	SDNDeleteVLAN(ctx context.Context, bridgeName string, vlanID int) error
	SDNListVLANs(ctx context.Context, bridgeName string) ([]interface{}, error)

	// SDN Statistics
	SDNGetPortStats(ctx context.Context, bridgeName string, portName string) (interface{}, error)
	SDNGetFlowStats(ctx context.Context, bridgeName string, flowID string) (interface{}, error)

	// Overlay network operations
	OverlayStatus(ctx context.Context) (interface{}, error)
	OverlayVTEPList(ctx context.Context) ([]interface{}, error)
	OverlayVTEPGet(ctx context.Context, nodeID string) (interface{}, error)
	OverlayVNIList(ctx context.Context) ([]interface{}, error)
	OverlayVNICreate(ctx context.Context, vni uint32, vlan uint16, name string) (interface{}, error)
	OverlayVNIDelete(ctx context.Context, vni uint32) error
	OverlayTunnelList(ctx context.Context, vni uint32) ([]interface{}, error)
	OverlayTunnelStats(ctx context.Context, remoteVTEP string, vni uint32) (interface{}, error)
	OverlayMACList(ctx context.Context, vni uint32) ([]interface{}, error)
	OverlayMACForget(ctx context.Context, mac string, vni uint32) error

	// Gateway operations
	GatewayStatus(ctx context.Context) (interface{}, error)
	GatewayModeSet(ctx context.Context, modes []string) (interface{}, error)

	// Gateway telemetry snapshots (#594). An empty gatewayID means the
	// gateway this node runs itself.
	GatewaySnapshot(ctx context.Context, gatewayID string) (interface{}, error)
	GatewaySnapshots(ctx context.Context) ([]interface{}, error)

	// Gateway BGP operations
	GatewayBGPStatus(ctx context.Context) (interface{}, error)
	GatewayBGPPeers(ctx context.Context) ([]interface{}, error)
	GatewayBGPAnnounce(ctx context.Context, prefix string, nextHop string) error
	GatewayBGPWithdraw(ctx context.Context, prefix string) error
	GatewayBGPPrefixes(ctx context.Context) ([]interface{}, error)

	// Gateway IPAM operations
	GatewayIPAMPools(ctx context.Context, zone string) ([]interface{}, error)
	GatewayIPAMPoolGet(ctx context.Context, poolID string) (interface{}, error)
	GatewayIPAMPoolCreate(ctx context.Context, req *IPAMPoolCreateRequest) (interface{}, error)
	GatewayIPAMPoolUpdate(ctx context.Context, poolID string, req *IPAMPoolUpdateRequest) (interface{}, error)
	GatewayIPAMPoolDelete(ctx context.Context, poolID string) error
	GatewayIPAMAllocate(ctx context.Context, poolID string, deviceID string, hostname string) (interface{}, error)
	GatewayIPAMRelease(ctx context.Context, ip string) error
	GatewayIPAMAllocations(ctx context.Context, poolID string) ([]interface{}, error)

	// Gateway load balancer operations
	GatewayLBVIPAdd(ctx context.Context, req *LBVIPAddRequest) (interface{}, error)
	GatewayLBVIPRemove(ctx context.Context, protocol, address string, port uint16) error
	GatewayLBVIPGet(ctx context.Context, protocol, address string, port uint16) (interface{}, error)
	GatewayLBVIPList(ctx context.Context) ([]interface{}, error)
	GatewayLBVIPSetBackends(ctx context.Context, protocol, address string, port uint16, backends []*LBBackendRequest) (interface{}, error)
	GatewayLBStatus(ctx context.Context) (interface{}, error)

	// GatewayNAT64Status returns the NAT64 translator's health snapshot.
	GatewayNAT64Status(ctx context.Context) (interface{}, error)

	// Gateway performance verification operations. Results are REAL
	// measurements only (timed flow programming, live ovs-vswitchd
	// counters); zone < 0 summarizes every conntrack zone. count == 0
	// selects the service default flow count.
	GatewayPerfFlows(ctx context.Context, bridge string, count int, batch bool) (interface{}, error)
	GatewayPerfDatapath(ctx context.Context, bridge string) (interface{}, error)
	GatewayPerfConntrack(ctx context.Context, zone int) (interface{}, error)

	// Gateway Network Zone operations
	GatewayNetworkZoneCreate(ctx context.Context, req *NetworkZoneCreateRequest) (interface{}, error)
	GatewayNetworkZoneUpdate(ctx context.Context, name string, req *NetworkZoneUpdateRequest) (interface{}, error)
	GatewayNetworkZoneDelete(ctx context.Context, name string) (bool, error)
	GatewayNetworkZoneList(ctx context.Context, lifecycleRole string) ([]interface{}, error)
	GatewayNetworkZoneVLAN(ctx context.Context, zoneName string) (uint16, error)

	// NTP (time synchronization) operations. Results are live readings
	// from chronyd's control socket; NTPStep is an operator recovery
	// action that fails when no source is reachable.
	NTPStatus(ctx context.Context) (interface{}, error)
	NTPSources(ctx context.Context) (interface{}, error)
	NTPStep(ctx context.Context) (interface{}, error)

	// VPN control-plane operations: peer enrolment, session status from
	// gateway telemetry, and tenant posture policies. An empty tenantID or
	// gatewayID on a list or status call means every tenant or gateway.
	VPNEnrolPeer(ctx context.Context, tenantID, deviceID string, zones []string) (interface{}, error)
	VPNListPeers(ctx context.Context, tenantID string) (interface{}, error)
	VPNRevokePeer(ctx context.Context, tenantID, deviceID string) (interface{}, error)
	VPNStatus(ctx context.Context, gatewayID string) (interface{}, error)
	VPNPosturePolicyGet(ctx context.Context, tenantID, name string) (interface{}, error)
	VPNPosturePolicySet(ctx context.Context, tenantID, name, module string) (interface{}, error)
	VPNPosturePolicyDelete(ctx context.Context, tenantID, name string) (interface{}, error)
	VPNPosturePolicyList(ctx context.Context, tenantID string) (interface{}, error)

	// Health operations
	Health(ctx context.Context) (interface{}, error)
	Liveness(ctx context.Context) (interface{}, error)
	Readiness(ctx context.Context) (interface{}, error)

	// Daemon management operations
	DaemonStatus(ctx context.Context) (interface{}, error)
	DaemonVersion(ctx context.Context) (interface{}, error)
	DaemonListServices(ctx context.Context) (interface{}, error)
	DaemonGetService(ctx context.Context, name string) (interface{}, error)
	DaemonStartService(ctx context.Context, name string) (interface{}, error)
	DaemonStopService(ctx context.Context, name string) (interface{}, error)
	DaemonRestartService(ctx context.Context, name string) (interface{}, error)
	DaemonListProtocols(ctx context.Context) (interface{}, error)

	// CA operations
	CAInfo(ctx context.Context) (interface{}, error)
	CAIssue(ctx context.Context, req *CAIssueRequest) (interface{}, error)
	CASignCSR(ctx context.Context, req *CASignCSRRequest) (interface{}, error)
	CAGet(ctx context.Context, serial string, includePEM, includeDER bool) (interface{}, error)
	CAList(ctx context.Context, limit int, cursor string, status string) (interface{}, error)
	CARevoke(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error)
	CARenew(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error)
	CAVerify(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error)
	CACRL(ctx context.Context) (interface{}, error)
	CABundle(ctx context.Context, storeType string, algorithm string) (interface{}, error)

	// IAM operations. Each answers what its gRPC PlatformIAMService method
	// answers, the same response message and the same error class.
	IAMCreateUser(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error)
	IAMDeleteUser(ctx context.Context, tenantID string, userID string) (interface{}, error)
	IAMGetUser(ctx context.Context, tenantID string, userID string) (interface{}, error)
	IAMUpdateUser(ctx context.Context, req *IAMUpdateUserRequest) (interface{}, error)
	IAMListUsers(ctx context.Context, req *IAMListUsersRequest) (interface{}, error)

	// IAM Role operations
	IAMCreateRole(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error)
	IAMDeleteRole(ctx context.Context, tenantID string, roleID string) (interface{}, error)
	IAMGetRole(ctx context.Context, tenantID string, roleID string) (interface{}, error)
	IAMListRoles(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error)

	// IAM Role assignment operations
	IAMAssignRole(ctx context.Context, tenantID string, userID string, roleID string) (interface{}, error)
	IAMRevokeRole(ctx context.Context, tenantID string, userID string, roleID string) (interface{}, error)

	// IAM Authorization operations
	IAMCheckPermission(ctx context.Context, req *IAMCheckPermissionRequest) (interface{}, error)
	IAMAuthenticate(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error)

	// IAM Group operations
	IAMCreateGroup(ctx context.Context, req *IAMCreateGroupRequest) (interface{}, error)
	IAMDeleteGroup(ctx context.Context, tenantID string, groupID string) (interface{}, error)
	IAMGetGroup(ctx context.Context, tenantID string, groupID string) (interface{}, error)
	IAMUpdateGroup(ctx context.Context, req *IAMUpdateGroupRequest) (interface{}, error)
	IAMListGroups(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error)
	IAMAddGroupMember(ctx context.Context, tenantID string, groupID string, userID string) (interface{}, error)
	IAMRemoveGroupMember(ctx context.Context, tenantID string, groupID string, userID string) (interface{}, error)

	// IAM Tenant operations
	IAMCreateTenant(ctx context.Context, req *IAMCreateTenantRequest) (interface{}, error)
	IAMDeleteTenant(ctx context.Context, tenantID string) (interface{}, error)
	IAMGetTenant(ctx context.Context, tenantID string) (interface{}, error)
	IAMListTenants(ctx context.Context, page IAMPagination) (interface{}, error)

	// IAM Token operations
	IAMCreateToken(ctx context.Context, req *IAMCreateTokenRequest) (interface{}, error)
	IAMRevokeToken(ctx context.Context, tokenID string) error
	IAMVerifyToken(ctx context.Context, token string) (interface{}, error)

	// KMS Key management operations
	KMSCreateKey(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error)
	KMSDeleteKey(ctx context.Context, keyID string) error
	KMSGetKey(ctx context.Context, keyID string, version uint64) (interface{}, error)
	KMSListKeys(ctx context.Context, limit int, offset int) (interface{}, error)
	KMSRotateKey(ctx context.Context, keyID string) (interface{}, error)
	KMSExportPublicKey(ctx context.Context, req *KMSExportPublicKeyRequest) (interface{}, error)

	// KMS Key lifecycle operations
	KMSRevokeKey(ctx context.Context, keyID string, reason string) (interface{}, error)
	KMSGetKeyMetadata(ctx context.Context, keyID string) (interface{}, error)
	KMSUpdateKeyMetadata(ctx context.Context, req *KMSUpdateKeyMetadataRequest) (interface{}, error)
	KMSSetKeyPolicy(ctx context.Context, req *KMSSetKeyPolicyRequest) (interface{}, error)
	KMSGetKeyPolicy(ctx context.Context, keyID string) (interface{}, error)
	KMSGetSupportedAlgorithms(ctx context.Context) ([]string, error)
	KMSBackendStatus(ctx context.Context) (interface{}, error)

	// Secrets operations
	SecretStore(ctx context.Context, req *SecretStoreRequest) (interface{}, error)
	SecretGet(ctx context.Context, secretID string, version uint64) (interface{}, error)
	SecretList(ctx context.Context, limit int) (interface{}, error)
	SecretDelete(ctx context.Context, secretID string) error
	SecretSetRotationPolicy(ctx context.Context, req *SecretSetRotationPolicyRequest) (interface{}, error)
	SecretGetRotationPolicy(ctx context.Context, secretID string) (interface{}, error)
	SecretGetVersion(ctx context.Context, secretID string, version uint64) (interface{}, error)
	SecretListVersions(ctx context.Context, secretID string, limit int) (interface{}, error)
	SecretRotate(ctx context.Context, req *SecretRotateRequest) (interface{}, error)
	SecretRollback(ctx context.Context, secretID string, targetVersion uint64) (interface{}, error)
	SecretUpdateStatus(ctx context.Context, secretID, status string) (interface{}, error)

	// DEK operations
	DEKCreate(ctx context.Context, req *DEKCreateRequest) (interface{}, error)
	DEKList(ctx context.Context, req *DEKListRequest) (interface{}, error)
	DEKGet(ctx context.Context, path string) (interface{}, error)
	DEKStatus(ctx context.Context, path string) (interface{}, error)
	DEKRotate(ctx context.Context, path string, background bool) (interface{}, error)
	DEKDelete(ctx context.Context, req *DEKDeleteRequest) (interface{}, error)

	// KMS Cryptographic operations
	KMSEncrypt(ctx context.Context, req *KMSEncryptRequest) (interface{}, error)
	KMSDecrypt(ctx context.Context, req *KMSDecryptRequest) (interface{}, error)
	KMSSign(ctx context.Context, req *KMSSignRequest) (interface{}, error)
	KMSVerify(ctx context.Context, req *KMSVerifyRequest) (interface{}, error)
	KMSHash(ctx context.Context, req *KMSHashRequest) (interface{}, error)
	KMSHMAC(ctx context.Context, req *KMSHMACRequest) (interface{}, error)
	KMSVerifyHMAC(ctx context.Context, req *KMSVerifyHMACRequest) (interface{}, error)
	KMSRewrap(ctx context.Context, req *KMSRewrapRequest) (interface{}, error)
	KMSImportKey(ctx context.Context, req *KMSImportKeyRequest) (interface{}, error)
	KMSUpdateKeyStatus(ctx context.Context, req *KMSUpdateKeyStatusRequest) (interface{}, error)
	KMSListKeyVersions(ctx context.Context, req *KMSListKeyVersionsRequest) (interface{}, error)
	KMSBatchEncrypt(ctx context.Context, req *KMSBatchEncryptRequest) (interface{}, error)
	KMSBatchDecrypt(ctx context.Context, req *KMSBatchDecryptRequest) (interface{}, error)

	// KMS Random generation
	KMSGenerateRandom(ctx context.Context, numBytes int) ([]byte, error)

	// KMS Data key operations (envelope encryption)
	KMSGenerateDataKey(ctx context.Context, req *KMSGenerateDataKeyRequest) (interface{}, error)
	KMSGenerateWrappedDataKey(ctx context.Context, req *KMSGenerateWrappedDataKeyRequest) (interface{}, error)

	// Container operations
	ContainerCreate(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error)
	ContainerStart(ctx context.Context, id string) error
	ContainerStop(ctx context.Context, id string, timeout int) error
	ContainerRemove(ctx context.Context, id string, force bool) error
	ContainerGet(ctx context.Context, id string) (interface{}, error)
	ContainerList(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error)
	ContainerLogs(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error)
	ContainerAttest(ctx context.Context, id string) (interface{}, error)

	// IDevID operations (IEEE 802.1AR device identity)
	IDevIDGenerate(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error)
	IDevIDInfo(ctx context.Context) (interface{}, error)
	IDevIDDelete(ctx context.Context) error
	IDevIDCSR(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error)
	IDevIDInstallCert(ctx context.Context, certificatePEM string) (interface{}, error)
	IDevIDGetCert(ctx context.Context, includePEM bool) (interface{}, error)
	IDevIDDeleteCert(ctx context.Context) error
	IDevIDExists(ctx context.Context) (bool, error)

	// IAK operations (IEEE 802.1AR attestation key)
	IAKGenerate(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error)
	IAKInfo(ctx context.Context) (interface{}, error)
	IAKDelete(ctx context.Context) error
	IAKCSR(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error)
	IAKInstallCert(ctx context.Context, certificatePEM string) (interface{}, error)
	IAKGetCert(ctx context.Context, includePEM bool) (interface{}, error)
	IAKDeleteCert(ctx context.Context) error
	IAKExists(ctx context.Context) (bool, error)

	// Device attribute and credential operations
	DeviceAttributes(ctx context.Context) (interface{}, error)
	ActivateCredential(ctx context.Context, credentialBlob []byte, secret []byte) ([]byte, error)

	// Physical TPM operations
	TPMInfo(ctx context.Context) (interface{}, error)
	TPMProvision(ctx context.Context, ownerPassword string) (interface{}, error)
	TPMClear(ctx context.Context, ownerPassword string) (interface{}, error)
	TPMGetEK(ctx context.Context) (interface{}, error)
	TPMGetEKCert(ctx context.Context) (interface{}, error)
	TPMImportEKCert(ctx context.Context, certDER []byte) (interface{}, error)
	TPMCreateEK(ctx context.Context) (interface{}, error)
	TPMDeleteEK(ctx context.Context) (interface{}, error)
	// TPMGetSRK returns the storage root key named by handle.
	// Handle 0 means the SSRK; a handle naming neither platform SRK
	// is an error rather than a fall-through to the SSRK (#475).
	TPMGetSRK(ctx context.Context, handle uint32) (interface{}, error)
	TPMCreateSRK(ctx context.Context) (interface{}, error)
	TPMDeleteSRK(ctx context.Context) (interface{}, error)
	TPMGetIAK(ctx context.Context) (interface{}, error)
	TPMCreateIAK(ctx context.Context) (interface{}, error)
	TPMQuote(ctx context.Context, nonce []byte, pcrs []int) (interface{}, error)
	TPMVerifyQuote(ctx context.Context, req *TPMVerifyQuoteRequest) (interface{}, error)
	TPMReadPCRs(ctx context.Context, indices []int) (interface{}, error)
	TPMExtendPCR(ctx context.Context, pcrIndex int, hashAlg string, data []byte) (interface{}, error)
	TPMEventLog(ctx context.Context) (interface{}, error)
	TPMCapabilities(ctx context.Context) (interface{}, error)
	TPMRandom(ctx context.Context, numBytes int) ([]byte, error)
	TPMSeal(ctx context.Context, data []byte, pcrs []uint32, cn, password string) ([]byte, error)
	TPMUnseal(ctx context.Context, cn, password string) ([]byte, error)
	TPMCertify(ctx context.Context, keyHandle uint32, keyPassword string, nonce []byte) (interface{}, error)
	TPMNVList(ctx context.Context) (interface{}, error)
	TPMNVRead(ctx context.Context, index uint32, size, offset uint16, password string) ([]byte, error)
	TPMNVWrite(ctx context.Context, index uint32, data []byte, offset uint16, password string) (interface{}, error)
	TPMNVDelete(ctx context.Context, index uint32, parentPassword string) (interface{}, error)
	TPMPlatform(ctx context.Context) (interface{}, error)
	TPMMakeCredential(ctx context.Context, akName, secret, ekCert, iakPub []byte) (interface{}, error)
	TPMActivateCredential(ctx context.Context, credentialBlob, encryptedSecret []byte) (interface{}, error)
}

// AuthManager validates authentication tokens.
type AuthManager interface {
	ValidateToken(ctx context.Context, token string) (bool, error)
	GetTokenClaims(ctx context.Context, token string) (map[string]interface{}, error)
}

// AuthorizationService checks permissions.
type AuthorizationService interface {
	CheckPermission(ctx context.Context, subject string, resource string, action string) (bool, error)
}

// Token context key type for avoiding collisions.
type tokenContextKey struct{}

// ContextWithToken adds a token to the context.
func ContextWithToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, tokenContextKey{}, token)
}

// TokenFromContext extracts a token from the context.
func TokenFromContext(ctx context.Context) string {
	if token, ok := ctx.Value(tokenContextKey{}).(string); ok {
		return token
	}
	return ""
}
