//go:build integration

package device

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// DeviceCommands defines the interface for device operations across all protocols
type DeviceCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// Device CRUD Operations

	// RegisterDevice registers a new device
	RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error)

	// GetDevice retrieves a device by its key
	GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error)

	// UpdateDevice updates an existing device
	UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error)

	// DeleteDevice removes a device
	DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error)

	// ListDevices lists all devices with optional filtering
	ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error)

	// Device Lookups

	// FindBySerial finds a device by its serial number
	FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error)

	// Profile CRUD Operations

	// CreateProfile creates a new device profile
	CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error)

	// GetProfile retrieves a profile by its key
	GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error)

	// UpdateProfile updates an existing profile
	UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error)

	// DeleteProfile removes a profile
	DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error)

	// ListProfiles lists all profiles with optional filtering
	ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error)

	// Profile Lookups

	// FindProfileByMACAddress finds a profile by MAC address prefix
	FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error)

	// FindProfileBySerial finds a profile by serial pattern
	FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error)

	// FindMatchingProfile finds a profile matching device attributes
	FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error)

	// Attestation

	// AttestDevice performs device attestation
	AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error)

	// RecordAttestCert records the device's attestation certificate on its
	// platform record without re-enrolling it (fail-closed on the server).
	RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error)

	// Template CRUD Operations

	// CreateTemplate creates a new device template
	CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error)

	// GetTemplate retrieves a template by ID
	GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error)

	// UpdateTemplate updates an existing template
	UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error)

	// DeleteTemplate removes a template
	DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error)

	// ListTemplates lists all templates
	ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error)

	// Template Operations

	// CreateProfileFromTemplate creates a profile from a template
	CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error)

	// FindConfigForDevice finds the config for a device by EK serial or MAC
	FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error)

	// AssignProfileToDevice assigns a profile to a device identity
	AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error)
}

// ============================================================================
// Device CRUD Options and Results
// ============================================================================

// RegisterDeviceOptions contains options for registering a device
type RegisterDeviceOptions struct {
	TenantID   string `json:"tenant_id"`
	Serial     string `json:"serial"`
	Model      string `json:"model,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	AttestCert string `json:"attest_cert,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	HashAlgoId uint32 `json:"hash_algo_id,omitempty"`
}

// RegisterDeviceResult contains the result of device registration
type RegisterDeviceResult struct {
	Device *entities.Device `json:"device"`
}

// GetDeviceOptions contains options for getting a device
type GetDeviceOptions struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
}

// GetDeviceResult contains the result of getting a device
type GetDeviceResult struct {
	Device *entities.Device `json:"device"`
}

// UpdateDeviceOptions contains options for updating a device
type UpdateDeviceOptions struct {
	TenantID   string `json:"tenant_id"`
	DeviceID   string `json:"device_id"`
	Model      string `json:"model,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	AttestCert string `json:"attest_cert,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	HashAlgoId uint32 `json:"hash_algo_id,omitempty"`
}

// UpdateDeviceResult contains the result of updating a device
type UpdateDeviceResult struct {
	Device *entities.Device `json:"device"`
}

// DeleteDeviceOptions contains options for deleting a device
type DeleteDeviceOptions struct {
	TenantID string `json:"tenant_id"`
	DeviceID string `json:"device_id"`
}

// DeleteDeviceResult contains the result of deleting a device
type DeleteDeviceResult struct {
	Success bool `json:"success"`
}

// ListDevicesOptions contains options for listing devices
type ListDevicesOptions struct {
	TenantID  string `json:"tenant_id"`
	ProfileID string `json:"profile_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
}

// ListDevicesResult contains the result of listing devices
type ListDevicesResult struct {
	Devices []*entities.Device `json:"devices"`
	Total   int                `json:"total"`
}

// ============================================================================
// Device Lookup Options and Results
// ============================================================================

// FindBySerialOptions contains options for finding a device by serial
type FindBySerialOptions struct {
	TenantID string `json:"tenant_id"`
	Serial   string `json:"serial"`
}

// FindBySerialResult contains the result of finding a device by serial
type FindBySerialResult struct {
	Device *entities.Device `json:"device"`
}

// ============================================================================
// Profile CRUD Options and Results
// ============================================================================

// CreateProfileOptions contains options for creating a profile
type CreateProfileOptions struct {
	TenantID     string                      `json:"tenant_id"`
	Name         string                      `json:"name"`
	Model        string                      `json:"model,omitempty"`
	Role         entities.DeviceRole         `json:"role,omitempty"`
	MACPrefix    string                      `json:"mac_prefix,omitempty"`
	SerialPrefix string                      `json:"serial_prefix,omitempty"`
	MatchRules   *entities.ProfileMatchRules `json:"match_rules,omitempty"`
}

// CreateProfileResult contains the result of creating a profile
type CreateProfileResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// GetProfileOptions contains options for getting a profile
type GetProfileOptions struct {
	TenantID  string `json:"tenant_id"`
	ProfileID string `json:"profile_id"`
}

// GetProfileResult contains the result of getting a profile
type GetProfileResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// UpdateProfileOptions contains options for updating a profile
type UpdateProfileOptions struct {
	TenantID     string                      `json:"tenant_id"`
	ProfileID    string                      `json:"profile_id"`
	Name         string                      `json:"name,omitempty"`
	Model        string                      `json:"model,omitempty"`
	Role         entities.DeviceRole         `json:"role,omitempty"`
	MACPrefix    string                      `json:"mac_prefix,omitempty"`
	SerialPrefix string                      `json:"serial_prefix,omitempty"`
	MatchRules   *entities.ProfileMatchRules `json:"match_rules,omitempty"`
}

// UpdateProfileResult contains the result of updating a profile
type UpdateProfileResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// DeleteProfileOptions contains options for deleting a profile
type DeleteProfileOptions struct {
	TenantID  string `json:"tenant_id"`
	ProfileID string `json:"profile_id"`
}

// DeleteProfileResult contains the result of deleting a profile
type DeleteProfileResult struct {
	Success bool `json:"success"`
}

// ListProfilesOptions contains options for listing profiles
type ListProfilesOptions struct {
	TenantID string              `json:"tenant_id"`
	Role     entities.DeviceRole `json:"role,omitempty"`
	Limit    int                 `json:"limit,omitempty"`
	Offset   int                 `json:"offset,omitempty"`
}

// ListProfilesResult contains the result of listing profiles
type ListProfilesResult struct {
	Profiles []*entities.DeviceProfile `json:"profiles"`
	Total    int                       `json:"total"`
}

// ============================================================================
// Profile Lookup Options and Results
// ============================================================================

// FindProfileByMACAddressOptions contains options for finding a profile by MAC address
type FindProfileByMACAddressOptions struct {
	TenantID   string `json:"tenant_id"`
	MACAddress string `json:"mac_address"`
}

// FindProfileByMACAddressResult contains the result of finding a profile by MAC address
type FindProfileByMACAddressResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// FindProfileBySerialOptions contains options for finding a profile by serial
type FindProfileBySerialOptions struct {
	TenantID string `json:"tenant_id"`
	Serial   string `json:"serial"`
}

// FindProfileBySerialResult contains the result of finding a profile by serial
type FindProfileBySerialResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// FindMatchingProfileOptions contains options for finding a matching profile
type FindMatchingProfileOptions struct {
	TenantID   string `json:"tenant_id"`
	MACAddress string `json:"mac_address,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Model      string `json:"model,omitempty"`
}

// FindMatchingProfileResult contains the result of finding a matching profile
type FindMatchingProfileResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// ============================================================================
// Attestation Options and Results
// ============================================================================

// AttestDeviceOptions contains options for device attestation
type AttestDeviceOptions struct {
	TenantID     string `json:"tenant_id"`
	DeviceID     string `json:"device_id"`
	EKCert       []byte `json:"ek_cert,omitempty"`
	AIKPublic    []byte `json:"aik_public,omitempty"`
	Quote        []byte `json:"quote,omitempty"`
	EventLog     []byte `json:"event_log,omitempty"`
	PCRs         []byte `json:"pcrs,omitempty"`
	Nonce        []byte `json:"nonce,omitempty"`
	AttestFormat string `json:"attest_format,omitempty"`
}

// RecordAttestCertOptions names the device whose attestation certificate is
// recorded and whether the CA may issue a fresh one.
type RecordAttestCertOptions struct {
	TenantID string `json:"tenant_id,omitempty"`
	DeviceID string `json:"device_id"`
	Reissue  bool   `json:"reissue"`
}

// RecordAttestCertResult mirrors platform.v1
// RecordAttestationCertificateResponse with proto JSON names.
type RecordAttestCertResult struct {
	DeviceID          string `json:"device_id"`
	Serial            string `json:"serial,omitempty"`
	Model             string `json:"model,omitempty"`
	Changed           bool   `json:"changed"`
	Source            string `json:"source"`
	SourceDetail      string `json:"source_detail,omitempty"`
	Reissued          bool   `json:"reissued"`
	Subject           string `json:"subject"`
	CertificateSerial string `json:"certificate_serial"`
	AttestCert        string `json:"attest_cert"`
}

// AttestDeviceResult contains the result of device attestation
type AttestDeviceResult struct {
	Attested    bool   `json:"attested"`
	DeviceID    string `json:"device_id"`
	TrustScore  int    `json:"trust_score,omitempty"`
	Message     string `json:"message,omitempty"`
	Certificate []byte `json:"certificate,omitempty"`
}

// ============================================================================
// Template CRUD Options and Results
// ============================================================================

// CreateTemplateOptions contains options for creating a device template
type CreateTemplateOptions struct {
	TenantID    string                      `json:"tenant_id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description,omitempty"`
	Role        entities.DeviceRole         `json:"role,omitempty"`
	Config      []byte                      `json:"config,omitempty"`
	MatchRules  *entities.ProfileMatchRules `json:"match_rules,omitempty"`
}

// CreateTemplateResult contains the result of creating a template
type CreateTemplateResult struct {
	Template *entities.DeviceTemplate `json:"template"`
}

// GetTemplateOptions contains options for getting a template
type GetTemplateOptions struct {
	TenantID   string `json:"tenant_id"`
	TemplateID string `json:"template_id"`
}

// GetTemplateResult contains the result of getting a template
type GetTemplateResult struct {
	Template *entities.DeviceTemplate `json:"template"`
}

// UpdateTemplateOptions contains options for updating a template
type UpdateTemplateOptions struct {
	TenantID    string                      `json:"tenant_id"`
	TemplateID  string                      `json:"template_id"`
	Name        string                      `json:"name,omitempty"`
	Description string                      `json:"description,omitempty"`
	Role        entities.DeviceRole         `json:"role,omitempty"`
	Config      []byte                      `json:"config,omitempty"`
	MatchRules  *entities.ProfileMatchRules `json:"match_rules,omitempty"`
}

// UpdateTemplateResult contains the result of updating a template
type UpdateTemplateResult struct {
	Template *entities.DeviceTemplate `json:"template"`
}

// DeleteTemplateOptions contains options for deleting a template
type DeleteTemplateOptions struct {
	TenantID   string `json:"tenant_id"`
	TemplateID string `json:"template_id"`
}

// DeleteTemplateResult contains the result of deleting a template
type DeleteTemplateResult struct {
	Success bool `json:"success"`
}

// ListTemplatesOptions contains options for listing templates
type ListTemplatesOptions struct {
	TenantID string              `json:"tenant_id"`
	Role     entities.DeviceRole `json:"role,omitempty"`
	Limit    int                 `json:"limit,omitempty"`
	Offset   int                 `json:"offset,omitempty"`
}

// ListTemplatesResult contains the result of listing templates
type ListTemplatesResult struct {
	Templates []*entities.DeviceTemplate `json:"templates"`
	Total     int                        `json:"total"`
}

// ============================================================================
// Template Operation Options and Results
// ============================================================================

// CreateProfileFromTemplateOptions contains options for creating a profile from a template
type CreateProfileFromTemplateOptions struct {
	TenantID   string `json:"tenant_id"`
	TemplateID string `json:"template_id"`
	Name       string `json:"name,omitempty"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
}

// FindConfigForDeviceOptions contains options for finding a config for a device
type FindConfigForDeviceOptions struct {
	TenantID   string `json:"tenant_id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
}

// FindConfigForDeviceResult contains the result of finding a config for a device
type FindConfigForDeviceResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}

// AssignProfileToDeviceOptions contains options for assigning a profile to a device
type AssignProfileToDeviceOptions struct {
	TenantID  string `json:"tenant_id"`
	ProfileID string `json:"profile_id"`
	EKSerial  string `json:"ek_serial,omitempty"`
}

// AssignProfileToDeviceResult contains the result of assigning a profile to a device
type AssignProfileToDeviceResult struct {
	Profile *entities.DeviceProfile `json:"profile"`
}
