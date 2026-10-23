//go:build integration

package device

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// CLIAdapterError represents an error from the CLI adapter
type CLIAdapterError struct {
	Operation string
	Message   string
	Output    string
}

func (e *CLIAdapterError) Error() string {
	return fmt.Sprintf("CLI adapter error [%s]: %s (output: %s)", e.Operation, e.Message, e.Output)
}

// ErrCLINoVerb reports a device operation platformctl has no verb for.
//
// The adapter used to shell verbs and flags that do not exist (device update,
// profile delete, template *, --tenant-id, ...); the suite's skip guard read
// the resulting "unknown flag" as "not implemented" and the CLI lane reported
// those operations passing (#493). The error is returned rather than faked so
// the CLI subtest fails and the gap stays visible. Its wording deliberately
// avoids the phrases skipIfNotImplemented swallows.
type ErrCLINoVerb struct {
	Operation string
	Reason    string
}

func (e ErrCLINoVerb) Error() string {
	return fmt.Sprintf("platformctl has no verb for device operation %s: %s", e.Operation, e.Reason)
}

// CLIAdapter implements DeviceCommands using the platformctl CLI. It drives
// the daemon through a local platformctl context Setup writes, so every
// command reaches the same Unix socket and gRPC endpoint the other adapters
// test.
type CLIAdapter struct {
	cliPath    string
	configDir  string
	configPath string
}

// NewCLIAdapter creates a new CLI adapter
func NewCLIAdapter() *CLIAdapter {
	return &CLIAdapter{
		cliPath: GetCLIPath(),
	}
}

// Setup verifies platformctl is installed and writes the platformctl config
// whose current context targets the integration daemon.
func (a *CLIAdapter) Setup(ctx context.Context) error {
	if _, err := exec.LookPath(a.cliPath); err != nil {
		return &CLIAdapterError{
			Operation: "Setup",
			Message:   "CLI not found",
			Output:    err.Error(),
		}
	}
	dir, err := os.MkdirTemp("", "platformctl-device-test-*")
	if err != nil {
		return err
	}
	path, err := helpers.WriteLocalCLIConfig(dir, GetSocketPath(), GetGRPCEndpoint())
	if err != nil {
		_ = os.RemoveAll(dir)
		return err
	}
	a.configDir, a.configPath = dir, path
	return nil
}

// Teardown removes the platformctl config Setup wrote.
func (a *CLIAdapter) Teardown(ctx context.Context) error {
	if a.configDir == "" {
		return nil
	}
	return os.RemoveAll(a.configDir)
}

// Name returns the adapter name
func (a *CLIAdapter) Name() string {
	return "CLI"
}

// runCommand executes a platformctl command against the integration context
// with JSON output and returns its stdout. Stderr is kept separate so a
// warning can never corrupt the JSON the caller decodes.
func (a *CLIAdapter) runCommand(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string{
		"--config", a.configPath,
		"--context", helpers.CLIContextName,
		"--output", "json",
	}, args...)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, a.cliPath, full...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, &CLIAdapterError{
			Operation: strings.Join(args, " "),
			Message:   err.Error(),
			Output:    stderr.String() + stdout.String(),
		}
	}
	return stdout.Bytes(), nil
}

// runJSON runs a platformctl command and decodes its JSON output into out.
func (a *CLIAdapter) runJSON(ctx context.Context, operation string, out any, args ...string) error {
	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(output, out); err != nil {
		return &CLIAdapterError{
			Operation: operation,
			Message:   "failed to parse response: " + err.Error(),
			Output:    string(output),
		}
	}
	return nil
}

// ============================================================================
// CLI output shapes
// ============================================================================

// deviceJSON is the device object `device get`, `find-serial` and `register`
// print (pkg/cli/commands/device buildGetOutput) and the daemon REST API
// returns (pkg/webservice/v1/device DeviceResponse). entities.Device cannot
// decode it: its own tags are att_pub and hash_algo. The CLI prints the id as
// a JSON number and the REST API as a JSON string, so the id takes the
// webservice's own ID type, which decodes both.
type deviceJSON struct {
	ID         wsdevice.ID `json:"id"`
	Serial     string      `json:"serial"`
	Model      string      `json:"model"`
	HashAlgoID uint32      `json:"hash_algo_id"`
	EKCert     string      `json:"ek_cert"`
	AttestPub  string      `json:"attest_pub"`
	AttestCert string      `json:"attest_cert"`
	SigningPub string      `json:"signing_pub"`
}

func (d deviceJSON) entity() *entities.Device {
	return &entities.Device{
		ID:         d.ID.Uint64(),
		Serial:     d.Serial,
		Model:      d.Model,
		HashAlgoId: d.HashAlgoID,
		EKCert:     d.EKCert,
		AttestPub:  d.AttestPub,
		AttestCert: d.AttestCert,
		SigningPub: d.SigningPub,
	}
}

// cliDeviceList is the page `device list` prints.
type cliDeviceList struct {
	Total   int          `json:"total"`
	Devices []deviceJSON `json:"devices"`
}

// cliProfile is the profile object the `device profile` verbs print
// (buildProfileOutput). The ID is a decimal string so a uint64 survives
// JSON consumers that parse numbers as float64.
type cliProfile struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Model         string `json:"model"`
	Role          string `json:"role"`
	Zone          string `json:"zone"`
	EKSerial      string `json:"ek_serial"`
	MACAddress    string `json:"mac_address"`
	EKCert        string `json:"ek_cert"`
	TLSServerName string `json:"tls_server_name"`
	Assigned      bool   `json:"assigned"`

	// MatchRules is the match_rules object; its keys are the entity's own
	// JSON tags (mac_prefix, serial_prefix, model, ...).
	MatchRules *entities.ProfileMatchRules `json:"match_rules"`
}

func (p cliProfile) entity(operation string) (*entities.DeviceProfile, error) {
	id, err := strconv.ParseUint(p.ID, 10, 64)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: operation,
			Message:   "profile id is not a decimal uint64: " + err.Error(),
			Output:    p.ID,
		}
	}
	return &entities.DeviceProfile{
		ID:            id,
		Name:          p.Name,
		Model:         p.Model,
		Role:          entities.DeviceRole(p.Role),
		Zone:          p.Zone,
		EKSerial:      p.EKSerial,
		MACAddress:    p.MACAddress,
		EKCert:        p.EKCert,
		TLSServerName: p.TLSServerName,
		Assigned:      p.Assigned,
		MatchRules:    p.MatchRules,
	}, nil
}

// cliProfileList is the page `device profile list` prints.
type cliProfileList struct {
	Total    int          `json:"total"`
	Profiles []cliProfile `json:"profiles"`
}

// cliAttestCertRecord is the result `device attest-cert record` prints.
type cliAttestCertRecord struct {
	ID                uint64 `json:"id"`
	Serial            string `json:"serial"`
	Model             string `json:"model"`
	Changed           bool   `json:"changed"`
	Source            string `json:"source"`
	SourceDetail      string `json:"source_detail"`
	Reissued          bool   `json:"reissued"`
	Subject           string `json:"subject"`
	CertificateSerial string `json:"certificate_serial"`
	AttestCert        string `json:"attest_cert"`
}

// cliDeleted is the result `device profile delete` and `device template
// delete` print.
type cliDeleted struct {
	ID      string `json:"id"`
	Deleted bool   `json:"deleted"`
}

// cliTemplate is the template object the `device template` verbs print
// (buildTemplateOutput). The CLI renders the config only as its length
// (config_bytes), so the entity's Config stays empty.
type cliTemplate struct {
	ID          string                      `json:"id"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
	Role        string                      `json:"role"`
	MatchRules  *entities.ProfileMatchRules `json:"match_rules"`
}

func (t cliTemplate) entity(operation string) (*entities.DeviceTemplate, error) {
	id, err := strconv.ParseUint(t.ID, 10, 64)
	if err != nil {
		return nil, &CLIAdapterError{
			Operation: operation,
			Message:   "template id is not a decimal uint64: " + err.Error(),
			Output:    t.ID,
		}
	}
	return &entities.DeviceTemplate{
		ID:          id,
		Name:        t.Name,
		Description: t.Description,
		Role:        entities.DeviceRole(t.Role),
		MatchRules:  t.MatchRules,
	}, nil
}

// cliTemplateList is the page `device template list` prints.
type cliTemplateList struct {
	Total     int           `json:"total"`
	Templates []cliTemplate `json:"templates"`
}

// pageArgs maps the suite's limit/offset window onto the CLI's 1-based
// --page/--page-size flags. A zero limit keeps the CLI defaults.
func pageArgs(limit, offset int) []string {
	if limit <= 0 {
		return nil
	}
	page := offset/limit + 1
	return []string{"--page", strconv.Itoa(page), "--page-size", strconv.Itoa(limit)}
}

// appendFlag appends --name value when value is set.
func appendFlag(args []string, name, value string) []string {
	if value == "" {
		return args
	}
	return append(args, name, value)
}

// ============================================================================
// Device CRUD Operations
// ============================================================================

// RegisterDevice creates a device record via `platformctl device register`.
func (a *CLIAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	args := []string{"device", "register", "--serial", opts.Serial}
	args = appendFlag(args, "--model", opts.Model)
	args = appendFlag(args, "--ek-cert", opts.EKCert)
	args = appendFlag(args, "--attest-pub", opts.AttestPub)
	args = appendFlag(args, "--attest-cert", opts.AttestCert)
	args = appendFlag(args, "--signing-pub", opts.SigningPub)
	if opts.HashAlgoId > 0 {
		args = append(args, "--hash-algo", strconv.FormatUint(uint64(opts.HashAlgoId), 10))
	}

	var device deviceJSON
	if err := a.runJSON(ctx, "RegisterDevice", &device, args...); err != nil {
		return nil, err
	}
	return &RegisterDeviceResult{Device: device.entity()}, nil
}

// GetDevice retrieves a device via `platformctl device get <id>`.
func (a *CLIAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	var device deviceJSON
	if err := a.runJSON(ctx, "GetDevice", &device, "device", "get", opts.DeviceID); err != nil {
		return nil, err
	}
	return &GetDeviceResult{Device: device.entity()}, nil
}

// UpdateDevice changes a device via `platformctl device update <id>`, which
// sets only the flagged fields (docs/device/cli.md §2.7a). A zero HashAlgoId
// means "unchanged" here, so --hash-algo is passed only when it is set.
func (a *CLIAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	args := []string{"device", "update", opts.DeviceID}
	args = appendFlag(args, "--model", opts.Model)
	args = appendFlag(args, "--ek-cert", opts.EKCert)
	args = appendFlag(args, "--attest-pub", opts.AttestPub)
	args = appendFlag(args, "--attest-cert", opts.AttestCert)
	args = appendFlag(args, "--signing-pub", opts.SigningPub)
	if opts.HashAlgoId > 0 {
		args = append(args, "--hash-algo", strconv.FormatUint(uint64(opts.HashAlgoId), 10))
	}

	var device deviceJSON
	if err := a.runJSON(ctx, "UpdateDevice", &device, args...); err != nil {
		return nil, err
	}
	return &UpdateDeviceResult{Device: device.entity()}, nil
}

// DeleteDevice removes a device via `platformctl device delete <id>`.
func (a *CLIAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	var result struct {
		Success bool `json:"success"`
	}
	if err := a.runJSON(ctx, "DeleteDevice", &result, "device", "delete", opts.DeviceID); err != nil {
		return nil, err
	}
	return &DeleteDeviceResult{Success: result.Success}, nil
}

// ListDevices lists devices via `platformctl device list`. The CLI, like the
// server, filters by nothing but the page window, so a ProfileID or Status
// filter cannot be honoured and is refused.
func (a *CLIAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	if opts.ProfileID != "" || opts.Status != "" {
		return nil, ErrCLINoVerb{Operation: "ListDevices", Reason: "`device list` has no profile or status filter"}
	}
	args := append([]string{"device", "list"}, pageArgs(opts.Limit, opts.Offset)...)

	var page cliDeviceList
	if err := a.runJSON(ctx, "ListDevices", &page, args...); err != nil {
		return nil, err
	}
	devices := make([]*entities.Device, 0, len(page.Devices))
	for _, d := range page.Devices {
		devices = append(devices, d.entity())
	}
	return &ListDevicesResult{Devices: devices, Total: page.Total}, nil
}

// ============================================================================
// Device Lookups
// ============================================================================

// FindBySerial finds a device via `platformctl device find-serial <serial>`.
func (a *CLIAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	var device deviceJSON
	if err := a.runJSON(ctx, "FindBySerial", &device, "device", "find-serial", opts.Serial); err != nil {
		return nil, err
	}
	return &FindBySerialResult{Device: device.entity()}, nil
}

// ============================================================================
// Profile CRUD Operations
// ============================================================================

// matchRuleArgs maps the suite's match rules onto the --match-mac-prefix,
// --match-serial-prefix and --match-model flags (docs/device/cli.md §3.1).
// A rule set in MatchRules wins over the bare prefix option, as on the RPC
// adapters. Those three are the only rules the CLI sets, so any other rule
// is refused rather than silently dropped.
func matchRuleArgs(operation, macPrefix, serialPrefix string, rules *entities.ProfileMatchRules) ([]string, error) {
	model := ""
	if rules != nil {
		if rules.ModelPattern != "" || rules.SerialPattern != "" || rules.ManufacturerMatch != "" ||
			rules.TPMVendor != "" || len(rules.CustomAttributes) > 0 {
			return nil, ErrCLINoVerb{Operation: operation, Reason: "the match-rule flags set only a MAC prefix, a serial prefix and a model"}
		}
		if rules.MACPrefix != "" {
			macPrefix = rules.MACPrefix
		}
		if rules.SerialPrefix != "" {
			serialPrefix = rules.SerialPrefix
		}
		model = rules.Model
	}
	var args []string
	args = appendFlag(args, "--match-mac-prefix", macPrefix)
	args = appendFlag(args, "--match-serial-prefix", serialPrefix)
	args = appendFlag(args, "--match-model", model)
	return args, nil
}

// CreateProfile creates a profile via `platformctl device profile create`.
func (a *CLIAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	matchArgs, err := matchRuleArgs("CreateProfile", opts.MACPrefix, opts.SerialPrefix, opts.MatchRules)
	if err != nil {
		return nil, err
	}
	args := []string{"device", "profile", "create"}
	args = appendFlag(args, "--name", opts.Name)
	args = appendFlag(args, "--model", opts.Model)
	args = appendFlag(args, "--role", string(opts.Role))
	args = append(args, matchArgs...)

	profile, err := a.runProfile(ctx, "CreateProfile", args...)
	if err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: profile}, nil
}

// GetProfile retrieves a profile via `platformctl device profile get <id>`.
func (a *CLIAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	profile, err := a.runProfile(ctx, "GetProfile", "device", "profile", "get", opts.ProfileID)
	if err != nil {
		return nil, err
	}
	return &GetProfileResult{Profile: profile}, nil
}

// UpdateProfile updates a profile via `platformctl device profile update <id>`.
func (a *CLIAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	matchArgs, err := matchRuleArgs("UpdateProfile", opts.MACPrefix, opts.SerialPrefix, opts.MatchRules)
	if err != nil {
		return nil, err
	}
	args := []string{"device", "profile", "update", opts.ProfileID}
	args = appendFlag(args, "--name", opts.Name)
	args = appendFlag(args, "--model", opts.Model)
	args = appendFlag(args, "--role", string(opts.Role))
	args = append(args, matchArgs...)

	profile, err := a.runProfile(ctx, "UpdateProfile", args...)
	if err != nil {
		return nil, err
	}
	return &UpdateProfileResult{Profile: profile}, nil
}

// DeleteProfile removes a profile via `platformctl device profile delete <id>`.
func (a *CLIAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	var result cliDeleted
	if err := a.runJSON(ctx, "DeleteProfile", &result, "device", "profile", "delete", opts.ProfileID); err != nil {
		return nil, err
	}
	return &DeleteProfileResult{Success: result.Deleted}, nil
}

// ListProfiles lists profiles via `platformctl device profile list`. There
// is no role filter on the CLI or the server, so one is refused.
func (a *CLIAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	if opts.Role != "" {
		return nil, ErrCLINoVerb{Operation: "ListProfiles", Reason: "`device profile list` has no role filter"}
	}
	args := append([]string{"device", "profile", "list"}, pageArgs(opts.Limit, opts.Offset)...)

	var page cliProfileList
	if err := a.runJSON(ctx, "ListProfiles", &page, args...); err != nil {
		return nil, err
	}
	profiles := make([]*entities.DeviceProfile, 0, len(page.Profiles))
	for _, p := range page.Profiles {
		profile, err := p.entity("ListProfiles")
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile)
	}
	return &ListProfilesResult{Profiles: profiles, Total: page.Total}, nil
}

// runProfile runs a `device profile` verb that prints one profile.
func (a *CLIAdapter) runProfile(ctx context.Context, operation string, args ...string) (*entities.DeviceProfile, error) {
	var profile cliProfile
	if err := a.runJSON(ctx, operation, &profile, args...); err != nil {
		return nil, err
	}
	return profile.entity(operation)
}

// ============================================================================
// Profile Lookups
// ============================================================================

// FindProfileByMACAddress finds a profile whose MAC prefix rule fits the
// address via `platformctl device profile match --mac`. The CLI has no
// separate by-MAC verb; `match` covers it (docs/device/cli.md §3.0a, §6).
func (a *CLIAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	profile, err := a.matchProfile(ctx, "FindProfileByMACAddress", FindMatchingProfileOptions{MACAddress: opts.MACAddress})
	if err != nil {
		return nil, err
	}
	return &FindProfileByMACAddressResult{Profile: profile}, nil
}

// FindProfileBySerial finds a profile whose serial prefix rule fits the
// serial via `platformctl device profile match --serial`.
func (a *CLIAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	profile, err := a.matchProfile(ctx, "FindProfileBySerial", FindMatchingProfileOptions{Serial: opts.Serial})
	if err != nil {
		return nil, err
	}
	return &FindProfileBySerialResult{Profile: profile}, nil
}

// FindMatchingProfile finds a profile via `platformctl device profile match`.
func (a *CLIAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	profile, err := a.matchProfile(ctx, "FindMatchingProfile", opts)
	if err != nil {
		return nil, err
	}
	return &FindMatchingProfileResult{Profile: profile}, nil
}

// matchProfile runs `device profile match` with the attributes opts sets.
func (a *CLIAdapter) matchProfile(ctx context.Context, operation string, opts FindMatchingProfileOptions) (*entities.DeviceProfile, error) {
	args := []string{"device", "profile", "match"}
	args = appendFlag(args, "--mac", opts.MACAddress)
	args = appendFlag(args, "--serial", opts.Serial)
	args = appendFlag(args, "--model", opts.Model)
	return a.runProfile(ctx, operation, args...)
}

// ============================================================================
// Attestation
// ============================================================================

// RecordAttestCert records the device's attestation certificate via
// platformctl device attest-cert record.
func (a *CLIAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	args := []string{"device", "attest-cert", "record", opts.DeviceID}
	if opts.Reissue {
		args = append(args, "--reissue")
	}
	if opts.ClearOnRefusal {
		args = append(args, "--clear-on-refusal")
	}

	var record cliAttestCertRecord
	if err := a.runJSON(ctx, "RecordAttestCert", &record, args...); err != nil {
		return nil, err
	}
	return &RecordAttestCertResult{
		DeviceID:          strconv.FormatUint(record.ID, 10),
		Serial:            record.Serial,
		Model:             record.Model,
		Changed:           record.Changed,
		Source:            record.Source,
		SourceDetail:      record.SourceDetail,
		Reissued:          record.Reissued,
		Subject:           record.Subject,
		CertificateSerial: record.CertificateSerial,
		AttestCert:        record.AttestCert,
	}, nil
}

// AttestDevice reports that platformctl has no device attestation command.
//
// This adapter used to shell `platformctl device attest`, a command that
// does not exist (pkg/cli/commands/device registers list, get, find-serial,
// register, delete and profile; docs/device/cli.md documents no attest
// verb). The resulting "unknown command" error was swallowed by the suite's
// skip guard, so the CLI lane reported attestation passing (#403).
//
// The error is returned rather than faked so the gap stays visible.
func (a *CLIAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	file, err := os.CreateTemp(a.configDir, "attest-evidence-*.json")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	defer func() { _ = os.Remove(path) }()
	_, writeErr := file.Write(opts.Evidence)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return nil, errors.Join(writeErr, closeErr)
	}

	var record cliAttestRecord
	if err := a.runJSON(ctx, "AttestDevice", &record, "device", "attest", opts.DeviceID, "--evidence-file", path); err != nil {
		return nil, err
	}
	return &AttestDeviceResult{
		DeviceID:              strconv.FormatUint(record.DeviceID, 10),
		Serial:                record.Serial,
		Verified:              record.Verified,
		SignatureValid:        record.SignatureValid,
		NonceValid:            record.NonceValid,
		PCRsValid:             record.PCRsValid,
		AKCertificateVerified: record.AKCertificateVerified,
		AttestationStatus:     record.AttestationStatus,
		Message:               record.Message,
	}, nil
}

// cliAttestRecord is the JSON `device attest` prints (docs/device/cli.md).
type cliAttestRecord struct {
	DeviceID              uint64 `json:"device_id"`
	Serial                string `json:"serial"`
	Verified              bool   `json:"verified"`
	SignatureValid        bool   `json:"signature_valid"`
	NonceValid            bool   `json:"nonce_valid"`
	PCRsValid             bool   `json:"pcrs_valid"`
	AKCertificateVerified bool   `json:"ak_certificate_verified"`
	AttestationStatus     string `json:"attestation_status"`
	Message               string `json:"message"`
}

// ============================================================================
// Template Operations
// ============================================================================

// templateArgs builds the flags `device template create` and `update` share
// (docs/device/cli.md §2.8). A config is written to a file in the adapter's
// config directory for --config-file; the returned cleanup removes it.
func (a *CLIAdapter) templateArgs(operation, name, description string, role entities.DeviceRole, config []byte, rules *entities.ProfileMatchRules) ([]string, func(), error) {
	matchArgs, err := matchRuleArgs(operation, "", "", rules)
	if err != nil {
		return nil, nil, err
	}
	var args []string
	args = appendFlag(args, "--name", name)
	args = appendFlag(args, "--description", description)
	args = appendFlag(args, "--role", string(role))
	args = append(args, matchArgs...)

	cleanup := func() {}
	if len(config) > 0 {
		file, err := os.CreateTemp(a.configDir, "template-config-*.json")
		if err != nil {
			return nil, nil, err
		}
		path := file.Name()
		cleanup = func() { _ = os.Remove(path) }
		_, writeErr := file.Write(config)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			cleanup()
			return nil, nil, errors.Join(writeErr, closeErr)
		}
		args = append(args, "--config-file", path)
	}
	return args, cleanup, nil
}

// runTemplate runs a `device template` verb that prints one template.
func (a *CLIAdapter) runTemplate(ctx context.Context, operation string, args ...string) (*entities.DeviceTemplate, error) {
	var template cliTemplate
	if err := a.runJSON(ctx, operation, &template, args...); err != nil {
		return nil, err
	}
	return template.entity(operation)
}

// CreateTemplate creates a template via `platformctl device template create`.
func (a *CLIAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	flags, cleanup, err := a.templateArgs("CreateTemplate", opts.Name, opts.Description, opts.Role, opts.Config, opts.MatchRules)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	template, err := a.runTemplate(ctx, "CreateTemplate", append([]string{"device", "template", "create"}, flags...)...)
	if err != nil {
		return nil, err
	}
	return &CreateTemplateResult{Template: template}, nil
}

// GetTemplate retrieves a template via `platformctl device template get <id>`.
func (a *CLIAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	template, err := a.runTemplate(ctx, "GetTemplate", "device", "template", "get", opts.TemplateID)
	if err != nil {
		return nil, err
	}
	return &GetTemplateResult{Template: template}, nil
}

// UpdateTemplate changes a template via `platformctl device template update
// <id>`, which sets only the flagged fields and keeps the rest.
func (a *CLIAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	flags, cleanup, err := a.templateArgs("UpdateTemplate", opts.Name, opts.Description, opts.Role, opts.Config, opts.MatchRules)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	template, err := a.runTemplate(ctx, "UpdateTemplate", append([]string{"device", "template", "update", opts.TemplateID}, flags...)...)
	if err != nil {
		return nil, err
	}
	return &UpdateTemplateResult{Template: template}, nil
}

// DeleteTemplate removes a template via `platformctl device template delete <id>`.
func (a *CLIAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	var result cliDeleted
	if err := a.runJSON(ctx, "DeleteTemplate", &result, "device", "template", "delete", opts.TemplateID); err != nil {
		return nil, err
	}
	return &DeleteTemplateResult{Success: result.Deleted}, nil
}

// ListTemplates lists templates via `platformctl device template list`. The
// CLI filters by nothing but the page window, so a role filter is refused.
func (a *CLIAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	if opts.Role != "" {
		return nil, ErrCLINoVerb{Operation: "ListTemplates", Reason: "`device template list` has no role filter"}
	}
	args := append([]string{"device", "template", "list"}, pageArgs(opts.Limit, opts.Offset)...)

	var page cliTemplateList
	if err := a.runJSON(ctx, "ListTemplates", &page, args...); err != nil {
		return nil, err
	}
	templates := make([]*entities.DeviceTemplate, 0, len(page.Templates))
	for _, t := range page.Templates {
		template, err := t.entity("ListTemplates")
		if err != nil {
			return nil, err
		}
		templates = append(templates, template)
	}
	return &ListTemplatesResult{Templates: templates, Total: page.Total}, nil
}

// CreateProfileFromTemplate builds a profile via `platformctl device template
// create-profile <template-id>`; the name, EK serial and MAC bind it.
func (a *CLIAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	args := []string{"device", "template", "create-profile", opts.TemplateID}
	args = appendFlag(args, "--name", opts.Name)
	args = appendFlag(args, "--ek-serial", opts.EKSerial)
	args = appendFlag(args, "--mac", opts.MACAddress)

	profile, err := a.runProfile(ctx, "CreateProfileFromTemplate", args...)
	if err != nil {
		return nil, err
	}
	return &CreateProfileResult{Profile: profile}, nil
}

// FindConfigForDevice reports that platformctl has no find-config verb.
func (a *CLIAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	args := []string{"device", "profile", "find-config"}
	args = appendFlag(args, "--ek-serial", opts.EKSerial)
	args = appendFlag(args, "--mac", opts.MACAddress)
	profile, err := a.runProfile(ctx, "FindConfigForDevice", args...)
	if err != nil {
		return nil, err
	}
	return &FindConfigForDeviceResult{Profile: profile}, nil
}

// AssignProfileToDevice binds a profile to a device identity via
// `platformctl device profile assign <profile-id> --ek-serial <serial>`.
func (a *CLIAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	args := []string{"device", "profile", "assign", opts.ProfileID}
	args = appendFlag(args, "--ek-serial", opts.EKSerial)

	profile, err := a.runProfile(ctx, "AssignProfileToDevice", args...)
	if err != nil {
		return nil, err
	}
	return &AssignProfileToDeviceResult{Profile: profile}, nil
}

// cliLifecycleOutput is the JSON platformctl device disable/enable prints.
type cliLifecycleOutput struct {
	ID                     uint64 `json:"id"`
	State                  string `json:"state"`
	PreviousState          string `json:"previous_state"`
	StateReason            string `json:"state_reason"`
	ReattestationRequested bool   `json:"reattestation_requested"`
}

// DisableDevice runs platformctl device disable.
func (a *CLIAdapter) DisableDevice(ctx context.Context, opts DisableDeviceOptions) (*DeviceLifecycleResult, error) {
	args := []string{"device", "disable", opts.DeviceID, "--output", "json"}
	if opts.Reason != "" {
		args = append(args, "--reason", opts.Reason)
	}
	return a.deviceLifecycle(ctx, "DisableDevice", args)
}

// EnableDevice runs platformctl device enable.
func (a *CLIAdapter) EnableDevice(ctx context.Context, opts EnableDeviceOptions) (*DeviceLifecycleResult, error) {
	return a.deviceLifecycle(ctx, "EnableDevice", []string{"device", "enable", opts.DeviceID, "--output", "json"})
}

func (a *CLIAdapter) deviceLifecycle(ctx context.Context, op string, args []string) (*DeviceLifecycleResult, error) {
	output, err := a.runCommand(ctx, args...)
	if err != nil {
		return nil, err
	}

	var out cliLifecycleOutput
	if err := json.Unmarshal(output, &out); err != nil {
		return nil, &CLIAdapterError{
			Operation: op,
			Message:   "failed to parse response",
			Output:    string(output),
		}
	}
	return &DeviceLifecycleResult{
		DeviceID:               strconv.FormatUint(out.ID, 10),
		State:                  out.State,
		PreviousState:          out.PreviousState,
		StateReason:            out.StateReason,
		ReattestationRequested: out.ReattestationRequested,
	}, nil
}

// Verify CLIAdapter implements DeviceCommands
var _ DeviceCommands = (*CLIAdapter)(nil)
