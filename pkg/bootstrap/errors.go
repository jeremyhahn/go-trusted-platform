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

package bootstrap

import "fmt"

// ErrConfigFileNotFound is returned when the config file does not exist.
type ErrConfigFileNotFound struct {
	Path string
}

func (e ErrConfigFileNotFound) Error() string {
	return fmt.Sprintf("config file not found: %s", e.Path)
}

// ErrInvalidYAMLPath is returned when the YAML path format is invalid.
type ErrInvalidYAMLPath struct {
	Path   string
	Reason string
}

func (e ErrInvalidYAMLPath) Error() string {
	return fmt.Sprintf("invalid YAML path %q: %s", e.Path, e.Reason)
}

// ErrPathNotFound is returned when the specified path does not exist in the YAML document.
type ErrPathNotFound struct {
	Path string
}

func (e ErrPathNotFound) Error() string {
	return fmt.Sprintf("path not found in config: %s", e.Path)
}

// ErrBackupFailed is returned when creating a backup of the config file fails.
type ErrBackupFailed struct {
	Path string
	Err  error
}

func (e ErrBackupFailed) Error() string {
	return fmt.Sprintf("failed to create backup of %s: %v", e.Path, e.Err)
}

func (e ErrBackupFailed) Unwrap() error {
	return e.Err
}

// ErrRestoreFailed is returned when restoring from a backup fails.
type ErrRestoreFailed struct {
	BackupPath string
	TargetPath string
	Err        error
}

func (e ErrRestoreFailed) Error() string {
	return fmt.Sprintf("failed to restore %s from backup %s: %v", e.TargetPath, e.BackupPath, e.Err)
}

func (e ErrRestoreFailed) Unwrap() error {
	return e.Err
}

// ErrWriteFailed is returned when writing the config file fails.
type ErrWriteFailed struct {
	Path string
	Err  error
}

func (e ErrWriteFailed) Error() string {
	return fmt.Sprintf("failed to write config file %s: %v", e.Path, e.Err)
}

func (e ErrWriteFailed) Unwrap() error {
	return e.Err
}

// ErrParseYAML is returned when parsing the YAML config file fails.
type ErrParseYAML struct {
	Path string
	Err  error
}

func (e ErrParseYAML) Error() string {
	return fmt.Sprintf("failed to parse YAML config %s: %v", e.Path, e.Err)
}

func (e ErrParseYAML) Unwrap() error {
	return e.Err
}

// ErrIndexOutOfBounds is returned when an array index in the path is out of bounds.
type ErrIndexOutOfBounds struct {
	Path  string
	Index int
	Size  int
}

func (e ErrIndexOutOfBounds) Error() string {
	return fmt.Sprintf("array index %d out of bounds (size %d) at path: %s", e.Index, e.Size, e.Path)
}

// ErrUnexpectedNodeType is returned when a YAML node has an unexpected type.
type ErrUnexpectedNodeType struct {
	Path     string
	Expected string
	Got      string
}

func (e ErrUnexpectedNodeType) Error() string {
	return fmt.Sprintf("unexpected node type at %s: expected %s, got %s", e.Path, e.Expected, e.Got)
}

// ErrAtomicWriteFailed is returned when atomic file write operation fails.
type ErrAtomicWriteFailed struct {
	TempPath   string
	TargetPath string
	Err        error
}

func (e ErrAtomicWriteFailed) Error() string {
	return fmt.Sprintf("atomic write failed (temp: %s, target: %s): %v", e.TempPath, e.TargetPath, e.Err)
}

func (e ErrAtomicWriteFailed) Unwrap() error {
	return e.Err
}

// ErrBackupNotFound is returned when trying to restore from a non-existent backup.
type ErrBackupNotFound struct {
	Path string
}

func (e ErrBackupNotFound) Error() string {
	return fmt.Sprintf("backup file not found: %s", e.Path)
}

// ErrNilLogger is returned when a nil logger is provided.
type ErrNilLogger struct{}

func (e ErrNilLogger) Error() string {
	return "logger cannot be nil"
}

// ErrEmptyPath is returned when an empty config file path is provided.
type ErrEmptyPath struct{}

func (e ErrEmptyPath) Error() string {
	return "config file path cannot be empty"
}

// ErrEmptyUpdates is returned when no updates are provided.
type ErrEmptyUpdates struct{}

func (e ErrEmptyUpdates) Error() string {
	return "no secret updates provided"
}

// ErrDryRunMode indicates the operation completed successfully in dry-run mode.
type ErrDryRunMode struct {
	UpdateCount int
}

func (e ErrDryRunMode) Error() string {
	return fmt.Sprintf("dry-run mode: %d updates would be applied", e.UpdateCount)
}

// Secret Manager Errors

// ErrNilRegistry is returned when a nil ResolverRegistry is provided.
type ErrNilRegistry struct{}

func (e ErrNilRegistry) Error() string {
	return "resolver registry cannot be nil"
}

// ErrNilKMSClient is returned when a nil SecretsClient is provided.
type ErrNilKMSClient struct{}

func (e ErrNilKMSClient) Error() string {
	return "KMS client cannot be nil"
}

// ErrNilConfig is returned when a nil configuration is provided to ProcessConfig.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "configuration cannot be nil"
}

// ErrInvalidConfigType is returned when the configuration is not a struct or pointer to struct.
type ErrInvalidConfigType struct {
	Kind string
}

func (e ErrInvalidConfigType) Error() string {
	return fmt.Sprintf("configuration must be a struct or pointer to struct, got %s", e.Kind)
}

// ErrNoResolverForURI is returned when no resolver can handle the given URI.
type ErrNoResolverForURI struct {
	URI string
}

func (e ErrNoResolverForURI) Error() string {
	return fmt.Sprintf("no resolver registered for URI: %s", e.URI)
}

// ErrSecretResolution is returned when a secret cannot be resolved.
type ErrSecretResolution struct {
	URI   string
	Cause error
}

func (e ErrSecretResolution) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to resolve secret %s: %v", e.URI, e.Cause)
	}
	return fmt.Sprintf("failed to resolve secret %s", e.URI)
}

func (e ErrSecretResolution) Unwrap() error {
	return e.Cause
}

// ErrSecretMigration is returned when a secret cannot be migrated to local KMS.
type ErrSecretMigration struct {
	Path  string
	Cause error
}

func (e ErrSecretMigration) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to migrate secret at %s to local KMS: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to migrate secret at %s to local KMS", e.Path)
}

func (e ErrSecretMigration) Unwrap() error {
	return e.Cause
}

// ErrFieldProcessing is returned when a config field cannot be processed.
type ErrFieldProcessing struct {
	Path  string
	Cause error
}

func (e ErrFieldProcessing) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to process field %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to process field %s", e.Path)
}

func (e ErrFieldProcessing) Unwrap() error {
	return e.Cause
}

// ErrMapValueImmutable is returned when a map value contains a secret that cannot be modified.
type ErrMapValueImmutable struct {
	Path string
}

func (e ErrMapValueImmutable) Error() string {
	return fmt.Sprintf("secret in map value at %s cannot be modified through reflection; manual migration required", e.Path)
}

// ErrResolverSchemeConflict is returned when registering a resolver with an already registered scheme.
type ErrResolverSchemeConflict struct {
	Scheme string
}

func (e ErrResolverSchemeConflict) Error() string {
	return fmt.Sprintf("resolver already registered for scheme: %s", e.Scheme)
}

// ErrSecretNotFound is returned when a secret is not found at the specified path.
type ErrSecretNotFound struct {
	Path string
}

func (e ErrSecretNotFound) Error() string {
	return fmt.Sprintf("secret not found at path: %s", e.Path)
}

// ErrSecretStoreFailed is returned when storing a secret fails.
type ErrSecretStoreFailed struct {
	Path  string
	Cause error
}

func (e ErrSecretStoreFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to store secret at %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to store secret at %s", e.Path)
}

func (e ErrSecretStoreFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidURI is returned when a URI is malformed or invalid.
type ErrInvalidURI struct {
	URI    string
	Reason string
}

func (e ErrInvalidURI) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid URI %s: %s", e.URI, e.Reason)
	}
	return fmt.Sprintf("invalid URI: %s", e.URI)
}

// ErrAutoGenFailed is returned when auto-generation of a secret fails.
type ErrAutoGenFailed struct {
	Path  string
	Spec  string
	Cause error
}

func (e ErrAutoGenFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to auto-generate secret for %s with spec %s: %v", e.Path, e.Spec, e.Cause)
	}
	return fmt.Sprintf("failed to auto-generate secret for %s with spec %s", e.Path, e.Spec)
}

func (e ErrAutoGenFailed) Unwrap() error {
	return e.Cause
}

// ErrEnvVarNotFound is returned when an environment variable is not found.
type ErrEnvVarNotFound struct {
	Name string
}

func (e ErrEnvVarNotFound) Error() string {
	return fmt.Sprintf("environment variable not found: %s", e.Name)
}

// ErrRemoteKMSUnavailable is returned when a remote KMS is not accessible.
type ErrRemoteKMSUnavailable struct {
	Endpoint string
	Cause    error
}

func (e ErrRemoteKMSUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("remote KMS at %s is unavailable: %v", e.Endpoint, e.Cause)
	}
	return fmt.Sprintf("remote KMS at %s is unavailable", e.Endpoint)
}

func (e ErrRemoteKMSUnavailable) Unwrap() error {
	return e.Cause
}

// ErrDecryptionFailed is returned when encrypted secret decryption fails.
type ErrDecryptionFailed struct {
	Path  string
	Cause error
}

func (e ErrDecryptionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to decrypt secret at %s: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("failed to decrypt secret at %s", e.Path)
}

func (e ErrDecryptionFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidPINLength is returned when an invalid PIN length is requested.
type ErrInvalidPINLength struct {
	Length int
}

func (e ErrInvalidPINLength) Error() string {
	return fmt.Sprintf("bootstrap: invalid PIN length: %d (must be > 0)", e.Length)
}

// ErrPINGeneration is returned when cryptographic random number generation fails
// during PIN creation.
type ErrPINGeneration struct {
	Cause error
}

func (e ErrPINGeneration) Error() string {
	return fmt.Sprintf("bootstrap: failed to generate PIN: %v", e.Cause)
}

func (e ErrPINGeneration) Unwrap() error {
	return e.Cause
}

// Bootstrap trust errors

// ErrDANEPublishFailed is returned when TLSA record publication fails for a zone.
type ErrDANEPublishFailed struct {
	Zone  string
	Cause error
}

func (e ErrDANEPublishFailed) Error() string {
	return fmt.Sprintf("bootstrap: TLSA record publication failed for zone %s: %v", e.Zone, e.Cause)
}

func (e ErrDANEPublishFailed) Unwrap() error {
	return e.Cause
}

// ErrTLSAComputeFailed is returned when TLSA data computation fails for a common name.
type ErrTLSAComputeFailed struct {
	CN    string
	Cause error
}

func (e ErrTLSAComputeFailed) Error() string {
	return fmt.Sprintf("bootstrap: TLSA data computation failed for CN %s: %v", e.CN, e.Cause)
}

func (e ErrTLSAComputeFailed) Unwrap() error {
	return e.Cause
}

// ErrCertReloadFailed is returned when certificate hot-reload fails.
type ErrCertReloadFailed struct {
	Cause error
}

func (e ErrCertReloadFailed) Error() string {
	return fmt.Sprintf("bootstrap: certificate hot-reload failed: %v", e.Cause)
}

func (e ErrCertReloadFailed) Unwrap() error {
	return e.Cause
}

// ErrNoiseServerFailed is returned when the Noise bootstrap server encounters an error.
type ErrNoiseServerFailed struct {
	Cause error
}

func (e ErrNoiseServerFailed) Error() string {
	return fmt.Sprintf("bootstrap: noise server error: %v", e.Cause)
}

func (e ErrNoiseServerFailed) Unwrap() error {
	return e.Cause
}

// ErrBootstrapFetchFailed is returned when client-side bootstrap fetch fails for a strategy.
type ErrBootstrapFetchFailed struct {
	Strategy string
	Cause    error
}

func (e ErrBootstrapFetchFailed) Error() string {
	return fmt.Sprintf("bootstrap: fetch failed for strategy %s: %v", e.Strategy, e.Cause)
}

func (e ErrBootstrapFetchFailed) Unwrap() error {
	return e.Cause
}

// ErrInvalidConfig is returned when the bootstrap configuration is invalid.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("bootstrap: invalid config: field %s: %s", e.Field, e.Reason)
}

// ErrRolloverInProgress is returned when a certificate rollover is already in progress.
type ErrRolloverInProgress struct {
	Hostname string
}

func (e ErrRolloverInProgress) Error() string {
	return fmt.Sprintf("bootstrap: rollover already in progress for %s", e.Hostname)
}

// ErrCABundleEmpty is returned when the CA bundle is empty.
type ErrCABundleEmpty struct{}

func (e ErrCABundleEmpty) Error() string {
	return "bootstrap: CA bundle is empty"
}

// ErrStrategyNotSupported is returned when an unsupported bootstrap strategy is requested.
type ErrStrategyNotSupported struct {
	Strategy string
}

func (e ErrStrategyNotSupported) Error() string {
	return fmt.Sprintf("bootstrap: unsupported strategy: %s", e.Strategy)
}

// ErrInvalidBootMethod is returned when a node config specifies an unrecognised
// boot_method value. Valid values are "pxe" (default) and "virtual-media".
type ErrInvalidBootMethod struct {
	Hostname string
	Value    string
}

func (e ErrInvalidBootMethod) Error() string {
	return fmt.Sprintf("bootstrap: node %s: invalid boot_method %q (expected pxe or virtual-media)",
		e.Hostname, e.Value)
}

// ErrVirtualMediaRequiresBMC is returned when a node uses boot_method:
// virtual-media but has no bmc_address -- virtual media boot can't run without
// a BMC to mount media on.
type ErrVirtualMediaRequiresBMC struct {
	Hostname string
}

func (e ErrVirtualMediaRequiresBMC) Error() string {
	return fmt.Sprintf("bootstrap: node %s: boot_method=virtual-media requires bmc_address",
		e.Hostname)
}

// ErrVirtualMediaBootFailed wraps any failure during the virtual-media boot
// flow (ISO staging, BMC mount, boot device set, power reset, health wait).
// The Cause preserves the underlying typed error for errors.As inspection.
type ErrVirtualMediaBootFailed struct {
	Hostname string
	Cause    error
}

func (e ErrVirtualMediaBootFailed) Error() string {
	return fmt.Sprintf("bootstrap: node %s: virtual-media boot failed: %v", e.Hostname, e.Cause)
}

func (e ErrVirtualMediaBootFailed) Unwrap() error { return e.Cause }

// ErrISOStagingFailed is returned when the orchestrator can't copy the
// platform ISO to the bootstrap container's host data directory. The Cause
// is typically a deployer SSH/SFTP failure.
type ErrISOStagingFailed struct {
	LocalPath  string
	RemoteHost string
	Cause      error
}

func (e ErrISOStagingFailed) Error() string {
	return fmt.Sprintf("bootstrap: failed to stage ISO %s on %s: %v",
		e.LocalPath, e.RemoteHost, e.Cause)
}

func (e ErrISOStagingFailed) Unwrap() error { return e.Cause }

// ErrBootDeviceSetFailed is returned when SetBootDevice fails on a node's
// BMC during virtual-media boot.
type ErrBootDeviceSetFailed struct {
	Hostname string
	Device   string
	Cause    error
}

func (e ErrBootDeviceSetFailed) Error() string {
	return fmt.Sprintf("bootstrap: node %s: failed to set boot device %s: %v",
		e.Hostname, e.Device, e.Cause)
}

func (e ErrBootDeviceSetFailed) Unwrap() error { return e.Cause }

// ErrPowerControlFailed wraps any BMC power control failure (status query,
// power on, power reset) during the virtual-media boot flow.
type ErrPowerControlFailed struct {
	Hostname  string
	Operation string
	Cause     error
}

func (e ErrPowerControlFailed) Error() string {
	return fmt.Sprintf("bootstrap: node %s: BMC power %s failed: %v",
		e.Hostname, e.Operation, e.Cause)
}

func (e ErrPowerControlFailed) Unwrap() error { return e.Cause }

// ErrPowerStateVerificationFailed is returned when a BMC power command
// (PowerOn or PowerReset) reports success but subsequent polling confirms
// the server never transitioned to the expected power state. This is a
// known issue on Supermicro X10 BMCs where IPMI PowerOn sometimes returns
// success while the chassis stays off.
type ErrPowerStateVerificationFailed struct {
	Hostname string
	Expected string
	Actual   string
	Retries  int
}

func (e ErrPowerStateVerificationFailed) Error() string {
	return fmt.Sprintf(
		"bootstrap: node %s: power state verification failed after %d retries: expected %s, got %s",
		e.Hostname, e.Retries, e.Expected, e.Actual)
}

// ErrRegistrationFetch is returned when the orchestrator fails to fetch or
// parse a node's registration.json from the bootstrap server. This is a
// best-effort operation so callers typically log-and-continue rather than
// propagating the error.
type ErrRegistrationFetch struct {
	URL   string
	Cause error
}

func (e ErrRegistrationFetch) Error() string {
	return fmt.Sprintf("bootstrap: failed to fetch registration from %s: %v", e.URL, e.Cause)
}

func (e ErrRegistrationFetch) Unwrap() error { return e.Cause }

// ErrPlainTextSecretMigration is returned when a plain-text secret tagged with
// secret:"true" cannot be migrated to the KMS.
type ErrPlainTextSecretMigration struct {
	Path  string
	Cause error
}

func (e ErrPlainTextSecretMigration) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: failed to migrate plain-text secret at %s to KMS: %v", e.Path, e.Cause)
	}
	return fmt.Sprintf("bootstrap: failed to migrate plain-text secret at %s to KMS", e.Path)
}

func (e ErrPlainTextSecretMigration) Unwrap() error { return e.Cause }

// ErrNilSecretManager is returned when a nil SecretManager is provided to
// MigratePlainTextSecrets.
type ErrNilSecretManager struct{}

func (e ErrNilSecretManager) Error() string {
	return "bootstrap: secret manager cannot be nil"
}
