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

import (
	"fmt"
	"time"
)

// ErrBootstrapFailed indicates a bootstrap phase failed.
type ErrBootstrapFailed struct {
	Phase string
	Cause error
}

func (e ErrBootstrapFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: phase %s failed: %v", e.Phase, e.Cause)
	}
	return fmt.Sprintf("bootstrap: phase %s failed", e.Phase)
}

func (e ErrBootstrapFailed) Unwrap() error {
	return e.Cause
}

// ErrPhaseTimeout indicates a bootstrap phase exceeded its timeout.
type ErrPhaseTimeout struct {
	Phase   string
	Timeout time.Duration
}

func (e ErrPhaseTimeout) Error() string {
	return fmt.Sprintf("bootstrap: phase %s timed out after %s", e.Phase, e.Timeout)
}

// ErrNodeProvisionFailed indicates provisioning failed for a specific node.
type ErrNodeProvisionFailed struct {
	Hostname string
	Role     string
	Cause    error
}

func (e ErrNodeProvisionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: provisioning failed for node %s (role=%s): %v", e.Hostname, e.Role, e.Cause)
	}
	return fmt.Sprintf("bootstrap: provisioning failed for node %s (role=%s)", e.Hostname, e.Role)
}

func (e ErrNodeProvisionFailed) Unwrap() error {
	return e.Cause
}

// ErrHealthCheckFailed indicates a health check did not succeed.
type ErrHealthCheckFailed struct {
	Address string
	Cause   error
}

func (e ErrHealthCheckFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: health check failed for %s: %v", e.Address, e.Cause)
	}
	return fmt.Sprintf("bootstrap: health check failed for %s", e.Address)
}

func (e ErrHealthCheckFailed) Unwrap() error {
	return e.Cause
}

// ErrSeedFailed indicates template seeding failed.
type ErrSeedFailed struct {
	Cause error
}

func (e ErrSeedFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: template seeding failed: %v", e.Cause)
	}
	return "bootstrap: template seeding failed"
}

func (e ErrSeedFailed) Unwrap() error {
	return e.Cause
}

// ErrContainerDeployFailed indicates the bootstrap container failed to deploy.
type ErrContainerDeployFailed struct {
	Host  string
	Cause error
}

func (e ErrContainerDeployFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: container deploy failed on host %s: %v", e.Host, e.Cause)
	}
	return fmt.Sprintf("bootstrap: container deploy failed on host %s", e.Host)
}

func (e ErrContainerDeployFailed) Unwrap() error {
	return e.Cause
}

// ErrContainerTeardownFailed indicates the bootstrap container teardown failed.
type ErrContainerTeardownFailed struct {
	Host  string
	Cause error
}

func (e ErrContainerTeardownFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: container teardown failed on host %s: %v", e.Host, e.Cause)
	}
	return fmt.Sprintf("bootstrap: container teardown failed on host %s", e.Host)
}

func (e ErrContainerTeardownFailed) Unwrap() error {
	return e.Cause
}

// ErrNilOrchestratorConfig is returned when a nil config is passed to NewOrchestrator.
type ErrNilOrchestratorConfig struct{}

func (e ErrNilOrchestratorConfig) Error() string {
	return "bootstrap: orchestrator config cannot be nil"
}

// ErrNilBMCFactory is returned when a nil BMC factory is passed to NewOrchestrator.
type ErrNilBMCFactory struct{}

func (e ErrNilBMCFactory) Error() string {
	return "bootstrap: BMC client factory cannot be nil"
}

// ErrNoControlPlaneNode is returned when no control-plane node is found.
type ErrNoControlPlaneNode struct{}

func (e ErrNoControlPlaneNode) Error() string {
	return "bootstrap: no control-plane node found in discovered nodes"
}

// ErrTemplateFileNotFound is returned when a template file does not exist.
type ErrTemplateFileNotFound struct {
	Role string
	Path string
}

func (e ErrTemplateFileNotFound) Error() string {
	return fmt.Sprintf("bootstrap: template file not found for role %s: %s", e.Role, e.Path)
}

// ErrTemplateUploadFailed is returned when uploading a template to the control plane fails.
type ErrTemplateUploadFailed struct {
	Role       string
	StatusCode int
	Cause      error
}

func (e ErrTemplateUploadFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: template upload failed for role %s (status=%d): %v", e.Role, e.StatusCode, e.Cause)
	}
	return fmt.Sprintf("bootstrap: template upload failed for role %s (status=%d)", e.Role, e.StatusCode)
}

func (e ErrTemplateUploadFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileCreateFailed is returned when creating a device profile fails.
type ErrProfileCreateFailed struct {
	Hostname   string
	StatusCode int
	Cause      error
}

func (e ErrProfileCreateFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: profile creation failed for %s (status=%d): %v", e.Hostname, e.StatusCode, e.Cause)
	}
	return fmt.Sprintf("bootstrap: profile creation failed for %s (status=%d)", e.Hostname, e.StatusCode)
}

func (e ErrProfileCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileIDParseFailed is returned when the profile ID in the create-profile
// response body cannot be parsed. The server serializes profile IDs as JSON
// strings (uint64 > 2^53); a malformed or missing "id" field is a hard error
// because the orchestrator cannot proceed with BMC enrollment without it.
type ErrProfileIDParseFailed struct {
	Hostname string
	Cause    error
}

func (e ErrProfileIDParseFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: failed to parse profile ID for node %s: %v", e.Hostname, e.Cause)
	}
	return fmt.Sprintf("bootstrap: failed to parse profile ID for node %s", e.Hostname)
}

func (e ErrProfileIDParseFailed) Unwrap() error {
	return e.Cause
}

// ErrMissingSeederAddr is returned when the control plane address is empty.
type ErrMissingSeederAddr struct{}

func (e ErrMissingSeederAddr) Error() string {
	return "bootstrap: seeder control plane address cannot be empty"
}

// ErrDryRunBMCUnreachable indicates a BMC was not reachable during dry-run.
type ErrDryRunBMCUnreachable struct {
	Hostname   string
	BMCAddress string
	Cause      error
}

func (e ErrDryRunBMCUnreachable) Error() string {
	return "bootstrap: dry-run: bmc unreachable for " + e.Hostname + " at " + e.BMCAddress + ": " + e.Cause.Error()
}

func (e ErrDryRunBMCUnreachable) Unwrap() error {
	return e.Cause
}

// ErrDryRunNoNodes is returned when a dry-run is attempted with no nodes configured.
type ErrDryRunNoNodes struct{}

func (e ErrDryRunNoNodes) Error() string {
	return "bootstrap: dry-run: no nodes configured"
}

// ErrTemplateNotFoundForRole is returned when no template is configured for a role.
type ErrTemplateNotFoundForRole struct {
	Role string
}

func (e ErrTemplateNotFoundForRole) Error() string {
	return fmt.Sprintf("bootstrap: no template configured for role %s", e.Role)
}

// ErrTemplateReadFailed is returned when reading or parsing a template file fails.
type ErrTemplateReadFailed struct {
	Role  string
	Path  string
	Cause error
}

func (e ErrTemplateReadFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: failed to read template for role %s at %s: %v", e.Role, e.Path, e.Cause)
	}
	return fmt.Sprintf("bootstrap: failed to read template for role %s at %s", e.Role, e.Path)
}

func (e ErrTemplateReadFailed) Unwrap() error {
	return e.Cause
}

// ErrControlPlaneHealthGateFailed is returned when the control-plane health
// verification gate fails before teardown. When this error is produced the
// orchestrator skips bootstrap container teardown to avoid disrupting network
// services (DHCP, DNS) that may still be provided by the container.
type ErrControlPlaneHealthGateFailed struct {
	Timeout time.Duration
	Cause   error
}

func (e ErrControlPlaneHealthGateFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: control-plane health gate failed after %s: %v", e.Timeout, e.Cause)
	}
	return fmt.Sprintf("bootstrap: control-plane health gate failed after %s", e.Timeout)
}

func (e ErrControlPlaneHealthGateFailed) Unwrap() error {
	return e.Cause
}

// ErrTemplateYAMLParseFailed is returned when a template YAML file cannot be
// parsed into a generic structure for JSON conversion.
type ErrTemplateYAMLParseFailed struct {
	Role  string
	Path  string
	Cause error
}

func (e ErrTemplateYAMLParseFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: failed to parse template YAML for role %s at %s: %v", e.Role, e.Path, e.Cause)
	}
	return fmt.Sprintf("bootstrap: failed to parse template YAML for role %s at %s", e.Role, e.Path)
}

func (e ErrTemplateYAMLParseFailed) Unwrap() error {
	return e.Cause
}

// ErrTemplateJSONConvertFailed is returned when a parsed template cannot be
// marshaled to JSON for upload to the control plane.
type ErrTemplateJSONConvertFailed struct {
	Role  string
	Cause error
}

func (e ErrTemplateJSONConvertFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: failed to convert template to JSON for role %s: %v", e.Role, e.Cause)
	}
	return fmt.Sprintf("bootstrap: failed to convert template to JSON for role %s", e.Role)
}

func (e ErrTemplateJSONConvertFailed) Unwrap() error {
	return e.Cause
}

// ErrBootRetryExhausted is returned when the orchestrator retried the
// virtual-media boot cycle the maximum number of times and the install log
// never appeared. This typically means the BIOS boot order does not have
// the virtual CD before the hard disk, so the server keeps booting from
// disk instead of the ISO.
type ErrBootRetryExhausted struct {
	Hostname   string
	MaxRetries int
	Cause      error
}

func (e ErrBootRetryExhausted) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf(
			"bootstrap: node %s: boot retry exhausted after %d attempts (check BIOS boot order: ATEN CDROM must be before Hard Disk): %v",
			e.Hostname, e.MaxRetries, e.Cause)
	}
	return fmt.Sprintf(
		"bootstrap: node %s: boot retry exhausted after %d attempts (check BIOS boot order: ATEN CDROM must be before Hard Disk)",
		e.Hostname, e.MaxRetries)
}

func (e ErrBootRetryExhausted) Unwrap() error {
	return e.Cause
}

// ErrBootFromDiskDetected is returned when the orchestrator determines
// that a node booted from disk instead of the ISO after a virtual-media
// boot attempt. This is a transient condition that triggers a retry.
type ErrBootFromDiskDetected struct {
	Hostname string
	Attempt  int
}

func (e ErrBootFromDiskDetected) Error() string {
	return fmt.Sprintf(
		"bootstrap: node %s: booted from disk instead of ISO on attempt %d",
		e.Hostname, e.Attempt)
}

// ErrTemplateMergeFailed is returned when the orchestrator fails to merge
// a node's overrides into the base template for profile creation.
type ErrTemplateMergeFailed struct {
	Hostname string
	Role     string
	Cause    error
}

func (e ErrTemplateMergeFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("bootstrap: failed to merge template for node %s (role=%s): %v",
			e.Hostname, e.Role, e.Cause)
	}
	return fmt.Sprintf("bootstrap: failed to merge template for node %s (role=%s)",
		e.Hostname, e.Role)
}

func (e ErrTemplateMergeFailed) Unwrap() error {
	return e.Cause
}

// ErrCABundleInvalid is returned when the fetched control-plane CA bundle
// contains no parseable CA certificates.
type ErrCABundleInvalid struct {
	URL string
}

func (e ErrCABundleInvalid) Error() string {
	return fmt.Sprintf("bootstrap: control-plane CA bundle from %s contains no parseable certificates", e.URL)
}

// ErrCABundleVerifyFailed is returned when the TLS certificate chain that
// served the control-plane CA bundle does not verify against the bundle
// itself (capture-then-verify). The bundle is rejected and never stored
// as a trust anchor.
type ErrCABundleVerifyFailed struct {
	URL   string
	Cause error
}

func (e ErrCABundleVerifyFailed) Error() string {
	return fmt.Sprintf("bootstrap: TLS chain serving %s does not verify against the fetched CA bundle, rejecting bundle: %v", e.URL, e.Cause)
}

func (e ErrCABundleVerifyFailed) Unwrap() error {
	return e.Cause
}

// ErrCABundleRequired is returned when an operation requires the
// control-plane CA pool captured by fetchControlPlaneCABundle but the
// bundle has not been (successfully) fetched. Operations that establish
// trust material, such as SPKI pin capture, must never proceed over an
// unverified connection.
type ErrCABundleRequired struct {
	Operation string
}

func (e ErrCABundleRequired) Error() string {
	return fmt.Sprintf("bootstrap: %s requires the control-plane CA bundle, but it has not been fetched", e.Operation)
}

// ErrNoPeerCertificates is returned when a TLS handshake with the control
// plane completes without the server presenting any certificates.
type ErrNoPeerCertificates struct {
	Endpoint string
}

func (e ErrNoPeerCertificates) Error() string {
	return fmt.Sprintf("bootstrap: TLS handshake with %s returned no peer certificates", e.Endpoint)
}

// ErrContainerServiceNotServing reports that the bootstrap container was
// started but the service inside it is not answering.
//
// This is distinct from ErrContainerDeployFailed, which means the
// container never started. Here `docker run` succeeded, `docker ps`
// shows the container Up, and supervisord has nonetheless retired
// pxeboot — a port conflict on the deployer is the common cause. The
// distinction is worth a separate type because the remedy differs: a
// deploy failure is usually the image or the host, while this one is
// almost always something else already holding a port, which the
// bootstrap_http_port / bootstrap_device_script_port settings exist to
// move.
type ErrContainerServiceNotServing struct {
	// Host is the deployer the container was started on.
	Host string
	// BaseURL is the endpoint that failed to answer.
	BaseURL string
	// Listener names which of the container's two listeners failed, so
	// the message points at the port actually in conflict.
	Listener string
	// Cause is the underlying readiness error.
	Cause error
}

func (e ErrContainerServiceNotServing) Error() string {
	msg := fmt.Sprintf(
		"bootstrap: container started on %s but its %s at %s is not serving"+
			" — nodes would install from the ISO's baked config instead of their own;"+
			" check for a port conflict on the deployer and set deployer.bootstrap_http_port"+
			" / deployer.bootstrap_device_script_port to move it",
		e.Host, e.Listener, e.BaseURL)
	if e.Cause != nil {
		return msg + ": " + e.Cause.Error()
	}
	return msg
}

func (e ErrContainerServiceNotServing) Unwrap() error {
	return e.Cause
}
