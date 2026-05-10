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

package bmc

import "fmt"

// ErrInvalidConfig indicates an invalid BMC configuration field.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("bmc: invalid configuration for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("bmc: invalid configuration: %s", e.Reason)
}

// ErrConnectionFailed indicates a BMC connection failure.
type ErrConnectionFailed struct {
	Address string
	Cause   error
}

func (e ErrConnectionFailed) Error() string {
	msg := "bmc: connection failed"
	if e.Address != "" {
		msg = fmt.Sprintf("%s to %s", msg, e.Address)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Cause
}

// ErrClientClosed indicates the BMC client has been closed.
type ErrClientClosed struct{}

func (e ErrClientClosed) Error() string {
	return "bmc: client is closed"
}

// ErrPowerOperation indicates a power management operation failure.
type ErrPowerOperation struct {
	Operation string
	Cause     error
}

func (e ErrPowerOperation) Error() string {
	msg := "bmc: power operation failed"
	if e.Operation != "" {
		msg = fmt.Sprintf("bmc: power %s failed", e.Operation)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrPowerOperation) Unwrap() error {
	return e.Cause
}

// ErrBootDevice indicates a boot device operation failure.
type ErrBootDevice struct {
	Device string
	Cause  error
}

func (e ErrBootDevice) Error() string {
	msg := "bmc: boot device operation failed"
	if e.Device != "" {
		msg = fmt.Sprintf("bmc: boot device %s failed", e.Device)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrBootDevice) Unwrap() error {
	return e.Cause
}

// ErrVirtualMedia indicates a virtual media operation failure.
type ErrVirtualMedia struct {
	Operation string
	Cause     error
}

func (e ErrVirtualMedia) Error() string {
	msg := "bmc: virtual media operation failed"
	if e.Operation != "" {
		msg = fmt.Sprintf("bmc: virtual media %s failed", e.Operation)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrVirtualMedia) Unwrap() error {
	return e.Cause
}

// ErrBootOverrideUnsupported is returned by a vendor-specific boot
// override backend (e.g. Supermicro CGI) when it cannot honour the
// request. The Redfish dispatch layer treats this as a soft failure
// and falls through to the standard DMTF PATCH path, so vendor
// backends that haven't been fully wired (documented stubs) don't
// block the orchestrator's boot flow.
type ErrBootOverrideUnsupported struct {
	Backend string
	Vendor  string
	Device  string
	Reason  string
}

func (e ErrBootOverrideUnsupported) Error() string {
	msg := "bmc: boot override unsupported"
	if e.Backend != "" {
		msg = fmt.Sprintf("%s: backend=%s", msg, e.Backend)
	}
	if e.Vendor != "" {
		msg = fmt.Sprintf("%s vendor=%s", msg, e.Vendor)
	}
	if e.Device != "" {
		msg = fmt.Sprintf("%s device=%s", msg, e.Device)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	return msg
}

// ErrUEFIBootClearUnsupported is returned by ClearUEFIBootEntries when
// the BMC does not advertise a Redfish BiosReset action and the
// platform has no vendor-specific fallback wired for the resolved
// quirk. The orchestrator catches this and either falls back to a
// vendor CGI implementation (Fix C) or surfaces it to the operator.
type ErrUEFIBootClearUnsupported struct {
	Manufacturer string
	Model        string
	Cause        error
}

func (e ErrUEFIBootClearUnsupported) Error() string {
	msg := "bmc: UEFI NVRAM boot-entry clear unsupported"
	if e.Manufacturer != "" || e.Model != "" {
		msg = fmt.Sprintf("%s on %s/%s", msg, e.Manufacturer, e.Model)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrUEFIBootClearUnsupported) Unwrap() error {
	return e.Cause
}

// ErrInventory indicates a failure retrieving BMC inventory data.
type ErrInventory struct {
	Cause error
}

func (e ErrInventory) Error() string {
	msg := "bmc: inventory retrieval failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrInventory) Unwrap() error {
	return e.Cause
}

// ErrProfileNotFound indicates a device profile was not found.
type ErrProfileNotFound struct {
	ProfileID uint64
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("bmc: profile not found: %d", e.ProfileID)
}

// ErrInvalidBootDevice indicates an unrecognized boot device value.
type ErrInvalidBootDevice struct {
	Device string
}

func (e ErrInvalidBootDevice) Error() string {
	return fmt.Sprintf("bmc: invalid boot device: %s", e.Device)
}

// ErrInvalidPowerState indicates an unrecognized power state value.
type ErrInvalidPowerState struct {
	State string
}

func (e ErrInvalidPowerState) Error() string {
	return fmt.Sprintf("bmc: invalid power state: %s", e.State)
}

// ErrNilConfig indicates a nil configuration was provided.
type ErrNilConfig struct{}

func (e ErrNilConfig) Error() string {
	return "bmc: configuration is nil"
}

// ErrUnsupportedOperation indicates the requested operation is not supported
// by the current BMC protocol.
type ErrUnsupportedOperation struct {
	Operation string
}

func (e ErrUnsupportedOperation) Error() string {
	return fmt.Sprintf("bmc: unsupported operation: %s", e.Operation)
}

// ErrSensorRead indicates a failure reading sensor data from the BMC.
type ErrSensorRead struct {
	Cause error
}

func (e ErrSensorRead) Error() string {
	msg := "bmc: sensor read failed"
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrSensorRead) Unwrap() error {
	return e.Cause
}

// ErrFRURead indicates a failure reading or parsing FRU data.
type ErrFRURead struct {
	Reason string
	Cause  error
}

func (e ErrFRURead) Error() string {
	msg := "bmc: FRU read failed"
	if e.Reason != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.Reason)
	}
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

func (e ErrFRURead) Unwrap() error {
	return e.Cause
}

// ErrSDRParse indicates a failure parsing an SDR record.
type ErrSDRParse struct {
	Reason string
}

func (e ErrSDRParse) Error() string {
	return fmt.Sprintf("bmc: SDR parse failed: %s", e.Reason)
}

// ErrIPMIShortResponse indicates an IPMI command returned fewer bytes
// than required to interpret the response.
type ErrIPMIShortResponse struct {
	Command string
	Got     int
	Want    int
}

func (e ErrIPMIShortResponse) Error() string {
	return fmt.Sprintf("bmc: %s response too short: got %d bytes, want >=%d",
		e.Command, e.Got, e.Want)
}

// ErrCredentialsNotFound indicates no credentials are stored under the
// requested name.
type ErrCredentialsNotFound struct {
	Name string
}

func (e ErrCredentialsNotFound) Error() string {
	return fmt.Sprintf("bmc: credentials not found: %s", e.Name)
}

// ErrInvalidCredentials indicates a credential value or operation
// failed validation.
type ErrInvalidCredentials struct {
	Reason string
}

func (e ErrInvalidCredentials) Error() string {
	return "bmc: invalid credentials: " + e.Reason
}

// ErrInvalidRotationConfig indicates a required RotationEngine
// dependency was missing or out of range.
type ErrInvalidRotationConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidRotationConfig) Error() string {
	return fmt.Sprintf("bmc: invalid rotation config %s: %s", e.Field, e.Reason)
}

// ErrRotationGenerate indicates password generation failed.
type ErrRotationGenerate struct {
	Cause error
}

func (e ErrRotationGenerate) Error() string {
	return fmt.Sprintf("bmc: rotation password generation failed: %v", e.Cause)
}

func (e ErrRotationGenerate) Unwrap() error { return e.Cause }

// ErrRotationStoreAhead indicates the pre-apply store write failed.
// Rotation did not touch the BMC; the store is unchanged.
type ErrRotationStoreAhead struct {
	Cause error
}

func (e ErrRotationStoreAhead) Error() string {
	return fmt.Sprintf("bmc: rotation store-ahead failed (BMC untouched): %v", e.Cause)
}

func (e ErrRotationStoreAhead) Unwrap() error { return e.Cause }

// ErrRotationConnect indicates a session could not be established
// during a rotation phase (apply, verify, rollback).
type ErrRotationConnect struct {
	Phase string
	Cause error
}

func (e ErrRotationConnect) Error() string {
	return fmt.Sprintf("bmc: rotation connect failed in %s phase: %v", e.Phase, e.Cause)
}

func (e ErrRotationConnect) Unwrap() error { return e.Cause }

// ErrRotationApply indicates the SetUserPassword call failed.
type ErrRotationApply struct {
	Cause error
}

func (e ErrRotationApply) Error() string {
	return fmt.Sprintf("bmc: rotation apply failed: %v", e.Cause)
}

func (e ErrRotationApply) Unwrap() error { return e.Cause }

// ErrRotationVerify indicates authentication with the new password
// failed after SetUserPassword appeared to succeed.
type ErrRotationVerify struct {
	Cause error
}

func (e ErrRotationVerify) Error() string {
	return fmt.Sprintf("bmc: rotation verify failed: %v", e.Cause)
}

func (e ErrRotationVerify) Unwrap() error { return e.Cause }

// ErrRotationReverted indicates rotation failed but the rollback was
// successful — both BMC and store now reflect the pre-rotation state.
// Cause wraps the underlying apply/verify failure.
type ErrRotationReverted struct {
	Cause error
}

func (e ErrRotationReverted) Error() string {
	return fmt.Sprintf("bmc: rotation reverted to prior password: %v", e.Cause)
}

func (e ErrRotationReverted) Unwrap() error { return e.Cause }

// ErrRotationStoreRollback indicates the rollback succeeded on the
// BMC but writing the prior credentials back to the store failed.
// BMC has old password; store has new. Operator should re-Put.
type ErrRotationStoreRollback struct {
	Cause error
}

func (e ErrRotationStoreRollback) Error() string {
	return fmt.Sprintf("bmc: rotation rollback succeeded on BMC but store write failed: %v", e.Cause)
}

func (e ErrRotationStoreRollback) Unwrap() error { return e.Cause }

// ErrRotationCatastrophic indicates both the rotation and its
// rollback failed. The store holds the new password (matching the
// BMC's post-apply state); operator intervention required to verify
// actual BMC state.
type ErrRotationCatastrophic struct {
	Name      string
	ApplyErr  error
	RollbackE error
}

func (e ErrRotationCatastrophic) Error() string {
	return fmt.Sprintf("bmc: CATASTROPHIC rotation failure for %s: apply=%v rollback=%v; store now has new password, operator intervention required",
		e.Name, e.ApplyErr, e.RollbackE)
}

// ErrAutoCertResolve indicates AutoCertManager could not determine the
// BMC vendor or reach the service root during backend resolution.
type ErrAutoCertResolve struct {
	Cause error
}

func (e ErrAutoCertResolve) Error() string {
	return fmt.Sprintf("bmc: auto-cert backend resolution failed: %v", e.Cause)
}

func (e ErrAutoCertResolve) Unwrap() error { return e.Cause }

// ErrAutoCertCGIGated indicates auto mode resolved to CertBackendSMCCGI
// but the SMC CGI path is gated behind hardware validation.
type ErrAutoCertCGIGated struct {
	Vendor Vendor
}

func (e ErrAutoCertCGIGated) Error() string {
	return fmt.Sprintf("bmc: auto-cert resolved to smc-cgi for vendor %s but CGI fallback is disabled pending hardware validation; set backend: smc-cgi explicitly to override",
		e.Vendor)
}

// ErrAutoCertBackendUnavailable indicates no factory is registered for
// the requested CertBackend. The caller probably forgot a side-effect
// import of the backend subpackage.
type ErrAutoCertBackendUnavailable struct {
	Backend CertBackend
}

func (e ErrAutoCertBackendUnavailable) Error() string {
	return fmt.Sprintf("bmc: no factory registered for backend %q (missing side-effect import?)", e.Backend)
}

// ErrAutoCertAllBackendsFailed indicates both the primary and fallback
// backends failed to replace the cert.
type ErrAutoCertAllBackendsFailed struct {
	Primary   CertBackend
	Fallback  CertBackend
	PrimaryE  error
	FallbackE error
}

func (e ErrAutoCertAllBackendsFailed) Error() string {
	return fmt.Sprintf("bmc: all backends failed: primary=%s (%v); fallback=%s (%v)",
		e.Primary, e.PrimaryE, e.Fallback, e.FallbackE)
}

// ErrGetSDRRepoInfo indicates the IPMI Get SDR Repository Info command
// failed at the transport layer.
type ErrGetSDRRepoInfo struct {
	Cause error
}

func (e ErrGetSDRRepoInfo) Error() string {
	return fmt.Sprintf("bmc: get SDR repository info: %v", e.Cause)
}

func (e ErrGetSDRRepoInfo) Unwrap() error { return e.Cause }

// ErrSDRResponseTooShort indicates an SDR-related IPMI response did not
// contain enough bytes to interpret. Operation identifies which SDR
// command produced the truncated reply.
type ErrSDRResponseTooShort struct {
	Operation string
	Length    int
	Expected  int
}

func (e ErrSDRResponseTooShort) Error() string {
	op := e.Operation
	if op == "" {
		op = "SDR"
	}
	return fmt.Sprintf("bmc: %s response too short: %d bytes (need >=%d)",
		op, e.Length, e.Expected)
}

// ErrReserveSDR indicates the IPMI Reserve SDR Repository command
// failed at the transport layer.
type ErrReserveSDR struct {
	Cause error
}

func (e ErrReserveSDR) Error() string {
	return fmt.Sprintf("bmc: reserve SDR repository: %v", e.Cause)
}

func (e ErrReserveSDR) Unwrap() error { return e.Cause }

// ErrGetFRUInfo indicates the IPMI Get FRU Inventory Area Info command
// failed at the transport layer.
type ErrGetFRUInfo struct {
	Cause error
}

func (e ErrGetFRUInfo) Error() string {
	return fmt.Sprintf("bmc: get FRU inventory area info: %v", e.Cause)
}

func (e ErrGetFRUInfo) Unwrap() error { return e.Cause }

// ErrReadFRU indicates a Read FRU Data command failed for a chunk at
// the given offset.
type ErrReadFRU struct {
	Offset int
	Cause  error
}

func (e ErrReadFRU) Error() string {
	return fmt.Sprintf("bmc: read FRU data at offset %d: %v", e.Offset, e.Cause)
}

func (e ErrReadFRU) Unwrap() error { return e.Cause }

// ErrBMCResetTimeout indicates the BMC did not become ready within the
// configured deadline after a reset operation. Cause is the last
// connection error observed before the deadline expired.
type ErrBMCResetTimeout struct {
	Cause error
}

func (e ErrBMCResetTimeout) Error() string {
	return fmt.Sprintf("bmc: timed out waiting for BMC to become ready after reset: %v", e.Cause)
}

func (e ErrBMCResetTimeout) Unwrap() error { return e.Cause }

// ErrRedfishServiceRootStatus indicates the Redfish service root
// returned a non-2xx HTTP status code during vendor probing.
type ErrRedfishServiceRootStatus struct {
	Status int
}

func (e ErrRedfishServiceRootStatus) Error() string {
	return fmt.Sprintf("bmc: redfish service root status %d", e.Status)
}
