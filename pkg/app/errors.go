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

package app

import (
	"fmt"
	"time"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
)

// ErrTPMNotInitialized is returned by App.Init when the platform TPM has
// not yet been provisioned (no Endorsement Key configured). It is
// re-exported here so consumers in pkg/daemon can match the sentinel via
// errors.Is without importing go-xkms directly. The SDK-only dependency
// rule (08-bootstrap-auth-architecture.md §5d) requires go-trusted-platform
// to depend solely on go-quicbaas/sdk/go; until the equivalent sentinel is
// re-exported from quicbaas, pkg/app remains the bridge.
var ErrTPMNotInitialized = xkmssdk.ErrTPMNotInitialized

// ErrXKMSStorageInit is returned when a filesystem storage backend cannot be created.
type ErrXKMSStorageInit struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e ErrXKMSStorageInit) Error() string {
	return fmt.Sprintf("app: failed to create xkms storage backend at %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrXKMSStorageInit) Unwrap() error { return e.Cause }

// ErrXKMSBackendInit is returned when an xkms software backend cannot be created.
type ErrXKMSBackendInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrXKMSBackendInit) Error() string {
	return fmt.Sprintf("app: failed to create xkms software backend: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrXKMSBackendInit) Unwrap() error { return e.Cause }

// ErrXKMSServiceInit is returned when the xkms service fails to initialize.
type ErrXKMSServiceInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrXKMSServiceInit) Error() string {
	return fmt.Sprintf("app: failed to initialize xkms service: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrXKMSServiceInit) Unwrap() error { return e.Cause }

// ErrXKMSKeystoreInit is returned when an xkms keystore cannot be created.
type ErrXKMSKeystoreInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrXKMSKeystoreInit) Error() string {
	return fmt.Sprintf("app: failed to create xkms keystore: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrXKMSKeystoreInit) Unwrap() error { return e.Cause }

// ErrQuicBaaSConfig is returned when QuicBaaS configuration is invalid.
type ErrQuicBaaSConfig struct {
	Cause error
}

// Error returns the error message.
func (e ErrQuicBaaSConfig) Error() string {
	return fmt.Sprintf("app: invalid quicbaas configuration: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrQuicBaaSConfig) Unwrap() error { return e.Cause }

// ErrQuicBaaSFactory is returned when the QuicBaaS factory cannot be created.
type ErrQuicBaaSFactory struct {
	Cause error
}

// Error returns the error message.
func (e ErrQuicBaaSFactory) Error() string {
	return fmt.Sprintf("app: failed to create quicbaas factory: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrQuicBaaSFactory) Unwrap() error { return e.Cause }

// ErrQuicBaaSStart is returned when the QuicBaaS factory fails to start.
type ErrQuicBaaSStart struct {
	Cause error
}

// Error returns the error message.
func (e ErrQuicBaaSStart) Error() string {
	return fmt.Sprintf("app: failed to start quicbaas factory: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrQuicBaaSStart) Unwrap() error { return e.Cause }

// ErrPlatformCAInit is returned when the platform CA cannot be initialized.
type ErrPlatformCAInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrPlatformCAInit) Error() string {
	return fmt.Sprintf("app: failed to initialize platform CA: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrPlatformCAInit) Unwrap() error { return e.Cause }

// ErrStorageInit is returned when platform storage cannot be configured.
type ErrStorageInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrStorageInit) Error() string {
	return fmt.Sprintf("app: failed to configure storage: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrStorageInit) Unwrap() error { return e.Cause }

// ErrBarrierInit is returned when the barrier manager cannot be created.
type ErrBarrierInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrBarrierInit) Error() string {
	return fmt.Sprintf("app: failed to create barrier manager: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBarrierInit) Unwrap() error { return e.Cause }

// ErrKeyBackendInit is returned when a TPM key backend cannot be created.
type ErrKeyBackendInit struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e ErrKeyBackendInit) Error() string {
	return fmt.Sprintf("app: failed to create key backend at %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrKeyBackendInit) Unwrap() error { return e.Cause }

// ErrBootstrapStoreInit is returned when a bootstrap CA store cannot be created.
// This occurs during platform CA initialization before QuicBaaS is running.
type ErrBootstrapStoreInit struct {
	Store string
	CN    string
	Cause error
}

// Error returns the error message.
func (e ErrBootstrapStoreInit) Error() string {
	return fmt.Sprintf("app: failed to create bootstrap %s for CA %s: %v", e.Store, e.CN, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapStoreInit) Unwrap() error { return e.Cause }

// ErrNilObjectStore is returned when a nil object store is provided.
type ErrNilObjectStore struct{}

// Error returns the error message.
func (e ErrNilObjectStore) Error() string {
	return "app: object store is required but was nil"
}

// ErrBarrierRequiresQuicBaaS is returned when barrier is configured but
// the QuicBaaS SDK client is not available.
type ErrBarrierRequiresQuicBaaS struct{}

// Error returns the error message.
func (e ErrBarrierRequiresQuicBaaS) Error() string {
	return "app: barrier requires QuicBaaS service"
}

// ErrBarrierSyncStatus is returned when the barrier fails to sync status.
type ErrBarrierSyncStatus struct {
	Cause error
}

// Error returns the error message.
func (e ErrBarrierSyncStatus) Error() string {
	return "app: failed to sync barrier status: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e ErrBarrierSyncStatus) Unwrap() error { return e.Cause }

// ErrDANEPublish is returned when DANE TLSA record publication fails.
type ErrDANEPublish struct {
	Hostname string
	Cause    error
}

// Error returns the error message.
func (e ErrDANEPublish) Error() string {
	return fmt.Sprintf("app: failed to publish DANE TLSA records for %s: %v", e.Hostname, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDANEPublish) Unwrap() error { return e.Cause }

// ErrDANECertParse is returned when a certificate cannot be parsed for DANE publishing.
type ErrDANECertParse struct {
	Cause error
}

// Error returns the error message.
func (e ErrDANECertParse) Error() string {
	return fmt.Sprintf("app: failed to parse certificate for DANE publishing: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrDANECertParse) Unwrap() error { return e.Cause }

// ErrDANENoZone is returned when no matching DNS zone can be found for a hostname.
type ErrDANENoZone struct {
	Hostname string
}

// Error returns the error message.
func (e ErrDANENoZone) Error() string {
	return fmt.Sprintf("app: no matching DNS zone found for hostname %s", e.Hostname)
}

// ErrBootstrapClientInit is returned when the bootstrap client cannot be created.
type ErrBootstrapClientInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrBootstrapClientInit) Error() string {
	return fmt.Sprintf("app: failed to create bootstrap client: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapClientInit) Unwrap() error { return e.Cause }

// ErrBootstrapFetchBundle is returned when fetching the CA bundle fails.
type ErrBootstrapFetchBundle struct {
	Cause error
}

// Error returns the error message.
func (e ErrBootstrapFetchBundle) Error() string {
	return fmt.Sprintf("app: failed to fetch CA bundle: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapFetchBundle) Unwrap() error { return e.Cause }

// ErrBootstrapInstallBundle is returned when installing the CA bundle to the
// system trust store fails.
type ErrBootstrapInstallBundle struct {
	Path  string
	Cause error
}

// Error returns the error message.
func (e ErrBootstrapInstallBundle) Error() string {
	return fmt.Sprintf("app: failed to install CA bundle to system trust at %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapInstallBundle) Unwrap() error { return e.Cause }

// ErrBootstrapTOFUNoSDK is returned when the trust configuration lists the
// tofu strategy in any class chain but the QuicBaaS SDK client is not yet
// available at trust-resolver construction time. The tofu strategy requires
// a live SDK connection so that pins can be persisted to the Raft-replicated
// ParameterStore.
type ErrBootstrapTOFUNoSDK struct{}

// Error returns the error message.
func (e ErrBootstrapTOFUNoSDK) Error() string {
	return "app: trust config lists tofu strategy but QuicBaaS SDK client is not available; " +
		"ensure the quicbaas service is started before calling BootstrapTrust"
}

// ErrBootstrapTOFUPinStore is returned when the TOFU pin store cannot be
// constructed from the platform's QuicBaaS SDK client.
type ErrBootstrapTOFUPinStore struct {
	Cause error
}

// Error returns the error message.
func (e ErrBootstrapTOFUPinStore) Error() string {
	return fmt.Sprintf("app: failed to create TOFU pin store: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrBootstrapTOFUPinStore) Unwrap() error { return e.Cause }

// ErrSDNConfigValidation is returned when the SDN configuration fails validation.
type ErrSDNConfigValidation struct {
	Cause error
}

// Error returns the error message.
func (e ErrSDNConfigValidation) Error() string {
	return fmt.Sprintf("app: sdn configuration validation failed: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrSDNConfigValidation) Unwrap() error { return e.Cause }

// ErrSDNOVSClientInit is returned when the OVS client cannot be created.
type ErrSDNOVSClientInit struct {
	Cause error
}

// Error returns the error message.
func (e ErrSDNOVSClientInit) Error() string {
	return fmt.Sprintf("app: failed to create ovs client: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrSDNOVSClientInit) Unwrap() error { return e.Cause }

// ErrSDNOVSConnect is returned when the OVS client cannot connect to OVSDB.
type ErrSDNOVSConnect struct {
	Socket string
	Cause  error
}

// Error returns the error message.
func (e ErrSDNOVSConnect) Error() string {
	return fmt.Sprintf("app: failed to connect to ovs at %s: %v", e.Socket, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrSDNOVSConnect) Unwrap() error { return e.Cause }

// ErrSDNBridgeCreate is returned when an OVS bridge cannot be created or fetched.
type ErrSDNBridgeCreate struct {
	Bridge string
	Cause  error
}

// Error returns the error message.
func (e ErrSDNBridgeCreate) Error() string {
	return fmt.Sprintf("app: failed to create ovs bridge %s: %v", e.Bridge, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrSDNBridgeCreate) Unwrap() error { return e.Cause }

// ErrSDNIPAMPoolCreate is returned when an IPAM pool cannot be created.
type ErrSDNIPAMPoolCreate struct {
	Pool  string
	Cause error
}

// Error returns the error message.
func (e ErrSDNIPAMPoolCreate) Error() string {
	return fmt.Sprintf("app: failed to create ipam pool %s: %v", e.Pool, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrSDNIPAMPoolCreate) Unwrap() error { return e.Cause }

// ErrWebserviceCertRead wraps a failure reading the live TLS certificate
// from a webservice endpoint. Returned by the cert renewal handler when
// the local TLS handshake or trust-pool construction fails.
type ErrWebserviceCertRead struct {
	Cause error
}

// Error returns the error message.
func (e ErrWebserviceCertRead) Error() string {
	return fmt.Sprintf("app: webservice cert read failed: %v", e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrWebserviceCertRead) Unwrap() error { return e.Cause }

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// CommandOutputError wraps a failed external command with captured output
// or a remediation hint appended after the underlying cause.
type CommandOutputError struct {
	Msg    string
	Err    error
	Detail string
}

// Error implements the error interface.
func (e *CommandOutputError) Error() string {
	return e.Msg + ": " + e.Err.Error() + e.Detail
}

// Unwrap returns the wrapped cause.
func (e *CommandOutputError) Unwrap() error {
	return e.Err
}

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// ErrHeartbeatIntervalTooShort signals a heartbeat interval below the
// minimum — usually a unitless YAML value that decoded to nanoseconds.
type ErrHeartbeatIntervalTooShort struct {
	Interval time.Duration
}

// Error implements the error interface.
func (e ErrHeartbeatIntervalTooShort) Error() string {
	return "heartbeat: interval " + e.Interval.String() +
		" is below the minimum " + MinHeartbeatInterval.String() +
		" (a unitless YAML value decodes to nanoseconds)"
}

// ErrHeartbeatIdentityIncomplete signals a heartbeat section that sets
// only one of cert-file / key-file.
type ErrHeartbeatIdentityIncomplete struct {
	CertFile string
	KeyFile  string
}

// Error implements the error interface.
func (e ErrHeartbeatIdentityIncomplete) Error() string {
	return "heartbeat: cert-file and key-file must both be set for a file-based identity"
}

// ErrHeartbeatCABundleInvalid signals a ca-file that contains no usable
// PEM certificates.
type ErrHeartbeatCABundleInvalid struct {
	Path string
}

// Error implements the error interface.
func (e ErrHeartbeatCABundleInvalid) Error() string {
	return "heartbeat: no certificates parsed from ca-file " + e.Path
}

// ErrPlatformAnchorNoIdentity signals that the platform anchor cannot be
// derived because this node has no TPM or CA, so it holds no IDevID whose
// issuing chain names the platform CA.
type ErrPlatformAnchorNoIdentity struct{}

// Error implements the error interface.
func (e ErrPlatformAnchorNoIdentity) Error() string {
	return "platform anchor: this node has no TPM-backed IDevID and CA to derive the platform CA from"
}

// Is implements errors.Is equality for value-type errors.
func (e ErrPlatformAnchorNoIdentity) Is(target error) bool {
	_, ok := target.(ErrPlatformAnchorNoIdentity)
	return ok
}
