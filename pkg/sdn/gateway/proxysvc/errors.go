// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// ErrNilEngine is returned when a Handler is constructed without a proxy
// engine.
type ErrNilEngine struct{}

// Error implements the error interface.
func (e *ErrNilEngine) Error() string {
	return "proxysvc: nil proxy engine"
}

// ErrNilClient is returned when a ConfigSyncer is constructed without a
// control-plane client.
type ErrNilClient struct{}

// Error implements the error interface.
func (e *ErrNilClient) Error() string {
	return "proxysvc: nil control-plane client"
}

// ErrNilReloader is returned when a ConfigSyncer is constructed without a
// reload target.
type ErrNilReloader struct{}

// Error implements the error interface.
func (e *ErrNilReloader) Error() string {
	return "proxysvc: nil reloader"
}

// ErrNilResolver is returned when a TrustResolverAdapter is constructed
// with neither a trust resolver nor a platform anchor.
type ErrNilResolver struct{}

// Error implements the error interface.
func (e *ErrNilResolver) Error() string {
	return "proxysvc: neither a trust resolver nor a platform anchor"
}

// ErrTrustSourceMissing is returned when a backend pool names a trust class
// whose source this gateway was not configured with.
type ErrTrustSourceMissing struct {
	// Class is the backend trust class.
	Class string
	// Source is the configuration that supplies it.
	Source string
}

// Error implements the error interface.
func (e *ErrTrustSourceMissing) Error() string {
	return fmt.Sprintf("proxysvc: trust class %q needs %s, which this gateway is not configured with", e.Class, e.Source)
}

// ErrUnknownTrustClass is returned when a backend pool references a trust
// class the platform trust resolver does not define.
type ErrUnknownTrustClass struct {
	// Class is the unrecognized trust class string.
	Class string
}

// Error implements the error interface.
func (e *ErrUnknownTrustClass) Error() string {
	return fmt.Sprintf("proxysvc: unknown trust class %q (known: %s, %s)", e.Class, BackendTrustPlatform, BackendTrustBMC)
}

// ErrProxyDisabled is returned when a Handler is requested for a disabled
// proxy configuration section.
type ErrProxyDisabled struct{}

// Error implements the error interface.
func (e *ErrProxyDisabled) Error() string {
	return "proxysvc: proxy service is disabled in configuration"
}

// ErrServerTLSRequired is returned when the proxy configuration declares
// authenticated routes but no server TLS certificate/key pair.
type ErrServerTLSRequired struct{}

// Error implements the error interface.
func (e *ErrServerTLSRequired) Error() string {
	return "proxysvc: authenticated routes require tls.cert-file and tls.key-file"
}

// ErrClientCARequired is returned when mutual-TLS routes are configured but
// no client CA source (client-ca-file or trust resolver) is available.
type ErrClientCARequired struct{}

// Error implements the error interface.
func (e *ErrClientCARequired) Error() string {
	return "proxysvc: mtls routes require tls.client-ca-file or a configured trust: section"
}

// ErrConfigInvalid is returned for structurally invalid proxysvc
// configuration values.
type ErrConfigInvalid struct {
	// Field is the offending configuration field.
	Field string
	// Reason describes why the value was rejected.
	Reason string
}

// Error implements the error interface.
func (e *ErrConfigInvalid) Error() string {
	return fmt.Sprintf("proxysvc: invalid configuration field %s: %s", e.Field, e.Reason)
}

// ErrPlatformdIdentityLoadFailed is returned when the client identity
// gatewayd presents to platformd (the cert-file/key-file pair or the
// token-file) cannot be loaded.
type ErrPlatformdIdentityLoadFailed struct {
	// Path is the configured credential file.
	Path string
	// Cause is the underlying error; nil when the token file is empty.
	Cause error
}

// Error implements the error interface.
func (e *ErrPlatformdIdentityLoadFailed) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("proxysvc: platformd client identity %s is empty", e.Path)
	}
	return fmt.Sprintf("proxysvc: loading platformd client identity %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrPlatformdIdentityLoadFailed) Unwrap() error { return e.Cause }

// ErrCertificateLoadFailed is returned when the server TLS keypair cannot be
// loaded from disk.
type ErrCertificateLoadFailed struct {
	// CertFile is the configured certificate path.
	CertFile string
	// Cause is the underlying error.
	Cause error
}

// Error implements the error interface.
func (e *ErrCertificateLoadFailed) Error() string {
	return fmt.Sprintf("proxysvc: loading server certificate %s: %v", e.CertFile, e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrCertificateLoadFailed) Unwrap() error { return e.Cause }

// ErrClientCALoadFailed is returned when the client CA bundle cannot be
// loaded or parsed.
type ErrClientCALoadFailed struct {
	// Path is the configured client CA bundle path.
	Path string
	// Cause is the underlying error; nil when the PEM parsed but contained
	// no certificates.
	Cause error
}

// Error implements the error interface.
func (e *ErrClientCALoadFailed) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("proxysvc: client CA bundle %s contains no certificates", e.Path)
	}
	return fmt.Sprintf("proxysvc: loading client CA bundle %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrClientCALoadFailed) Unwrap() error { return e.Cause }

// ErrDialFailed is returned by the lazy control-plane client when the SDK
// connection to platformd cannot be established. The sync loop treats it as
// transient and retries on the next tick.
type ErrDialFailed struct {
	// Cause is the underlying connection error.
	Cause error
}

// Error implements the error interface.
func (e *ErrDialFailed) Error() string {
	return fmt.Sprintf("proxysvc: dialing platformd control plane: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrDialFailed) Unwrap() error { return e.Cause }

// ErrNilDialFunc is returned when a lazy control-plane client is constructed
// without a dial function.
type ErrNilDialFunc struct{}

// Error implements the error interface.
func (e *ErrNilDialFunc) Error() string {
	return "proxysvc: nil dial function"
}

// ErrNilAttestationClient is returned when an SDKAttestationGate is
// constructed without an attestation client.
type ErrNilAttestationClient struct{}

// Error implements the error interface.
func (e *ErrNilAttestationClient) Error() string {
	return "proxysvc: nil attestation client"
}

// ErrDeviceIDRequired is returned when the attestation gate is queried
// without a device identifier.
type ErrDeviceIDRequired struct{}

// Error implements the error interface.
func (e *ErrDeviceIDRequired) Error() string {
	return "proxysvc: attestation device id is required"
}

// ErrDeviceNotAttested is the definitive attestation-gate verdict: the
// device has no manifest, its newest manifest failed platformd verification,
// or the manifest is older than the route's accepted age. It wraps
// proxy.ErrAttestationStale so the auth chain maps it to the
// "attestation_stale" deny reason.
type ErrDeviceNotAttested struct {
	// DeviceID is the attestation host identifier queried.
	DeviceID string
	// Detail describes which freshness requirement failed.
	Detail string
}

// Error implements the error interface.
func (e *ErrDeviceNotAttested) Error() string {
	return fmt.Sprintf("proxysvc: device %q not freshly attested: %s", e.DeviceID, e.Detail)
}

// Unwrap classifies the verdict as the chain's definitive stale sentinel.
func (e *ErrDeviceNotAttested) Unwrap() error { return proxy.ErrAttestationStale }

// ErrAttestationQueryFailed is the indeterminate attestation-gate outcome: a
// platformd query failed, so the device's attestation state could not be
// established. The auth chain maps it to "attestation_unavailable" (deny).
type ErrAttestationQueryFailed struct {
	// DeviceID is the attestation host identifier queried.
	DeviceID string
	// Cause is the underlying query error.
	Cause error
}

// Error implements the error interface.
func (e *ErrAttestationQueryFailed) Error() string {
	return fmt.Sprintf("proxysvc: attestation query for device %q failed: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrAttestationQueryFailed) Unwrap() error { return e.Cause }

// ErrTokenAuthConfig indicates the token-auth section is missing or carries
// an invalid required field.
type ErrTokenAuthConfig struct {
	// Field is the offending configuration field.
	Field string
	// Reason describes why the value was rejected.
	Reason string
}

// Error implements the error interface.
func (e *ErrTokenAuthConfig) Error() string {
	return fmt.Sprintf("proxysvc: token-auth configuration invalid: %s: %s", e.Field, e.Reason)
}

// ErrNilTokenRequest is returned when the token authenticator is called
// without a request.
type ErrNilTokenRequest struct{}

// Error implements the error interface.
func (e *ErrNilTokenRequest) Error() string {
	return "proxysvc: nil token auth request"
}

// ErrBearerNotAllowed is returned when a token is presented without a DPoP
// proof while the token-auth section rejects plain bearers
// (allow-bearer: false, the default).
type ErrBearerNotAllowed struct{}

// Error implements the error interface.
func (e *ErrBearerNotAllowed) Error() string {
	return "proxysvc: DPoP proof required: bearer tokens are not accepted"
}

// ErrScopeDenied is returned when a validated token lacks a required scope.
// It wraps proxy.ErrTokenScopeDenied so the auth chain maps it to the
// "token_scope_denied" deny reason.
type ErrScopeDenied struct {
	// Scope is the required scope the token was not granted.
	Scope string
}

// Error implements the error interface.
func (e *ErrScopeDenied) Error() string {
	return fmt.Sprintf("proxysvc: token missing required scope %q", e.Scope)
}

// Unwrap classifies the denial as the chain's scope-denied sentinel.
func (e *ErrScopeDenied) Unwrap() error { return proxy.ErrTokenScopeDenied }

// ErrOPADisabled is returned when an OPAEvaluator is requested for a
// disabled opa configuration section.
type ErrOPADisabled struct{}

// Error implements the error interface.
func (e *ErrOPADisabled) Error() string {
	return "proxysvc: opa section is disabled in configuration"
}

// ErrAuditConfig indicates the audit section is missing or carries an
// invalid required field.
type ErrAuditConfig struct {
	// Field is the offending configuration field.
	Field string
	// Reason describes why the value was rejected.
	Reason string
}

// Error implements the error interface.
func (e *ErrAuditConfig) Error() string {
	return fmt.Sprintf("proxysvc: audit configuration invalid: %s: %s", e.Field, e.Reason)
}

// ErrNilAuditClient is returned when an SDKAuditSink is constructed
// without an audit client, or when the quicbaas SDK IAM audit client
// cannot be resolved from a dialed connection.
type ErrNilAuditClient struct{}

// Error implements the error interface.
func (e *ErrNilAuditClient) Error() string {
	return "proxysvc: nil audit client"
}

// ErrAuditDialFailed is returned by the lazy audit client when the SDK
// connection to quicbaasd cannot be established. The sink treats it as
// transient: it logs a warning and drops the event (fail open — the
// proxy data path never blocks on the audit plane).
type ErrAuditDialFailed struct {
	// Cause is the underlying connection error.
	Cause error
}

// Error implements the error interface.
func (e *ErrAuditDialFailed) Error() string {
	return fmt.Sprintf("proxysvc: dialing quicbaasd audit client: %v", e.Cause)
}

// Unwrap returns the underlying error.
func (e *ErrAuditDialFailed) Unwrap() error { return e.Cause }
