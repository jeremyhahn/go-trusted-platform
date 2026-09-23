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

package commands

import (
	"errors"
	"strconv"
)

var (
	// ErrMissingBGPConfig is returned when BGP configuration is required but not provided.
	ErrMissingBGPConfig = errors.New("gatewayd: missing BGP configuration")

	// ErrGatewayStartFailed is returned when the gateway fails to start.
	ErrGatewayStartFailed = errors.New("gatewayd: failed to start gateway")

	// ErrGatewayShutdownFailed is returned when the gateway fails to shutdown gracefully.
	ErrGatewayShutdownFailed = errors.New("gatewayd: failed to shutdown gateway gracefully")

	// ErrConfigLoadFailed is returned when the gateway configuration cannot be loaded.
	ErrConfigLoadFailed = errors.New("gatewayd: failed to load configuration")
)

// ErrNothingEnabled is returned when neither the gateway nor the proxy
// section enables any service.
var ErrNothingEnabled = errors.New("gatewayd: no services enabled in configuration")

// ErrGatewayDisabled is returned when the gateway section is explicitly
// disabled while the proxy section is enabled; the proxy service runs
// inside the gateway node and requires it.
var ErrGatewayDisabled = errors.New("gatewayd: gateway section disabled; the proxy service requires an enabled gateway")

// ErrPlatformAnchorRequiredForGRPC is returned when the platformd connection
// uses the grpc protocol without `platform-ca-file:`, the platform anchor that
// verifies platformd's certificate.
var ErrPlatformAnchorRequiredForGRPC = errors.New("gatewayd: platformd grpc protocol requires platform-ca-file: (the platform CA bundle that verifies platformd)")

// ErrConfigSection wraps a configuration-section unmarshal failure.
type ErrConfigSection struct {
	// Section is the top-level configuration key.
	Section string
	// Cause is the underlying decode error.
	Cause error
}

// Error implements the error interface.
func (e *ErrConfigSection) Error() string {
	return "gatewayd: parsing configuration section " + e.Section + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrConfigSection) Unwrap() error { return e.Cause }

// ErrSDNOVSRequired is returned when the sdn: section is enabled without
// the ovs: subsection carrying the OVSDB socket and bridge.
var ErrSDNOVSRequired = errors.New("gatewayd: sdn: section enabled without an ovs: subsection")

// ErrSDNRequiredForService is returned when a datapath service section
// (firewall, NAT, load balancer) is enabled without the sdn: section that
// supplies its OVS runtime.
type ErrSDNRequiredForService struct {
	// Service is the datapath service that needs the runtime.
	Service string
}

// Error implements the error interface.
func (e *ErrSDNRequiredForService) Error() string {
	return "gatewayd: service " + e.Service + " requires an enabled sdn: section with an ovs: subsection"
}

// ErrNoZoneNetworks is returned when a zone-matrix service (firewall,
// NAT) is enabled but the sdn: section's networks produce no per-zone
// VLAN summaries — the compiled matrix would contain no flows and the
// service would pass all cross-zone traffic while reporting healthy.
type ErrNoZoneNetworks struct {
	// Service is the zone-matrix service that would enforce nothing.
	Service string
}

// Error implements the error interface.
func (e *ErrNoZoneNetworks) Error() string {
	return "gatewayd: service " + e.Service + " requires sdn: networks entries with VLANs bound to zones; an empty zone matrix would enforce nothing"
}

// ErrOVSClientInit wraps an OVS client or flow-controller construction
// failure.
type ErrOVSClientInit struct {
	// Socket is the configured OVSDB socket path.
	Socket string
	// Cause is the underlying error.
	Cause error
}

// Error implements the error interface.
func (e *ErrOVSClientInit) Error() string {
	return "gatewayd: initializing OVS client for " + e.Socket + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrOVSClientInit) Unwrap() error { return e.Cause }

// ErrOVSConnectFailed wraps an OVSDB connection failure.
type ErrOVSConnectFailed struct {
	// Socket is the configured OVSDB socket path.
	Socket string
	// Cause is the underlying error.
	Cause error
}

// Error implements the error interface.
func (e *ErrOVSConnectFailed) Error() string {
	return "gatewayd: connecting to OVSDB at " + e.Socket + ": " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrOVSConnectFailed) Unwrap() error { return e.Cause }

// ErrBridgeNotProvisioned is returned when the configured OVS bridge does
// not exist. gatewayd programs flows on a bridge provisioned by the
// node's installer or by platformd on a gateway-role node; it does not
// create bridges.
type ErrBridgeNotProvisioned struct {
	// Bridge is the configured bridge name.
	Bridge string
	// Cause is the underlying lookup error.
	Cause error
}

// Error implements the error interface.
func (e *ErrBridgeNotProvisioned) Error() string {
	return "gatewayd: OVS bridge " + e.Bridge + " is not provisioned: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrBridgeNotProvisioned) Unwrap() error { return e.Cause }

// ErrCAFileLoadFailed wraps a failure loading the control-plane
// verification CA bundle.
type ErrCAFileLoadFailed struct {
	// Path is the configured ca-file path.
	Path string
	// Cause is the underlying read error; nil when the file parsed to an
	// empty pool.
	Cause error
}

// Error implements the error interface.
func (e *ErrCAFileLoadFailed) Error() string {
	msg := "gatewayd: loading control-plane CA bundle " + e.Path
	if e.Cause != nil {
		return msg + ": " + e.Cause.Error()
	}
	return msg + ": no certificates found"
}

// Unwrap returns the underlying error.
func (e *ErrCAFileLoadFailed) Unwrap() error { return e.Cause }

// ErrGatewayIDCertMismatch reports that the resolved gateway ID is not
// the identity the control plane will see. The CP binds a reported
// gateway_id to the Common Name of the mTLS client certificate, so this
// configuration could only ever produce 403s on every telemetry push and
// every desired-config fetch.
type ErrGatewayIDCertMismatch struct {
	// GatewayID is the resolved control-plane gateway ID (the
	// control-plane section's gateway-id, or the gateway node ID).
	GatewayID string
	// CertCN is the Subject Common Name of the configured client
	// certificate — the identity the control plane will actually bind to.
	CertCN string
	// CertFile is the configured cert-file path.
	CertFile string
}

// Error implements the error interface.
func (e *ErrGatewayIDCertMismatch) Error() string {
	return "gatewayd: control-plane gateway-id " + strconv.Quote(e.GatewayID) +
		" does not match the client certificate Common Name " + strconv.Quote(e.CertCN) +
		" in " + e.CertFile +
		"; the control plane binds reported telemetry to the certificate identity"
}

// ErrClientCertEmpty reports a loaded keypair that carries no
// certificate to read an identity from.
var ErrClientCertEmpty = errors.New(
	"gatewayd: control-plane client keypair contains no certificate")

// ErrGatewayIDNotReportable reports a control-plane identity the control
// plane will never accept, whatever certificate backs it. The CP binds
// reported telemetry to the client certificate's Common Name and refuses
// a Common Name with leading or trailing whitespace outright, so an
// identity of that shape can only ever produce 401s — including when the
// certificate's own CN matches it exactly, which a plain CN comparison
// would wave through.
type ErrGatewayIDNotReportable struct {
	// GatewayID is the resolved control-plane gateway ID.
	GatewayID string
}

// Error implements the error interface.
func (e *ErrGatewayIDNotReportable) Error() string {
	return "gatewayd: control-plane gateway-id " + strconv.Quote(e.GatewayID) +
		" has leading or trailing whitespace; the control plane binds telemetry to the" +
		" certificate Common Name verbatim and refuses a padded identity"
}

// ErrTOFUPinDirUnset reports that a trust class lists the tofu strategy but
// gatewayd has no --data-dir to persist pins under. Failing here is
// deliberate: the alternative is an in-memory store that silently re-trusts
// every BMC after a restart, which is not what the strategy promises.
type ErrTOFUPinDirUnset struct{}

func (e *ErrTOFUPinDirUnset) Error() string {
	return "trust: the tofu strategy is configured but --data-dir is empty, so TOFU pins have nowhere durable to live"
}

// ErrTOFUPinDirUnusable reports that gatewayd's TOFU pin directory could not
// be created or opened.
type ErrTOFUPinDirUnusable struct {
	Dir   string
	Cause error
}

func (e *ErrTOFUPinDirUnusable) Error() string {
	return "trust: TOFU pin store unusable at " + e.Dir + ": " + e.Cause.Error()
}

func (e *ErrTOFUPinDirUnusable) Unwrap() error { return e.Cause }
