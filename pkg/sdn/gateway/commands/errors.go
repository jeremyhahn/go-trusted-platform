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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
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
// NAT) is enabled but the network plan yields no per-zone VLAN summaries —
// the compiled matrix would contain no flows and the service would pass all
// cross-zone traffic while reporting healthy. A validated sdn.environment
// always numbers the required zones; the check stays as a fail-closed
// invariant of assembly.
type ErrNoZoneNetworks struct {
	// Service is the zone-matrix service that would enforce nothing.
	Service string
}

// Error implements the error interface.
func (e *ErrNoZoneNetworks) Error() string {
	return "gatewayd: service " + e.Service + " requires sdn.environment so every zone has a VLAN; an empty zone matrix would enforce nothing"
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

// ErrOverlayPlatformRecordMissing reports that platformd holds no record an
// overlay admission asked for. It matches gateway.ErrOverlayRecordNotFound, so
// the admitter denies the VTEP instead of treating the miss as an outage.
type ErrOverlayPlatformRecordMissing struct {
	// Record names what was looked up, such as "device 42".
	Record string
	// Cause is the platformd NotFound error.
	Cause error
}

// Error implements the error interface.
func (e *ErrOverlayPlatformRecordMissing) Error() string {
	return "gatewayd: platformd has no " + e.Record + ": " + e.Cause.Error()
}

// Unwrap returns gateway.ErrOverlayRecordNotFound and the platformd error.
func (e *ErrOverlayPlatformRecordMissing) Unwrap() []error {
	return []error{gateway.ErrOverlayRecordNotFound, e.Cause}
}

// ErrOverlayIPAMAllocation reports a fabric allocation platformd listed that
// overlay admission cannot index: its address does not parse or its status is
// missing or unknown. The status is never assumed active, because an
// allocation IPAM expired for inactivity is told apart only by it.
type ErrOverlayIPAMAllocation struct {
	// IP is the allocation address as platformd listed it.
	IP string
	// Reason says what is wrong with the allocation.
	Reason string
	// Cause is the underlying parse error, if any.
	Cause error
}

// Error implements the error interface.
func (e *ErrOverlayIPAMAllocation) Error() string {
	msg := "gatewayd: platformd listed fabric allocation " + strconv.Quote(e.IP) + ": " + e.Reason
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Unwrap returns the underlying parse error.
func (e *ErrOverlayIPAMAllocation) Unwrap() error {
	return e.Cause
}

// ErrServiceConfigUnreadable is returned when a supervised child cannot read
// the gatewayd configuration as its service account. The child reads it only
// after dropping its privileges, so the file must be readable by that
// account.
type ErrServiceConfigUnreadable struct {
	// Process is the supervised process that could not read it.
	Process string
	// Cause is the read error.
	Cause error
}

// Error implements the error interface.
func (e *ErrServiceConfigUnreadable) Error() string {
	return "gatewayd service " + e.Process + ": reading the configuration as the service account: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrServiceConfigUnreadable) Unwrap() error { return e.Cause }

// ErrStaleTunnelSweep is returned when serve, starting with no tunnel
// configured, cannot remove the ESP state a killed predecessor's tunnels
// left behind.
type ErrStaleTunnelSweep struct {
	// Cause is the tunnel manager's sweep failure.
	Cause error
}

// Error implements the error interface.
func (e *ErrStaleTunnelSweep) Error() string {
	return "gatewayd: cannot remove the stale tunnel state of a predecessor: " + e.Cause.Error()
}

// Unwrap returns the sweep failure.
func (e *ErrStaleTunnelSweep) Unwrap() error { return e.Cause }

// ErrTunnelsRecord is returned when serve cannot read, write or remove the
// record under --data-dir that tunnels ran, which decides whether a start
// without tunnels must sweep their stale state.
type ErrTunnelsRecord struct {
	// Path is the record file.
	Path string
	// Cause is the filesystem failure.
	Cause error
}

// Error implements the error interface.
func (e *ErrTunnelsRecord) Error() string {
	return "gatewayd: tunnels record " + e.Path + " unusable: " + e.Cause.Error()
}

// Unwrap returns the filesystem failure.
func (e *ErrTunnelsRecord) Unwrap() error { return e.Cause }

// ErrProcessHostsNothing is returned when a supervised child's configuration
// enables none of the services its process hosts, so there is nothing for it
// to run.
type ErrProcessHostsNothing struct {
	// Process is the supervised process.
	Process string
}

// Error implements the error interface.
func (e *ErrProcessHostsNothing) Error() string {
	return "gatewayd service " + e.Process + ": the configuration enables none of its services"
}

// ErrServiceIPCFailed is returned when a supervised child's control service
// stops serving while the child runs; without it the supervisor can neither
// read the child's health nor reach its services.
type ErrServiceIPCFailed struct {
	// Process is the supervised process.
	Process string
	// Cause is the serve error.
	Cause error
}

// Error implements the error interface.
func (e *ErrServiceIPCFailed) Error() string {
	return "gatewayd service " + e.Process + ": control service stopped: " + e.Cause.Error()
}

// Unwrap returns the underlying error.
func (e *ErrServiceIPCFailed) Unwrap() error { return e.Cause }
