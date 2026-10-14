package vpn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/manifest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vpn/agent"
)

// agentFactory builds the client agent that trusts roots for the gateway's
// admission listener (nil: the system pool), presents device, which is nil
// for the verbs that contact no gateway, and brings up planes.
type agentFactory func(roots *x509.CertPool, device agent.Device, planes []agent.DataPlane) (*agent.Agent, error)

// newClientAgent is replaced in tests.
var newClientAgent agentFactory = func(roots *x509.CertPool, device agent.Device, planes []agent.DataPlane) (*agent.Agent, error) {
	return agent.New(agent.Deps{
		Device:     device,
		Posture:    agent.NewHostPosture(app.Version),
		DataPlanes: planes,
		State:      agent.NewFileStateStore(""),
		Dial:       agent.DialHTTPGateway(roots),
	})
}

// clientDataPlanes are the data planes this build can bring up for device.
// A kernel plane outlives the command; MASQUE's TUN lives only as long as
// the process holding it, so it is offered only when held is set: by connect
// --foreground, and by disconnect and renew, which must end a MASQUE lease
// the foreground process holds (its Down is a no-op there).
func clientDataPlanes(roots *x509.CertPool, device agent.Device, held bool) []agent.DataPlane {
	planes := kernelDataPlanes()
	if held {
		planes = append(planes, agent.NewMASQUEPlane(device.Certificate, roots, nil))
	}
	return planes
}

// hostDevice is this host's device identity, held open for one verb.
type hostDevice interface {
	agent.Device
	Close() error
}

// openHostDevice opens this host's TPM device identity. It is replaced in
// tests.
var openHostDevice = func(opts agent.HostDeviceOptions) (hostDevice, error) {
	device, err := agent.OpenHostDevice(opts)
	if err != nil {
		return nil, err
	}
	return device, nil
}

// unopenedDevice stands in for a device identity that could not be opened,
// so disconnect still tears the local data plane down; every use of it
// reports why it could not be opened.
type unopenedDevice struct{ err error }

func (d unopenedDevice) ID() string                            { return "" }
func (d unopenedDevice) Certificate() (tls.Certificate, error) { return tls.Certificate{}, d.err }
func (d unopenedDevice) Quote(context.Context, []byte) (*manifest.HostAttestation, error) {
	return nil, d.err
}
func (d unopenedDevice) Close() error { return nil }

// connectOptions are the flags of vpn connect.
type connectOptions struct {
	gateway    string
	deviceID   string
	idevidCert string
	dataPlane  string
	factor     string
	zones      []string
	caFile     string
	foreground bool
}

// idevidCertUsage is the --idevid-cert help shared by connect and disconnect.
const idevidCertUsage = "PEM IDevID certificate chain, leaf first (default: the TPM's NV index; " +
	"export one with platformctl tpm idevid certificate -o json)"

func newConnectCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var opts connectOptions
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect this device to a gateway's remote-access VPN",
		Long: `Run the admission against a gateway (device identity, TPM quote, posture
report, person factor) and bring the leased data plane up.

The device identity is this host's TPM: the IDevID key signs the mTLS
handshake and the attestation key quotes the PCRs, opened from the tpm
section of the platform configuration.

The data plane is the one --data-plane names, or else the first the gateway
offers that this build has: WireGuard, a kernel interface (vpn-wg0) that
stays up after the command exits, or MASQUE CONNECT-IP, a TUN (vpn-masque0)
that lives only as long as the command, so MASQUE needs --foreground. A FIPS
build has no WireGuard plane.

With --foreground the command stays running and keeps the lease alive: each
time the lease's renewal opens it presents a fresh quote and posture report.
A refusal tears the data plane down and exits with the refusal's code; a
renewal that fails otherwise is retried until the lease expires. SIGINT or
SIGTERM disconnects and exits 0.

Exit codes: 0 connected; 4 refused (the reason class is printed); 5 posture
violation (the failed rules are listed); 1 any other failure, including a
host with no TPM device identity.

Examples:
  platformctl vpn connect --gateway gw.example.com:4433 --device-id laptop-1 --factor fido2
  platformctl vpn connect --gateway gw.example.com:4433 --device-id laptop-1 --idevid-cert idevid.pem --ca-file gw-ca.pem --zones management
  platformctl vpn connect --gateway gw.example.com:4433 --device-id laptop-1 --idevid-cert idevid.pem --foreground
  platformctl vpn connect --gateway gw.example.com:4433 --device-id laptop-1 --data-plane masque --foreground`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConnect(getFlags(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.gateway, "gateway", "", "admission listener of the gateway, host:port (required)")
	cmd.Flags().StringVar(&opts.deviceID, "device-id", "", "this device's id in the gateway's device registry (required)")
	cmd.Flags().StringVar(&opts.idevidCert, "idevid-cert", "", idevidCertUsage)
	cmd.Flags().StringVar(&opts.dataPlane, "data-plane", "", "wireguard or masque; masque needs --foreground (default: the gateway's preference)")
	cmd.Flags().StringVar(&opts.factor, "factor", "", "person factor to present: fido2 or piv")
	cmd.Flags().StringSliceVar(&opts.zones, "zones", nil, "zones to request (default: every zone the peer may reach)")
	cmd.Flags().StringVar(&opts.caFile, "ca-file", "", "PEM roots the gateway's certificate chains to (default: the system pool)")
	cmd.Flags().BoolVar(&opts.foreground, "foreground", false, "stay running and renew the lease until interrupted")
	markRequired(cmd, "gateway")
	markRequired(cmd, "device-id")
	return cmd
}

func newDisconnectCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var caFile, idevidCert string
	cmd := &cobra.Command{
		Use:   "disconnect",
		Short: "Revoke this device's lease and tear the data plane down",
		Long: `Revoke the lease at the gateway that issued it and bring the data plane
down. The revoke is made over mTLS with this host's TPM device identity. The
local lease is removed even when the gateway cannot be reached or the TPM
cannot be opened; the gateway then lets the lease expire.

Exit codes: 0 disconnected; 6 not connected; 1 any other failure.

Examples:
  platformctl vpn disconnect`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDisconnect(getFlags(), caFile, idevidCert)
		},
	}
	cmd.Flags().StringVar(&caFile, "ca-file", "", "PEM roots the gateway's certificate chains to (default: the system pool)")
	cmd.Flags().StringVar(&idevidCert, "idevid-cert", "", idevidCertUsage)
	return cmd
}

func newLeaseCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "lease",
		Short: "Show the lease this device holds",
		Long: `Show the lease this device holds: its id, address, zones, expiry and the
time of the next re-attestation. It reads local state and contacts no gateway.

Exit codes: 0 connected; 6 not connected; 1 any other failure.

Examples:
  platformctl vpn lease
  platformctl vpn lease -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLease(getFlags())
		},
	}
}

func newRenewCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var caFile, idevidCert string
	cmd := &cobra.Command{
		Use:   "renew",
		Short: "Renew this device's lease now",
		Long: `Renew the lease now with a fresh TPM quote, posture report and, when connect
presented one, person factor. A refusal that ends the lease (a posture
violation, a failed attestation, an expired lease) tears the data plane down;
a renewal the gateway does not accept yet keeps the lease.

Exit codes: 0 renewed; 4 refused (the reason class is printed); 5 posture
violation (the failed rules are listed); 6 not connected; 1 any other failure.

Examples:
  platformctl vpn renew --idevid-cert idevid.pem
  platformctl vpn renew --idevid-cert idevid.pem -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRenew(getFlags(), caFile, idevidCert)
		},
	}
	cmd.Flags().StringVar(&caFile, "ca-file", "", "PEM roots the gateway's certificate chains to (default: the system pool)")
	cmd.Flags().StringVar(&idevidCert, "idevid-cert", "", idevidCertUsage)
	return cmd
}

func runConnect(flags *cli.CommonFlags, opts connectOptions) (err error) {
	if gwvpn.DataPlaneKind(opts.dataPlane) == gwvpn.DataPlaneMASQUE && !opts.foreground {
		return &ErrForegroundRequired{DataPlane: opts.dataPlane}
	}
	roots, err := loadGatewayRoots(opts.caFile)
	if err != nil {
		return err
	}
	device, err := openHostDevice(agent.HostDeviceOptions{ID: opts.deviceID, CertFile: opts.idevidCert})
	if err != nil {
		return agentError("failed to connect to the VPN", err)
	}
	defer func() { err = errors.Join(err, device.Close()) }()
	a, err := clientAgent(roots, device, clientDataPlanes(roots, device, opts.foreground))
	if err != nil {
		return err
	}
	ctx, cancel := newCLIContext()
	defer cancel()
	st, err := a.Connect(ctx, agent.ConnectOptions{
		Gateway:   opts.gateway,
		DataPlane: gwvpn.DataPlaneKind(opts.dataPlane),
		Factor:    gwvpn.PersonFactorKind(opts.factor),
		Zones:     opts.zones,
	})
	if err != nil {
		return agentError("failed to connect to the VPN", err)
	}
	if err := printState(flags, st); err != nil || !opts.foreground {
		return err
	}
	return holdLease(a)
}

// foregroundContext is the context connect --foreground holds its lease
// under: it ends on SIGINT or SIGTERM.
var foregroundContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// holdLease renews a's lease until interrupted and then disconnects. A
// renewal that ends the lease returns with its exit code.
func holdLease(a *agent.Agent) error {
	ctx, stop := foregroundContext()
	defer stop()
	if err := a.KeepAlive(ctx); err != nil {
		return agentError("the VPN lease ended", err)
	}
	disconnectCtx, cancel := newCLIContext()
	defer cancel()
	if _, err := a.Disconnect(disconnectCtx); err != nil {
		return agentError("failed to disconnect from the VPN", err)
	}
	return nil
}

func runDisconnect(flags *cli.CommonFlags, caFile, idevidCert string) (err error) {
	roots, err := loadGatewayRoots(caFile)
	if err != nil {
		return err
	}
	// The device id is the lease's; only the certificate is presented.
	device, err := openHostDevice(agent.HostDeviceOptions{CertFile: idevidCert})
	if err != nil {
		device = unopenedDevice{err: err}
	}
	defer func() { err = errors.Join(err, device.Close()) }()
	a, err := clientAgent(roots, device, clientDataPlanes(roots, device, true))
	if err != nil {
		return err
	}
	ctx, cancel := newCLIContext()
	defer cancel()
	st, err := a.Disconnect(ctx)
	if err != nil {
		return agentError("failed to disconnect from the VPN", err)
	}
	if isStructuredOutput(flags) {
		return output(flags, st)
	}
	table := cli.NewTableData("LEASE", "GATEWAY", "STATUS")
	table.AddRow(string(st.Lease.ID), st.Gateway, "disconnected")
	return output(flags, *table)
}

func runRenew(flags *cli.CommonFlags, caFile, idevidCert string) (err error) {
	roots, err := loadGatewayRoots(caFile)
	if err != nil {
		return err
	}
	// The device id is the lease's; only the certificate is presented.
	device, err := openHostDevice(agent.HostDeviceOptions{CertFile: idevidCert})
	if err != nil {
		return agentError("failed to renew the VPN lease", err)
	}
	defer func() { err = errors.Join(err, device.Close()) }()
	a, err := clientAgent(roots, device, clientDataPlanes(roots, device, true))
	if err != nil {
		return err
	}
	ctx, cancel := newCLIContext()
	defer cancel()
	st, err := a.Renew(ctx)
	if err != nil {
		return agentError("failed to renew the VPN lease", err)
	}
	return printState(flags, st)
}

func runLease(flags *cli.CommonFlags) error {
	a, err := clientAgent(nil, nil, nil)
	if err != nil {
		return err
	}
	st, err := a.Lease()
	if err != nil {
		return agentError("failed to read the VPN lease", err)
	}
	return printState(flags, st)
}

func newPostureCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "posture",
		Short: "Print the posture report connect would send",
		Long: `Print the posture report connect sends with the admission: Secure Boot,
IMA and disk-encryption state, the agent version and the OS and kernel
releases. The gateway's posture policy judges exactly this report, so it is
the fastest way to see why a posture rule fails. It contacts no gateway and
needs no TPM.

Exit codes: 0 the report was collected; 1 any failure.

Examples:
  platformctl vpn posture
  platformctl vpn posture -o json`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPosture(getFlags())
		},
	}
}

func runPosture(flags *cli.CommonFlags) error {
	a, err := clientAgent(nil, nil, nil)
	if err != nil {
		return err
	}
	ctx, cancel := newCLIContext()
	defer cancel()
	report, err := a.Posture(ctx)
	if err != nil {
		return agentError("failed to collect the VPN posture", err)
	}
	if isStructuredOutput(flags) {
		return output(flags, report)
	}
	table := cli.NewTableData("CHECK", "VALUE")
	table.AddRow("secure_boot.available", strconv.FormatBool(report.SecureBoot.Available))
	table.AddRow("secure_boot.enabled", strconv.FormatBool(report.SecureBoot.Enabled))
	table.AddRow("secure_boot.setup_mode", strconv.FormatBool(report.SecureBoot.SetupMode))
	table.AddRow("ima.available", strconv.FormatBool(report.IMA.Available))
	table.AddRow("ima.enabled", strconv.FormatBool(report.IMA.Enabled))
	table.AddRow("ima.policy_loaded", strconv.FormatBool(report.IMA.PolicyLoaded))
	table.AddRow("fde.root_encrypted", strconv.FormatBool(report.FDE.RootEncrypted))
	table.AddRow("agent_version", report.AgentVersion)
	table.AddRow("os_release", report.OSRelease)
	table.AddRow("kernel_release", report.KernelRelease)
	table.AddRow("collected_at", report.CollectedAt.UTC().Format(time.RFC3339))
	return output(flags, *table)
}

// clientAgent builds the agent over roots, device and planes, wrapping a
// failure.
func clientAgent(roots *x509.CertPool, device agent.Device, planes []agent.DataPlane) (*agent.Agent, error) {
	a, err := newClientAgent(roots, device, planes)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to start the VPN client agent", Err: err}
	}
	return a, nil
}

// loadGatewayRoots reads a PEM bundle; an empty path selects the system pool.
func loadGatewayRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, cli.ErrTLSCACertLoadFailed{Path: path, Err: err}
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, cli.ErrTLSCACertInvalid{Path: path}
	}
	return pool, nil
}

// agentError wraps an agent failure with the exit code cli.md documents.
func agentError(msg string, err error) error {
	return &cli.ExitError{Code: agent.ExitCode(err), Err: &WrappedError{Msg: msg, Err: err}}
}

func printState(flags *cli.CommonFlags, st *agent.State) error {
	if isStructuredOutput(flags) {
		return output(flags, st)
	}
	table := cli.NewTableData("LEASE", "GATEWAY", "ADDRESS", "ZONES", "DATA PLANE", "INTERFACE", "EXPIRES", "RENEWS")
	table.AddRow(
		string(st.Lease.ID),
		st.Gateway,
		st.Lease.Address,
		strings.Join(st.Lease.Zones, ","),
		string(st.Lease.DataPlane),
		st.Session.Interface,
		formatUnix(st.Lease.ExpiresAtUnix),
		formatUnix(st.Lease.RenewAtUnix),
	)
	return output(flags, *table)
}
