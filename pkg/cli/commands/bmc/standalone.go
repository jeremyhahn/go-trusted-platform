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

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// standaloneBMCFlags holds the flags that select and configure the standalone
// (no-daemon) BMC connection mode. When --bmc-host is set the CLI talks
// directly to a BMC over IPMI or Redfish without going through platformd.
// There is no audit log and no profile persistence in this mode; it is
// intended for bootstrap and one-off operations.
type standaloneBMCFlags struct {
	host         string
	port         int
	user         string
	password     string
	passwordFile string
	protocol     string
	bmcPin       string // --bmc-pin <hex-spki-sha256>: pin the BMC's leaf SPKI hash
	bmcCAFile    string // --bmc-ca-file <path>: trust a custom CA bundle PEM file

	// solInstance is the explicit IPMI 2.0 SOL payload instance override
	// for the bmc console subcommand. Zero (the flag default) means
	// "consult the quirk registry, fall back to 0x01". Permitted values
	// per IPMI 2.0 Table 24-2: 0x01 - 0x0F.
	solInstance uint8
}

// addStandaloneFlags registers the standalone BMC flag set on the given cobra
// command. It is safe to call alongside the daemon-mode --server-url and
// --profile-id flags; resolveBMCClient enforces mutual exclusion at runtime.
func addStandaloneFlags(cmd *cobra.Command, f *standaloneBMCFlags) {
	cmd.Flags().StringVar(&f.host, "bmc-host", "",
		"Standalone mode: BMC IP/hostname (mutually exclusive with --server-url). "+
			"Talks directly to the BMC without going through platformd. No audit log, "+
			"no profile persistence. Use for bootstrap and one-off operations.")
	cmd.Flags().IntVar(&f.port, "bmc-port", 0,
		"BMC port (default: 443 for redfish, 623 for ipmi)")
	cmd.Flags().StringVar(&f.user, "bmc-user", "",
		"BMC username (standalone mode)")
	cmd.Flags().StringVar(&f.password, "bmc-pass", "",
		"BMC password (standalone mode; prefer --bmc-pass-file)")
	cmd.Flags().StringVar(&f.passwordFile, "bmc-pass-file", "",
		"Path to file containing BMC password (mode 0600 or stricter)")
	cmd.Flags().StringVar(&f.protocol, "bmc-protocol", "auto",
		"BMC protocol: redfish | ipmi | auto")
	cmd.Flags().StringVar(&f.bmcPin, "bmc-pin", "",
		"Hex-encoded SHA-256 SPKI fingerprint of the BMC TLS leaf certificate. "+
			"When set, the connection is verified against this pin. "+
			"Obtain via: platformctl bmc cert get --bmc-host <ip> (interactive mode).")
	cmd.Flags().StringVar(&f.bmcCAFile, "bmc-ca-file", "",
		"Path to a PEM CA bundle file used to verify the BMC TLS certificate. "+
			"Mutually exclusive with --bmc-pin.")
}

// modeStandalone reports whether the user supplied --bmc-host.
func (f *standaloneBMCFlags) isSet() bool {
	return f.host != ""
}

// resolveBMCClient decides which mode the user requested and either builds a
// direct bmc.Client (standalone) or returns an error directing the caller to
// use the existing daemon-mode HTTP path. It enforces mutual exclusion of
// standalone and daemon flag sets.
//
// Daemon-path subcommands continue to use raw HTTP against platformd; the
// caller is responsible for branching on standalone.isSet() before invoking
// resolveBMCClient.
func resolveBMCClient(
	ctx context.Context,
	standalone *standaloneBMCFlags,
	logger *slog.Logger,
) (bmc.Client, error) {
	if !standalone.isSet() {
		return nil, ErrBMCNoMode{}
	}
	return newStandaloneClient(ctx, standalone, logger)
}

// checkModeConflict returns an error when the caller supplied both standalone
// and daemon flag sets. It is invoked from each subcommand's RunE before
// dispatching on mode.
func checkModeConflict(standalone *standaloneBMCFlags, daemon *bmcFlags) error {
	standaloneSet := standalone.isSet()
	daemonSet := daemon.serverURL != "" || daemon.profileID != ""
	if standaloneSet && daemonSet {
		return ErrBMCFlagConflict{Fields: []string{"--bmc-host", "--server-url/--profile-id"}}
	}
	if !standaloneSet && !daemonSet {
		return ErrBMCNoMode{}
	}
	return nil
}

// newStandaloneClient builds a direct bmc.Client from the standalone flag set.
// It loads the password (file precedence enforced), auto-detects the protocol
// when requested, and wires a TLSProvider from the trust flags.
func newStandaloneClient(ctx context.Context, f *standaloneBMCFlags, logger *slog.Logger) (bmc.Client, error) {
	pw, err := loadStandalonePassword(f)
	if err != nil {
		return nil, err
	}

	if f.user == "" {
		return nil, ErrBMCMissingCredential{Field: "username (set --bmc-user)"}
	}

	proto := bmc.Protocol(f.protocol)
	switch f.protocol {
	case "", "auto":
		detected := bmc.DetectProtocol(ctx, f.host, 5*time.Second)
		if detected == "" {
			return nil, ErrBMCStandaloneNotReachable{Host: f.host}
		}
		proto = detected
	case string(bmc.ProtocolIPMI), string(bmc.ProtocolRedfish):
		// explicit protocol; leave proto as set above
	default:
		return nil, ErrBMCInvalidProtocol{Value: f.protocol}
	}

	port := f.port
	if port == 0 {
		switch proto {
		case bmc.ProtocolRedfish:
			port = 443
		case bmc.ProtocolIPMI:
			port = 623
		}
	}

	// TLS provider resolution only applies to Redfish (HTTPS) connections.
	// IPMI 2.0 uses UDP/RMCP+ which does not use TLS. Any embedded Redfish
	// sub-connection from an IPMI client will use system roots when TLS is nil.
	var tlsProvider bmc.TLSProvider
	if proto == bmc.ProtocolRedfish {
		tlsProvider, err = standaloneTLSProvider(ctx, f, port)
		if err != nil {
			return nil, err
		}
	}

	cfg := &bmc.Config{
		Address:            f.host,
		Port:               port,
		Protocol:           proto,
		Username:           f.user,
		Password:           pw,
		TLS:                tlsProvider,
		SOLPayloadInstance: f.solInstance,
	}
	return newBMCClient(cfg, logger)
}

// standaloneTLSProvider builds a bmc.TLSProvider for the standalone connection
// from the trust flags. The resolution order is:
//
//  1. --bmc-pin <hex>: SPKI-pinned trust via trust.ClassBMC spki strategy.
//  2. --bmc-ca-file <path>: custom CA bundle via trust.ClassBMC ca-file strategy.
//  3. Neither flag set in an interactive terminal: capture-then-confirm. A
//     raw InsecureSkipVerify dial captures the peer certificate (no app data
//     is exchanged), its SPKI fingerprint is displayed, and the operator is
//     prompted for confirmation. After confirmation the connection is verified
//     via the SPKI-pin path.
//     See also: pkg/bootstrap/virtual_media.go fetchControlPlaneCABundle for
//     the documented pattern this is modelled on.
//  4. Neither flag set in a non-interactive session: ErrBMCNoPinOrCAFile.
//
// Passing both --bmc-pin and --bmc-ca-file is a conflict.
func standaloneTLSProvider(ctx context.Context, f *standaloneBMCFlags, httpsPort int) (bmc.TLSProvider, error) {
	if f.bmcPin != "" && f.bmcCAFile != "" {
		return nil, ErrBMCFlagConflict{Fields: []string{"--bmc-pin", "--bmc-ca-file"}}
	}

	if f.bmcPin != "" {
		return buildSPKIPinProvider(f.bmcPin)
	}

	if f.bmcCAFile != "" {
		return buildCAFileProvider(f.bmcCAFile)
	}

	// Neither pin nor CA file: capture-then-confirm when stdin is a terminal.
	if !isTerminal() {
		return nil, ErrBMCNoPinOrCAFile{}
	}

	pin, err := captureAndConfirmSPKI(ctx, f.host, httpsPort)
	if err != nil {
		return nil, err
	}
	return buildSPKIPinProvider(pin)
}

// buildSPKIPinProvider returns a TLSProvider that verifies the BMC leaf
// certificate against the given SPKI SHA-256 hex pin via the trust resolver's
// ClassBMC/spki strategy.
func buildSPKIPinProvider(pin string) (bmc.TLSProvider, error) {
	trustCfg := &trust.Config{
		BMC: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategySPKI},
			SPKI:       &trust.SPKIConfig{Pin: pin},
		},
	}
	resolver, err := trust.NewResolver(trustCfg, logging.NewFromSlog(standaloneLogger()))
	if err != nil {
		return nil, err
	}
	return &standaloneTrustProvider{resolver: resolver}, nil
}

// buildCAFileProvider returns a TLSProvider that verifies the BMC leaf
// certificate against the given CA bundle PEM file via the trust resolver's
// ClassBMC/ca-file strategy.
func buildCAFileProvider(caFile string) (bmc.TLSProvider, error) {
	trustCfg := &trust.Config{
		BMC: &trust.ScopeConfig{
			Strategies: []trust.Strategy{trust.StrategyCAFile},
			CAFile:     caFile,
		},
	}
	resolver, err := trust.NewResolver(trustCfg, logging.NewFromSlog(standaloneLogger()))
	if err != nil {
		return nil, err
	}
	return &standaloneTrustProvider{resolver: resolver}, nil
}

// standaloneTrustProvider adapts a trust.Resolver into a bmc.TLSProvider
// for the ClassBMC scope.
type standaloneTrustProvider struct {
	resolver trust.Resolver
}

func (p *standaloneTrustProvider) TLSConfig(ctx context.Context, endpoint string) (*tls.Config, error) {
	return p.resolver.TLSConfig(ctx, trust.ClassBMC, endpoint)
}

// captureAndConfirmSPKI performs a capture-then-confirm handshake:
//
//  1. Dial the BMC with InsecureSkipVerify to capture the peer certificate.
//     No application data is exchanged; the connection is closed immediately
//     after the handshake.
//  2. Display the certificate subject and SPKI SHA-256 fingerprint on stderr.
//  3. Prompt the operator to confirm on stdin.
//
// This follows the sanctioned capture-then-verify pattern documented in
// pkg/bootstrap/virtual_media.go. The InsecureSkipVerify dial is the
// ONLY permitted use of InsecureSkipVerify in standalone mode; app data
// is never sent before the pinned reconnect is made.
func captureAndConfirmSPKI(ctx context.Context, host string, port int) (string, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Step 1: capture-only dial — InsecureSkipVerify is intentional here.
	// This is the only call site in standalone mode. No app data is sent;
	// the connection is closed immediately after handshake for pin extraction.
	captureCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // capture-then-confirm: peer cert capture only, no app data exchanged; pinned reconnect follows
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, captureCfg)
	if err != nil {
		return "", ErrBMCCaptureDial{Host: addr, Cause: err}
	}
	certs := conn.ConnectionState().PeerCertificates
	conn.Close()

	if len(certs) == 0 {
		return "", ErrBMCNoPeerCert{Host: addr}
	}
	leaf := certs[0]

	// Compute SPKI SHA-256.
	spkiSum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(spkiSum[:])

	// Step 2: display cert info and prompt.
	fmt.Fprintf(os.Stderr, "\nBMC TLS certificate at %s:\n", addr)
	fmt.Fprintf(os.Stderr, "  Subject:    %s\n", leaf.Subject)
	fmt.Fprintf(os.Stderr, "  Issuer:     %s\n", leaf.Issuer)
	fmt.Fprintf(os.Stderr, "  Not After:  %s\n", leaf.NotAfter.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "  SPKI pin:   %s\n\n", pin)
	fmt.Fprintf(os.Stderr, "Do you trust this certificate? [yes/no]: ")

	// Step 3: read confirmation.
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	answer := strings.TrimSpace(strings.ToLower(scanner.Text()))
	if answer != "yes" && answer != "y" {
		return "", ErrBMCNoPinOrCAFile{}
	}

	fmt.Fprintf(os.Stderr, "\nAccepted. To skip this prompt in future, pass: --bmc-pin %s\n\n", pin)
	return pin, nil
}

// isTerminal reports whether os.Stdin is an interactive terminal.
func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// newBMCClient is the package-level constructor used by newStandaloneClient.
// Tests override it to inject a MockClient without going through the real
// IPMI/Redfish factories.
var newBMCClient = func(cfg *bmc.Config, logger *slog.Logger) (bmc.Client, error) {
	return bmc.NewDefaultClientFactory(logger).NewClient(cfg)
}

// loadStandalonePassword resolves the BMC password from either --bmc-pass or
// --bmc-pass-file. The two flags are mutually exclusive. When --bmc-pass-file
// is used the file mode must be 0600 or stricter and trailing whitespace is
// stripped from the contents.
func loadStandalonePassword(f *standaloneBMCFlags) (string, error) {
	if f.password != "" && f.passwordFile != "" {
		return "", ErrBMCFlagConflict{Fields: []string{"--bmc-pass", "--bmc-pass-file"}}
	}
	if f.password != "" {
		return f.password, nil
	}
	if f.passwordFile == "" {
		return "", ErrBMCMissingCredential{Field: "password (set --bmc-pass or --bmc-pass-file)"}
	}
	info, err := os.Stat(f.passwordFile)
	if err != nil {
		return "", ErrBMCPasswordFileUnreadable{Path: f.passwordFile, Cause: err}
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", ErrBMCInsecurePasswordFile{Path: f.passwordFile, Mode: info.Mode().Perm()}
	}
	raw, err := os.ReadFile(f.passwordFile)
	if err != nil {
		return "", ErrBMCPasswordFileUnreadable{Path: f.passwordFile, Cause: err}
	}
	return strings.TrimRight(string(raw), "\r\n \t"), nil
}

// standaloneLogger returns a discard-level slog.Logger suitable for the
// standalone CLI path. The CLI's primary output channel is stdout/stderr, not
// the structured log; verbose protocol logging would corrupt JSON output and
// confuse interactive users.
func standaloneLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// compile-time check: standaloneTrustProvider implements bmc.TLSProvider.
var _ bmc.TLSProvider = (*standaloneTrustProvider)(nil)
