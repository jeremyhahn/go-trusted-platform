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
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
)

// standaloneBMCFlags holds the flags that select and configure the standalone
// (no-daemon) BMC connection mode. When --bmc-host is set the CLI talks
// directly to a BMC over IPMI or Redfish without going through platformd.
// There is no audit log and no profile persistence in this mode; it is
// intended for bootstrap and one-off operations.
type standaloneBMCFlags struct {
	host          string
	port          int
	user          string
	password      string
	passwordFile  string
	protocol      string
	skipTLSVerify bool

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
	cmd.Flags().BoolVar(&f.skipTLSVerify, "bmc-skip-tls-verify", false,
		"Skip TLS verification (BMC self-signed certs)")
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
// when requested, and returns a configured client via the package-level
// newBMCClient hook (overridable in tests).
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

	cfg := &bmc.Config{
		Address:            f.host,
		Port:               port,
		Protocol:           proto,
		Username:           f.user,
		Password:           pw,
		SkipTLSVerify:      f.skipTLSVerify,
		SOLPayloadInstance: f.solInstance,
	}
	return newBMCClient(cfg, logger)
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
