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
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// escapeChar is the disconnect key for the interactive console (Ctrl+] = 0x1D).
const escapeChar = 0x1D

// errCtrlX is the sentinel returned by ctlXReader when the user presses the
// disconnect key. The interactive loop translates it into a clean shutdown.
var errCtrlX = errors.New("bmc: console disconnect requested")

// newConsoleCommand creates the console subcommand for interactive SOL access.
// In standalone mode (--bmc-host) it talks directly to the BMC over IPMI 2.0
// RMCP+. The daemon path is intentionally rejected: SOL is a long-lived
// bidirectional stream and there is no platformd REST endpoint that proxies
// it; users who want SOL must use the standalone path.
func newConsoleCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var standalone standaloneBMCFlags
	var logFile string
	var sendBreakOnly bool
	var sendStrings []string
	var sendDelay time.Duration

	cmd := &cobra.Command{
		Use:   "console",
		Short: "Open an interactive Serial Over LAN (SOL) console",
		Long: `Open an interactive SOL console session to a BMC via IPMI 2.0 RMCP+.

The console provides bidirectional character streaming with the BMC's serial
console. Press Ctrl+] to disconnect.

Standalone mode talks directly to the BMC over UDP 623 and does not require
platformd to be running. Redfish does not expose a SOL transport, so this
command requires --bmc-protocol ipmi (or auto-detection landing on IPMI).

Examples:
  # Interactive console
  platformctl bmc console \
    --bmc-host 10.4.2.103 \
    --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass \
    --bmc-protocol ipmi

  # Capture session to a log file (no TTY required)
  platformctl bmc console \
    --bmc-host 10.4.2.103 \
    --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass \
    --bmc-protocol ipmi \
    --log-file /var/log/sol-r640-01.log

  # Send a single serial-break and exit
  platformctl bmc console \
    --bmc-host 10.4.2.103 \
    --bmc-user admin \
    --bmc-pass-file /etc/platform/bmc.pass \
    --bmc-protocol ipmi \
    --send-break`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsole(cmd.Context(), &standalone, logFile, sendBreakOnly, sendStrings, sendDelay)
		},
	}

	addStandaloneFlags(cmd, &standalone)
	cmd.Flags().StringVar(&logFile, "log-file", "",
		"Capture SOL output to a file instead of an interactive terminal")
	cmd.Flags().BoolVar(&sendBreakOnly, "send-break", false,
		"Send a serial-break to the console and exit (no interactive session)")
	cmd.Flags().StringArrayVar(&sendStrings, "send", nil,
		"Send a literal string to the console then continue. Repeatable. "+
			"Use \\r for CR, \\n for LF, \\t for TAB, \\e for ESC, \\xNN for arbitrary byte. "+
			"Pairs naturally with --log-file to drive non-interactive recoveries "+
			"(EFI Shell, GRUB cmdline edit, kernel debugger, etc.) without a TTY.")
	cmd.Flags().DurationVar(&sendDelay, "send-delay", 500*time.Millisecond,
		"Delay between consecutive --send strings (default 500ms). Some BMCs and "+
			"firmware command interpreters drop bytes that arrive faster than they "+
			"can echo, so a small delay between commands is the safe default.")
	cmd.Flags().Uint8Var(&standalone.solInstance, "sol-instance", 0,
		"IPMI 2.0 SOL payload instance to activate against (Table 24-2). "+
			"Zero (default) consults the platform quirk registry and falls back "+
			"to 0x01. Set "+
			"explicitly to diagnose new hardware before adding a quirk.")

	return cmd
}

// runConsole opens a SOL session against the configured BMC and dispatches to
// either interactive raw-TTY mode or capture-to-log mode based on flags and
// stdin's TTY state.
func runConsole(
	ctx context.Context,
	standalone *standaloneBMCFlags,
	logFile string,
	sendBreakOnly bool,
	sendStrings []string,
	sendDelay time.Duration,
) error {
	if !standalone.isSet() {
		return ErrBMCNoMode{}
	}

	// Force IPMI when the user did not pick a protocol: SOL is IPMI-only.
	if standalone.protocol == "" || standalone.protocol == "auto" {
		standalone.protocol = string(bmc.ProtocolIPMI)
	}
	if standalone.protocol != string(bmc.ProtocolIPMI) {
		return ErrBMCConsoleNotSupported{Protocol: standalone.protocol}
	}

	client, err := resolveBMCClient(ctx, standalone, standaloneLogger())
	if err != nil {
		return err
	}
	defer client.Close()

	sol, err := client.Console(ctx)
	if err != nil {
		return ErrBMCConsoleActivate{Cause: err}
	}
	defer sol.Close()

	if sendBreakOnly {
		if err := sol.SendBreak(); err != nil {
			return ErrBMCConsoleActivate{Cause: err}
		}
		fmt.Fprintln(os.Stderr, "bmc: serial break sent")
		return nil
	}

	// --send strings are written to the SOL console BEFORE switching to
	// log/interactive mode. This lets operators drive recoveries from
	// pre-OS firmware (EFI Shell, GRUB, kernel debugger) without a TTY.
	if len(sendStrings) > 0 {
		if err := sendStringsToSOL(ctx, sol, sendStrings, sendDelay); err != nil {
			return err
		}
	}

	stdinFd := int(os.Stdin.Fd())
	interactive := term.IsTerminal(stdinFd) && logFile == ""
	if !interactive {
		return runConsoleLogMode(ctx, sol, logFile)
	}
	return runConsoleInteractive(ctx, sol, standalone.host)
}

// sendStringsToSOL writes each --send argument to the SOL console with the
// configured delay between writes. Escape sequences are decoded so the user
// can pass shell-quoted control bytes (\r, \n, \t, \e, \xNN) without
// shell-escaping nightmares.
func sendStringsToSOL(ctx context.Context, sol *bmc.SOLSession, strs []string, delay time.Duration) error {
	for i, s := range strs {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
		decoded, err := decodeSendEscapes(s)
		if err != nil {
			return ErrBMCConsoleSendDecode{Input: s, Cause: err}
		}
		if _, err := sol.Write(decoded); err != nil {
			return ErrBMCConsoleSendWrite{Index: i, Cause: err}
		}
		fmt.Fprintf(os.Stderr, "bmc: console: sent %d bytes (--send #%d)\n", len(decoded), i+1)
	}
	return nil
}

// decodeSendEscapes interprets the limited escape grammar accepted by --send.
// Recognises \r, \n, \t, \\, \e (ESC, 0x1b), and \xNN (hex byte). Anything
// else after a backslash is an error so typos don't silently turn into
// literal sequences.
func decodeSendEscapes(s string) ([]byte, error) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(s) {
			return nil, ErrBMCConsoleSendDecodeReason{Reason: "trailing backslash"}
		}
		switch s[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case '\\':
			out = append(out, '\\')
		case 'e':
			out = append(out, 0x1b)
		case 'x':
			if i+2 >= len(s) {
				return nil, ErrBMCConsoleSendDecodeReason{Reason: "truncated \\xNN escape"}
			}
			var b byte
			for j := 1; j <= 2; j++ {
				b <<= 4
				h := s[i+j]
				switch {
				case h >= '0' && h <= '9':
					b |= h - '0'
				case h >= 'a' && h <= 'f':
					b |= 10 + (h - 'a')
				case h >= 'A' && h <= 'F':
					b |= 10 + (h - 'A')
				default:
					return nil, ErrBMCConsoleSendDecodeReason{Reason: "non-hex digit in \\xNN escape"}
				}
			}
			out = append(out, b)
			i += 2
		default:
			return nil, ErrBMCConsoleSendDecodeReason{Reason: "unrecognised escape \\" + string(s[i])}
		}
	}
	return out, nil
}

// runConsoleInteractive bridges stdin/stdout to the SOL session in raw-TTY
// mode. It returns when the user presses the disconnect key, the BMC closes
// the session, or the context is cancelled.
func runConsoleInteractive(ctx context.Context, sol *bmc.SOLSession, host string) error {
	stdinFd := int(os.Stdin.Fd())
	oldState, termErr := term.MakeRaw(stdinFd)
	if termErr != nil {
		return ErrBMCTTYRaw{Cause: termErr}
	}
	defer term.Restore(stdinFd, oldState)

	fmt.Fprintf(os.Stderr, "Connected to SOL console on %s. Press Ctrl+] to disconnect.\r\n", host)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// errCh fans in errors from both copy goroutines and the signal handler.
	errCh := make(chan error, 3)

	// BMC -> stdout
	go func() {
		_, copyErr := io.Copy(os.Stdout, sol)
		errCh <- copyErr
	}()

	// stdin -> BMC, intercepting Ctrl+]
	go func() {
		_, copyErr := io.Copy(sol, &ctlXReader{r: os.Stdin})
		errCh <- copyErr
	}()

	// Signal -> errCh
	go func() {
		select {
		case <-sigCh:
			errCh <- errCtrlX
		case <-ctx.Done():
			errCh <- ctx.Err()
		}
	}()

	err := <-errCh
	fmt.Fprint(os.Stderr, "\r\nDisconnected from SOL console.\r\n")
	if errors.Is(err, errCtrlX) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// runConsoleLogMode is the non-interactive capture path. It writes received
// SOL bytes to logFile (or stdout when empty) until the BMC closes the
// session, the user sends SIGINT, or the context is cancelled.
//
// The SOL reader is wrapped in a flushing writer so every packet is synced
// to disk immediately — silent SOL sessions (BIOS redirection off, wrong
// COM port) must produce a zero-byte file we can rely on rather than a
// file that could still hold buffered bytes at termination.
func runConsoleLogMode(ctx context.Context, sol *bmc.SOLSession, logFile string) error {
	var dst io.Writer = os.Stdout
	var syncer interface{ Sync() error }
	if logFile != "" {
		// O_TRUNC so repeated captures don't confuse the operator with
		// old bytes from a prior run.
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return ErrBMCConsoleActivate{Cause: err}
		}
		defer f.Close()
		dst = f
		syncer = f
		fmt.Fprintf(os.Stderr, "Capturing SOL session to %s. Press Ctrl+C to stop.\n", logFile)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	errCh := make(chan error, 2)

	go func() {
		// Custom copy loop flushing to disk after every SOL packet so
		// termination never loses in-flight bytes.
		buf := make([]byte, 32*1024)
		for {
			n, rerr := sol.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					errCh <- werr
					return
				}
				if syncer != nil {
					_ = syncer.Sync()
				}
			}
			if rerr != nil {
				errCh <- rerr
				return
			}
		}
	}()

	go func() {
		select {
		case <-sigCh:
			errCh <- errCtrlX
		case <-ctx.Done():
			errCh <- ctx.Err()
		}
	}()

	err := <-errCh

	// A successful Activate Payload followed by zero data bytes for the
	// lifetime of the session is the canonical signature of a wrong SOL
	// payload instance — the BMC routes serial bytes to a different
	// instance and our receiver sees nothing. Surface this loudly so
	// operators don't conclude "SOL is broken" and waste hours debugging
	// before they consider channel selection.
	if sol.BytesReceived() == 0 {
		fmt.Fprintf(os.Stderr,
			"WARNING: SOL session activated on payload instance 0x%02X but "+
				"received zero data bytes. This usually means the BMC routes "+
				"serial-console output to a different instance, or that BIOS "+
				"console redirection is off. Try --sol-instance 2.\n",
			sol.PayloadInstance())
	}

	if errors.Is(err, errCtrlX) || errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// ctlXReader wraps an io.Reader and returns errCtrlX as soon as it sees the
// disconnect key in the input stream. Any bytes that arrive before the
// disconnect key are passed through to the caller.
type ctlXReader struct {
	r io.Reader
}

// Read forwards bytes from the underlying reader, terminating with errCtrlX
// the moment the disconnect key appears.
func (c *ctlXReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	for i := 0; i < n; i++ {
		if p[i] == escapeChar {
			return i, errCtrlX
		}
	}
	return n, err
}
