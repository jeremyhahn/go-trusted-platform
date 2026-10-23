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
	"context"
	"encoding/hex"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

// defaultHTTPBootPath is the HTTP_PATH of a netboot media build's HTTP boot
// files, which the container serves under its data directory.
var defaultHTTPBootPath = (&container.NetbootMedia{HTTPBoot: container.HTTPBootDir}).HTTPBootPath()

// probeRPiHTTPFlags are the flags of `bootstrap probe rpi-http`.
type probeRPiHTTPFlags struct {
	host    string
	path    string
	pubkey  string
	otpHash string
	timeout time.Duration
}

func newProbeRPiHTTPCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &probeRPiHTTPFlags{}
	cmd := &cobra.Command{
		Use:   "rpi-http",
		Short: "HTTP boot the way a Raspberry Pi's bootloader does, with SIGNED_BOOT",
		Long: `Run the Raspberry Pi bootloader's signed HTTP boot against the boot server:
fetch boot.img and boot.sig from http://--http-host/--http-path/, require the
public key the EEPROM carries (--pubkey, its pubkey.bin) to hash to the
customer key hash in OTP (--otp-key-hash), verify boot.sig over boot.img with
it, and mount boot.img as the FAT ramdisk the bootloader boots from. It fails
on whatever the bootloader would refuse.

--pubkey and --otp-key-hash are what the Pi holds, so give them from the
device's provisioning record, not from the server being probed. 'platformctl
diskimage netboot --fleet-key' prints the hash and writes pubkey.bin.

Examples:
  platformctl bootstrap probe rpi-http --http-host 10.99.99.1:8080 \
      --pubkey bin/netboot-media/http-boot/pubkey.bin --otp-key-hash 3f9a...c1

  # As JSON
  platformctl bootstrap probe rpi-http --http-host 10.99.99.1:8080 --pubkey pubkey.bin --otp-key-hash 3f9a...c1 -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProbeRPiHTTP(cmd.Context(), flags, getFlags())
		},
	}
	cmd.Flags().StringVar(&flags.host, "http-host", "", "the EEPROM's HTTP_HOST: the boot server's address, with its port unless 80 (required)")
	cmd.Flags().StringVar(&flags.path, "http-path", defaultHTTPBootPath, "the EEPROM's HTTP_PATH")
	cmd.Flags().StringVar(&flags.pubkey, "pubkey", "", "the public key the EEPROM carries: a pubkey.bin file (required)")
	cmd.Flags().StringVar(&flags.otpHash, "otp-key-hash", "", "the customer key hash in OTP: 64 hex digits (required)")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 0, "overall deadline (default: none)")
	return cmd
}

// probeHTTPOptions turns the flags into rpinetboot.HTTPBootOptions.
func probeHTTPOptions(flags *probeRPiHTTPFlags, logger *logging.Logger) (rpinetboot.HTTPBootOptions, error) {
	invalid := func(flag, reason string) (rpinetboot.HTTPBootOptions, error) {
		return rpinetboot.HTTPBootOptions{}, &ErrProbeInvalidFlag{Flag: flag, Reason: reason}
	}
	if flags.host == "" {
		return invalid("--http-host", "required")
	}
	if flags.pubkey == "" {
		return invalid("--pubkey", "required")
	}
	blob, err := os.ReadFile(flags.pubkey)
	if err != nil {
		return invalid("--pubkey", err.Error())
	}
	raw, err := hex.DecodeString(strings.TrimSpace(flags.otpHash))
	if err != nil || len(raw) != rpibootsig.KeyHashSize {
		return invalid("--otp-key-hash", strconv.Itoa(2*rpibootsig.KeyHashSize)+" hex digits required")
	}
	opts := rpinetboot.HTTPBootOptions{Host: flags.host, Path: flags.path, PublicKey: blob, Logger: logger}
	copy(opts.OTPKeyHash[:], raw)
	return opts, nil
}

func runProbeRPiHTTP(ctx context.Context, flags *probeRPiHTTPFlags, commonFlags *cli.CommonFlags) error {
	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr)
	opts, err := probeHTTPOptions(flags, logger)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if flags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, flags.timeout)
		defer cancel()
	}

	report, err := rpinetboot.HTTPBoot(ctx, opts)
	if err != nil {
		return &ErrProbeFailed{Cause: err}
	}
	return printHTTPBootReport(report, commonFlags)
}

// probeHTTPView is the report as it is printed.
type probeHTTPView struct {
	URL       string   `json:"url" yaml:"url"`
	Bytes     int64    `json:"bytes" yaml:"bytes"`
	SHA256    string   `json:"sha256" yaml:"sha256"`
	Timestamp int64    `json:"ts" yaml:"ts"`
	TargetSoC string   `json:"target_soc,omitempty" yaml:"target_soc,omitempty"`
	Ramdisk   []string `json:"ramdisk" yaml:"ramdisk"`
}

func httpBootView(r *rpinetboot.HTTPBootReport) probeHTTPView {
	return probeHTTPView{
		URL:       r.URL,
		Bytes:     r.Image.Bytes,
		SHA256:    r.Image.SHA256,
		Timestamp: r.Signature.Timestamp.Unix(),
		TargetSoC: r.Signature.TargetSoC,
		Ramdisk:   r.Ramdisk,
	}
}

// printHTTPBootReport prints a signed boot the bootloader would have run.
func printHTTPBootReport(r *rpinetboot.HTTPBootReport, commonFlags *cli.CommonFlags) error {
	format, noColor := cli.OutputFormatTable, false
	if commonFlags != nil {
		if commonFlags.OutputFormat != "" {
			format = commonFlags.OutputFormat
		}
		noColor = commonFlags.NoColor
	}
	view := httpBootView(r)
	printer := cli.NewPrinter(format, noColor)
	if format != cli.OutputFormatTable {
		return printer.Print(view)
	}
	printer.PrintKeyValue("Fetched from", view.URL)
	printer.PrintKeyValue("boot.img", strconv.FormatInt(view.Bytes, 10)+" bytes, sha256 "+view.SHA256)
	printer.PrintKeyValue("boot.sig", "verified against the OTP key hash, ts "+strconv.FormatInt(view.Timestamp, 10)+targetSoCSuffix(view.TargetSoC))
	printer.PrintKeyValue("Ramdisk", strings.Join(view.Ramdisk, ", "))
	return nil
}

func targetSoCSuffix(soc string) string {
	if soc == "" {
		return ""
	}
	return ", target-soc " + soc
}
