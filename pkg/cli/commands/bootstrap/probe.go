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
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpinetboot"
)

// probeRPiFlags are the flags of `bootstrap probe rpi`.
type probeRPiFlags struct {
	iface     string
	serial    string
	mac       string
	revision  string
	model     string
	prefix    string
	prefixStr string
	option43  string
	timeout   time.Duration
}

func newProbeCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Probe a boot server from a client's side of the wire",
		Long: `Speak a network boot client's protocol to the boot server on a segment
and report what the client would have seen, without the client.`,
	}
	cmd.AddCommand(newProbeRPiCommand(getFlags), newProbeRPiHTTPCommand(getFlags))
	return cmd
}

func newProbeRPiCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	flags := &probeRPiFlags{}
	cmd := &cobra.Command{
		Use:   "rpi",
		Short: "Boot from the network the way a Raspberry Pi's bootloader does",
		Long: `Run the Raspberry Pi bootloader's network boot against the boot server
on --interface's segment: the DHCP exchange with the bootloader's vendor
class, architecture and client identifier (option 97), accepting only a
reply that carries the "Raspberry Pi Boot" match in option 43 (a proxy
DHCP reply included), then every file the bootloader and the firmware
fetch over TFTP, in their order, under the per-device prefix first and
the root second, with the bootloader's timeouts. The report lists what a
Pi with this identity would have booted with; the first thing a Pi would
have failed at fails the probe.

Binding the DHCP client socket to an interface needs CAP_NET_RAW: run as
root.

Examples:
  # A Pi 4 with serial 9ffefdef on the provisioning segment
  sudo platformctl bootstrap probe rpi --interface eth1 --serial 9ffefdef --mac dc:a6:32:01:36:c2

  # A Pi 5 whose bootloader is configured with TFTP_PREFIX=2 (MAC directories)
  sudo platformctl bootstrap probe rpi --interface eth1 --serial 1a2b3c4d --mac 2c:cf:67:00:11:22 --model rpi5 --prefix mac

  # As JSON
  sudo platformctl bootstrap probe rpi --interface eth1 --serial 9ffefdef --mac dc:a6:32:01:36:c2 -o json`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runProbeRPi(cmd.Context(), flags, getFlags())
		},
	}
	cmd.Flags().StringVar(&flags.iface, "interface", "", "network interface on the boot segment (required)")
	cmd.Flags().StringVar(&flags.serial, "serial", "", "the Pi's serial number, up to eight hex digits (required)")
	cmd.Flags().StringVar(&flags.mac, "mac", "", "the Pi's Ethernet address (required)")
	cmd.Flags().StringVar(&flags.revision, "revision", "0", "the board revision code, hex (for option 97)")
	cmd.Flags().StringVar(&flags.model, "model", "rpi4", "board model: "+strings.Join(rpinetboot.Models(), ", "))
	cmd.Flags().StringVar(&flags.prefix, "prefix", "serial", "the bootloader's TFTP_PREFIX: serial, mac or string")
	cmd.Flags().StringVar(&flags.prefixStr, "prefix-str", "", "the bootloader's TFTP_PREFIX_STR (with --prefix string)")
	cmd.Flags().StringVar(&flags.option43, "option43", rpinetboot.Option43Match, "the bootloader's PXE_OPTION43 match string")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", 0, "overall deadline (default: the bootloader's own timeouts)")
	return cmd
}

// probeOptions turns the flags into rpinetboot.Options.
func probeOptions(flags *probeRPiFlags, logger *logging.Logger) (rpinetboot.Options, error) {
	if flags.iface == "" {
		return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--interface", Reason: "required"}
	}
	serial, err := parseHex32(flags.serial)
	if err != nil {
		return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--serial", Reason: err.Error()}
	}
	mac, err := net.ParseMAC(flags.mac)
	if err != nil || len(mac) != 6 {
		return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--mac", Reason: "a 48-bit Ethernet address is required"}
	}
	revision, err := parseHex32(flags.revision)
	if err != nil {
		return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--revision", Reason: err.Error()}
	}
	model, err := rpinetboot.LookupModel(flags.model)
	if err != nil {
		return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--model", Reason: err.Error()}
	}
	var prefix rpinetboot.PrefixMode
	switch flags.prefix {
	case "serial":
		prefix = rpinetboot.PrefixSerial
	case "mac":
		prefix = rpinetboot.PrefixMAC
	case "string":
		prefix = rpinetboot.PrefixString
		if flags.prefixStr == "" {
			return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--prefix-str", Reason: "required with --prefix string"}
		}
	default:
		return rpinetboot.Options{}, &ErrProbeInvalidFlag{Flag: "--prefix", Reason: "serial, mac or string"}
	}
	return rpinetboot.Options{
		Interface:    flags.iface,
		Identity:     rpinetboot.Identity{Serial: serial, MAC: mac, Revision: revision},
		Model:        model,
		Prefix:       prefix,
		PrefixString: flags.prefixStr,
		Option43:     flags.option43,
		Logger:       logger,
	}, nil
}

// parseHex32 reads up to eight hex digits, with or without 0x.
func parseHex32(s string) (uint32, error) {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	if s == "" {
		return 0, &ErrProbeInvalidFlag{Reason: "empty"}
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, &ErrProbeInvalidFlag{Reason: "not up to eight hex digits: " + s}
	}
	return uint32(v), nil
}

func runProbeRPi(ctx context.Context, flags *probeRPiFlags, commonFlags *cli.CommonFlags) error {
	verbose := commonFlags != nil && commonFlags.Verbose
	logger := logging.NewLogger(logLevelFromVerbose(verbose), os.Stderr)
	opts, err := probeOptions(flags, logger)
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

	report, err := rpinetboot.Probe(ctx, opts)
	printProbeReport(report, commonFlags)
	if err != nil {
		return &ErrProbeFailed{Cause: err}
	}
	return nil
}

// probeReportView is the report as it is printed.
type probeReportView struct {
	Offer  probeOfferView  `json:"offer" yaml:"offer"`
	Lease  *probeLeaseView `json:"lease,omitempty" yaml:"lease,omitempty"`
	Prefix string          `json:"prefix" yaml:"prefix"`
	Files  []probeFileView `json:"files" yaml:"files"`
}

type probeOfferView struct {
	Server     string `json:"server" yaml:"server"`
	TFTPServer string `json:"tftp_server" yaml:"tftp_server"`
	Proxy      bool   `json:"proxy" yaml:"proxy"`
	Option43   string `json:"option43_hex" yaml:"option43_hex"`
	BootFile   string `json:"boot_file,omitempty" yaml:"boot_file,omitempty"`
}

type probeLeaseView struct {
	IP     string `json:"ip" yaml:"ip"`
	Mask   string `json:"mask" yaml:"mask"`
	Router string `json:"router,omitempty" yaml:"router,omitempty"`
}

type probeFileView struct {
	Name     string `json:"name" yaml:"name"`
	Path     string `json:"path" yaml:"path"`
	Bytes    int64  `json:"bytes" yaml:"bytes"`
	SHA256   string `json:"sha256,omitempty" yaml:"sha256,omitempty"`
	Optional bool   `json:"optional" yaml:"optional"`
	Missing  bool   `json:"missing" yaml:"missing"`
}

func probeView(r *rpinetboot.Report) probeReportView {
	v := probeReportView{Prefix: r.Prefix}
	v.Offer = probeOfferView{
		Server:     ipString(r.Offer.Server),
		TFTPServer: ipString(r.Offer.TFTPServer),
		Proxy:      r.Offer.Proxy,
		Option43:   hex.EncodeToString(r.Offer.Option43),
		BootFile:   r.Offer.BootFile,
	}
	if r.Lease != nil {
		v.Lease = &probeLeaseView{IP: ipString(r.Lease.IP), Mask: net.IP(r.Lease.Mask).String(), Router: ipString(r.Lease.Router)}
	}
	for _, f := range r.Files {
		v.Files = append(v.Files, probeFileView{Name: f.Name, Path: f.Path, Bytes: f.Bytes, SHA256: f.SHA256, Optional: f.Optional, Missing: f.Missing})
	}
	return v
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// printProbeReport prints whatever the probe saw, in the requested
// format; a failed probe still shows how far it got.
func printProbeReport(r *rpinetboot.Report, commonFlags *cli.CommonFlags) {
	if r == nil {
		return
	}
	format, noColor := cli.OutputFormatTable, false
	if commonFlags != nil {
		if commonFlags.OutputFormat != "" {
			format = commonFlags.OutputFormat
		}
		noColor = commonFlags.NoColor
	}
	view := probeView(r)
	printer := cli.NewPrinter(format, noColor)
	if format != cli.OutputFormatTable {
		if err := printer.Print(view); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		return
	}
	printer.PrintKeyValue("DHCP server", view.Offer.Server)
	printer.PrintKeyValue("TFTP server", view.Offer.TFTPServer)
	printer.PrintKeyValue("Proxy DHCP", strconv.FormatBool(view.Offer.Proxy))
	if view.Lease != nil {
		printer.PrintKeyValue("Lease", view.Lease.IP+"/"+view.Lease.Mask)
	}
	printer.PrintKeyValue("Device prefix", view.Prefix)
	rows := make([][]string, 0, len(view.Files))
	for _, f := range view.Files {
		state := "ok"
		switch {
		case f.Missing:
			state = "absent (optional)"
		case f.Bytes == 0 && f.SHA256 == "":
			state = "failed"
		}
		rows = append(rows, []string{f.Name, f.Path, strconv.FormatInt(f.Bytes, 10), state})
	}
	if err := printer.Print(cli.TableData{Headers: []string{"FILE", "SERVED AS", "BYTES", "STATE"}, Rows: rows}); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
