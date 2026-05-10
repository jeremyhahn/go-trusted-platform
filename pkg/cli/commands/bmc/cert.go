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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// certFlags holds flags for cert subcommands.
type certFlags struct {
	profileID string
	certFile  string
	keyFile   string
}

// newCertCommand creates the cert subcommand group for BMC certificate management.
func newCertCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Manage BMC web server certificates",
		Long: `Manage BMC web server TLS certificates.

Provides commands to inspect and replace the certificate presented
by the BMC's HTTPS management interface.

Examples:
  # Get current certificate details
  platformctl bmc cert get --profile-id 1

  # Show certificate status (days until expiry)
  platformctl bmc cert status --profile-id 1

  # Replace the BMC web certificate
  platformctl bmc cert replace --profile-id 1 \
    --cert /path/to/cert.pem --key /path/to/key.pem`,
	}

	cmd.AddCommand(newCertGetCommand(getFlags))
	cmd.AddCommand(newCertStatusCommand(getFlags))
	cmd.AddCommand(newCertReplaceCommand(getFlags))

	return cmd
}

// newCertGetCommand creates the cert get subcommand.
func newCertGetCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags certFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get BMC web certificate details",
		Long: `Retrieve the current BMC web server certificate details including
subject, issuer, validity period, and fingerprint.

Examples:
  # Via platformd
  platformctl bmc cert get --profile-id 1

  # Direct standalone
  platformctl bmc cert get \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneCertGet(cmd, &standalone, getFlags)
			}
			return runCertGet(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newCertStatusCommand creates the cert status subcommand.
func newCertStatusCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags certFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show BMC certificate expiry status",
		Long: `Display the BMC web server certificate status including days until
expiry, issuer, and subject.

Examples:
  # Via platformd
  platformctl bmc cert status --profile-id 1

  # Direct standalone
  platformctl bmc cert status \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneCertGet(cmd, &standalone, getFlags)
			}
			return runCertGet(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// newCertReplaceCommand creates the cert replace subcommand.
func newCertReplaceCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var flags certFlags
	var standalone standaloneBMCFlags

	cmd := &cobra.Command{
		Use:   "replace",
		Short: "Replace BMC web certificate",
		Long: `Replace the BMC web server TLS certificate with a new certificate
and private key. The BMC will restart its web server to activate
the new certificate.

Examples:
  # Via platformd
  platformctl bmc cert replace --profile-id 1 \
    --cert /path/to/cert.pem --key /path/to/key.pem

  # Direct standalone
  platformctl bmc cert replace \
    --bmc-host 192.168.1.100 --bmc-user admin --bmc-pass-file /etc/bmc-pass \
    --cert /path/to/cert.pem --key /path/to/key.pem`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if standalone.isSet() {
				return runStandaloneCertReplace(cmd, &standalone, &flags, getFlags)
			}
			return runCertReplace(&flags, getFlags)
		},
	}

	cmd.Flags().StringVar(&flags.profileID, "profile-id", "", "BMC profile ID (required for daemon mode)")
	cmd.Flags().StringVar(&flags.certFile, "cert", "", "path to PEM certificate file (required)")
	cmd.Flags().StringVar(&flags.keyFile, "key", "", "path to PEM private key file (required)")
	addStandaloneFlags(cmd, &standalone)

	return cmd
}

// runCertGet retrieves the BMC web certificate via the SDK.
func runCertGet(flags *certFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	certInfo, err := sdkClient.GetWebCertificate(ctx, profileID)
	if err != nil {
		return err
	}

	return printCertInfo(commonFlags, certInfo)
}

// runCertReplace replaces the BMC web certificate via the SDK.
func runCertReplace(flags *certFlags, getFlags func() *cli.CommonFlags) error {
	if flags.profileID == "" {
		return ErrProfileIDRequired{}
	}
	if flags.certFile == "" {
		return ErrCertFileRequired{}
	}
	if flags.keyFile == "" {
		return ErrKeyFileRequired{}
	}

	profileID, err := strconv.ParseUint(flags.profileID, 10, 64)
	if err != nil {
		return ErrProfileIDParseFailed{Value: flags.profileID, Cause: err}
	}

	certPEM, err := os.ReadFile(flags.certFile)
	if err != nil {
		return ErrCertFileReadFailed{Path: flags.certFile, Cause: err}
	}

	keyPEM, err := os.ReadFile(flags.keyFile)
	if err != nil {
		return ErrKeyFileReadFailed{Path: flags.keyFile, Cause: err}
	}

	commonFlags := getFlags()
	base, err := cli.NewBaseCommand(commonFlags)
	if err != nil {
		return err
	}
	defer base.Close()

	grpcClient := base.Client().BMC()
	if grpcClient == nil {
		return ErrBMCClientNotInitialized{}
	}

	sdkClient := bmcsvc.NewClientFromGRPC(grpcClient)

	ctx := base.Context()
	message, err := sdkClient.ReplaceWebCertificate(ctx, profileID, certPEM, keyPEM)
	if err != nil {
		return err
	}

	resp := certReplaceResponse{
		ProfileID: flags.profileID,
		Status:    "success",
		Message:   message,
	}

	done, emitErr := emitJSON(getFlags, resp)
	if emitErr != nil || done {
		return emitErr
	}

	fmt.Fprintf(os.Stdout, "Profile: %s\nStatus:  %s\n", resp.ProfileID, resp.Status)
	if resp.Message != "" {
		fmt.Fprintf(os.Stdout, "Message: %s\n", resp.Message)
	}
	return nil
}

// runStandaloneCertGet retrieves the BMC web certificate via standalone mode.
func runStandaloneCertGet(cmd *cobra.Command, standalone *standaloneBMCFlags, getFlags func() *cli.CommonFlags) error {
	return withStandaloneCertManager(cmd, standalone, func(mgr bmc.CertificateManager) error {
		ctx := cmd.Context()
		cert, err := mgr.GetWebCertificate(ctx)
		if err != nil {
			return err
		}

		certInfo := x509CertToInfo(cert, standalone.host)

		return printCertInfo(getFlags(), certInfo)
	})
}

// runStandaloneCertReplace replaces the BMC web certificate via standalone mode.
func runStandaloneCertReplace(cmd *cobra.Command, standalone *standaloneBMCFlags, flags *certFlags, getFlags func() *cli.CommonFlags) error {
	if flags.certFile == "" {
		return ErrCertFileRequired{}
	}
	if flags.keyFile == "" {
		return ErrKeyFileRequired{}
	}

	certPEM, err := os.ReadFile(flags.certFile)
	if err != nil {
		return ErrCertFileReadFailed{Path: flags.certFile, Cause: err}
	}

	keyPEM, err := os.ReadFile(flags.keyFile)
	if err != nil {
		return ErrKeyFileReadFailed{Path: flags.keyFile, Cause: err}
	}

	return withStandaloneCertManager(cmd, standalone, func(mgr bmc.CertificateManager) error {
		ctx := cmd.Context()
		keySecret := memguard.New(keyPEM)
		defer keySecret.Destroy()

		if err := mgr.ReplaceWebCertificate(ctx, certPEM, keySecret); err != nil {
			return err
		}

		resp := certReplaceResponse{
			ProfileID: standalone.host,
			Status:    "success",
			Message:   "certificate replaced and BMC web server restarted",
		}

		done, emitErr := emitJSON(getFlags, resp)
		if emitErr != nil || done {
			return emitErr
		}

		fmt.Fprintf(os.Stdout, "Host:    %s\nStatus:  %s\nMessage: %s\n", resp.ProfileID, resp.Status, resp.Message)
		return nil
	})
}

// withStandaloneCertManager creates a standalone CertificateManager and runs fn.
func withStandaloneCertManager(cmd *cobra.Command, standalone *standaloneBMCFlags, fn func(bmc.CertificateManager) error) error {
	pw, err := loadStandalonePassword(standalone)
	if err != nil {
		return err
	}

	if standalone.user == "" {
		return ErrBMCMissingCredential{Field: "username (set --bmc-user)"}
	}

	cfg := &bmc.Config{
		Address:       standalone.host,
		Port:          standalone.port,
		Protocol:      bmc.Protocol(standalone.protocol),
		Username:      standalone.user,
		Password:      pw,
		SkipTLSVerify: standalone.skipTLSVerify,
	}

	mgr, err := bmc.NewAutoCertManager(cfg, bmc.CertBackendAuto, standaloneLogger())
	if err != nil {
		return err
	}
	defer mgr.Close()

	return fn(mgr)
}

// printCertInfo prints certificate info in the appropriate format.
func printCertInfo(flags *cli.CommonFlags, info *bmcsvc.CertificateInfo) error {
	if flags != nil && flags.OutputFormat == cli.OutputFormatJSON {
		return encodeJSON(os.Stdout, info)
	}

	fmt.Fprintf(os.Stdout, "Subject:        %s\n", info.Subject)
	fmt.Fprintf(os.Stdout, "Issuer:         %s\n", info.Issuer)
	fmt.Fprintf(os.Stdout, "Serial Number:  %s\n", info.SerialNumber)
	fmt.Fprintf(os.Stdout, "Not Before:     %s\n", info.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "Not After:      %s\n", info.NotAfter.UTC().Format(time.RFC3339))
	fmt.Fprintf(os.Stdout, "Days Remaining: %d\n", info.DaysRemaining)
	if len(info.SubjectAlternativeNames) > 0 {
		fmt.Fprintf(os.Stdout, "SANs:           %s\n", strings.Join(info.SubjectAlternativeNames, ", "))
	}
	fmt.Fprintf(os.Stdout, "Fingerprint:    %s\n", info.Fingerprint)

	return nil
}

// x509CertToInfo converts an x509.Certificate to the SDK CertificateInfo type.
func x509CertToInfo(cert *x509.Certificate, host string) *bmcsvc.CertificateInfo {
	fingerprint := sha256.Sum256(cert.Raw)

	var sans []string
	for _, dns := range cert.DNSNames {
		sans = append(sans, dns)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	daysRemaining := int32(math.Floor(time.Until(cert.NotAfter).Hours() / 24))

	return &bmcsvc.CertificateInfo{
		Subject:                 cert.Subject.String(),
		Issuer:                  cert.Issuer.String(),
		SerialNumber:            cert.SerialNumber.Text(16),
		NotBefore:               cert.NotBefore,
		NotAfter:                cert.NotAfter,
		DaysRemaining:           daysRemaining,
		SubjectAlternativeNames: sans,
		Fingerprint:             hex.EncodeToString(fingerprint[:]),
	}
}
