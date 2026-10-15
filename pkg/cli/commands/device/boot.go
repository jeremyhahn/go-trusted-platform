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

package device

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
)

// keyParsers parses a PEM private key block by its type.
var keyParsers = map[string]func([]byte) (any, error){
	"PRIVATE KEY":     x509.ParsePKCS8PrivateKey,
	"EC PRIVATE KEY":  func(der []byte) (any, error) { return x509.ParseECPrivateKey(der) },
	"RSA PRIVATE KEY": func(der []byte) (any, error) { return x509.ParsePKCS1PrivateKey(der) },
}

// newBootCommand creates the boot command group.
func newBootCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "boot",
		Short: "Exercise a diskless node's per-boot requests",
		Long: `Send the two requests a diskless node makes at boot to the control plane.

The control plane authenticates both itself. The proof of possession and the
attestation evidence are checked against the TLS connection the request
travels on (a channel nonce exported from that connection), so input computed
for another connection is refused. Over a transport with no TLS connection
(the Unix socket, MCP stdio) every request is refused. Use these commands to
probe that enforcement; a diskless node makes the same requests itself.`,
	}
	cmd.AddCommand(newBootCertificateCommand(getFlags))
	cmd.AddCommand(newBootDeliveryCommand(getFlags))
	return cmd
}

// newBootCertificateCommand creates the certificate subcommand.
func newBootCertificateCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var identity, keyPath string
	cmd := &cobra.Command{
		Use:   "certificate",
		Short: "Request a node's recorded IDevID chain with a proof of possession",
		Long: `Request the IDevID chain recorded for a device identity. Once connected,
the command signs the identity and this connection's channel nonce with the
key in --key; the control plane answers only a signature that verifies and
refuses every other request alike.

Examples:
  platformctl device boot certificate --identity node-1.example --key idevid.key`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBootCertificate(getFlags(), identity, keyPath)
		},
	}
	cmd.Flags().StringVar(&identity, "identity", "", "Claimed device identity")
	cmd.Flags().StringVar(&keyPath, "key", "", "PEM private key of the identity's IDevID certificate")
	cli.MarkFlagsRequired(cmd, "identity")
	cli.MarkFlagsRequired(cmd, "key")
	return cmd
}

// newBootDeliveryCommand creates the delivery subcommand.
func newBootDeliveryCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var quoteCommand string
	cmd := &cobra.Command{
		Use:   "delivery",
		Short: "Request a node's network profile and the CA bundle with attestation evidence",
		Long: `Present attestation evidence and, once the control plane has verified it
against this connection's client certificate and channel nonce, receive the
node's network profile and the CA bundle. The node's identity is the client
certificate, never an argument.

Once connected, the command runs --quote-command with the connection's channel
nonce, base64-encoded, as its only argument; the program prints the JSON quote
evidence over that nonce on stdout.

Examples:
  platformctl device boot delivery --quote-command /usr/libexec/node-quote`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBootDelivery(getFlags(), quoteCommand)
		},
	}
	cmd.Flags().StringVar(&quoteCommand, "quote-command", "", "Program that prints quote evidence over the base64 nonce it is given")
	cli.MarkFlagsRequired(cmd, "quote-command")
	return cmd
}

// bootCertificateOutput is the machine-readable result of certificate.
type bootCertificateOutput struct {
	Identity    string `json:"identity"`
	IDevIDChain string `json:"idevid_chain"`
}

// bootDeliveryOutput is the machine-readable result of delivery.
type bootDeliveryOutput struct {
	Serial              string `json:"serial"`
	IDevIDChain         string `json:"idevid_chain"`
	AttestCert          string `json:"attest_cert,omitempty"`
	CABundle            string `json:"ca_bundle"`
	AdmittedVLAN        uint32 `json:"admitted_vlan"`
	PCRBaselineSource   string `json:"pcr_baseline_source"`
	PCRBaselineCaptured bool   `json:"pcr_baseline_captured"`
}

func runBootCertificate(flags *cli.CommonFlags, identity, keyPath string) error {
	signer, err := loadBootSigner(keyPath)
	if err != nil {
		return err
	}

	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	resp, err := deviceClient.BootCertificate(base.Context(), identity, signBootCertificate(signer, identity))
	if err != nil {
		return ErrBootCertificateFailed{Identity: identity, Reason: err.Error()}
	}

	out := bootCertificateOutput{Identity: resp.GetIdentity(), IDevIDChain: resp.GetIdevidChain()}
	if flags.OutputFormat == cli.OutputFormatTable {
		base.Printer().PrintSuccess("IDevID chain returned")
		base.Printer().PrintKeyValue("Identity", out.Identity)
		return nil
	}
	return base.Output(out)
}

func runBootDelivery(flags *cli.CommonFlags, quoteCommand string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	deviceClient := device.NewClientFromGRPC(base.Client().Device())
	resp, err := deviceClient.BootDelivery(base.Context(), runQuoteCommand(quoteCommand))
	if err != nil {
		return ErrBootDeliveryFailed{Reason: err.Error()}
	}

	out := bootDeliveryOutput{
		Serial:              resp.GetSerial(),
		IDevIDChain:         resp.GetIdevidChain(),
		AttestCert:          resp.GetAttestCert(),
		CABundle:            resp.GetCaBundle(),
		AdmittedVLAN:        resp.GetProfile().GetAdmittedNetwork().GetVlan(),
		PCRBaselineSource:   resp.GetPcrBaselineSource(),
		PCRBaselineCaptured: resp.GetPcrBaselineCaptured(),
	}
	if flags.OutputFormat == cli.OutputFormatTable {
		printer := base.Printer()
		printer.PrintSuccess("Boot delivery returned")
		printer.PrintKeyValue("Serial", out.Serial)
		printer.PrintKeyValue("Admitted VLAN", strconv.FormatUint(uint64(out.AdmittedVLAN), 10))
		printer.PrintKeyValue("PCR Baseline", out.PCRBaselineSource)
		return nil
	}
	return base.Output(out)
}

// loadBootSigner reads the PEM private key at path and returns it as a
// signer.
func loadBootSigner(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrBootKeyUnreadable{Path: path, Cause: err}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrBootKeyUnreadable{Path: path}
	}
	parse, ok := keyParsers[block.Type]
	if !ok {
		return nil, ErrBootKeyUnreadable{Path: path}
	}
	key, err := parse(block.Bytes)
	if err != nil {
		return nil, ErrBootKeyUnreadable{Path: path, Cause: err}
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, ErrBootKeyUnreadable{Path: path}
	}
	return signer, nil
}

// signBootCertificate returns the proof callback that signs identity and
// the binding of the connection the request travels on.
func signBootCertificate(signer crypto.Signer, identity string) device.BootProofFunc {
	return func(_ context.Context, binding []byte) ([]byte, error) {
		return provisioning.SignBootCertificateProof(signer, identity, binding)
	}
}

// runQuoteCommand returns the proof callback that runs program with the
// connection's binding, base64-encoded, as its only argument and takes
// its stdout as the quote evidence.
func runQuoteCommand(program string) device.BootProofFunc {
	return func(ctx context.Context, binding []byte) ([]byte, error) {
		var stdout, stderr bytes.Buffer
		// #nosec G204 -- the operator names the program; no shell is involved
		// and the only argument is base64 text.
		cmd := exec.CommandContext(ctx, program, base64.StdEncoding.EncodeToString(binding))
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return nil, ErrBootQuoteCommandFailed{Command: program, Stderr: stderr.String(), Cause: err}
		}
		if stdout.Len() == 0 {
			return nil, ErrBootQuoteCommandFailed{Command: program, Stderr: stderr.String()}
		}
		return stdout.Bytes(), nil
	}
}
