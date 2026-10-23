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

package kms

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/spf13/cobra"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// ErrKeyCSRFailed is returned when a certificate signing request cannot be
// built for a KMS key.
type ErrKeyCSRFailed struct {
	KeyID string
	Step  string
	Err   error
}

func (e ErrKeyCSRFailed) Error() string {
	return fmt.Sprintf("failed to create a CSR for key %s: %s: %v", e.KeyID, e.Step, e.Err)
}

func (e ErrKeyCSRFailed) Unwrap() error {
	return e.Err
}

// newKeyCSRCommand creates the key csr subcommand
func newKeyCSRCommand(getFlags func() *cli.CommonFlags) *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "csr <key-id>",
		Short: "Create a certificate signing request signed by a KMS key",
		Long: `Create a PEM certificate signing request for an asymmetric KMS key.

The request carries the key's public key as the KMS reports it and the key ID
as its common name, and the KMS signs it: the private key never leaves the
KMS. Certify it for code signing with 'platformctl ca sign-csr', which needs
the ca:sign-csr scope; the CA stores the certificate under the key ID, where
KMS signers look it up.

Examples:
  # Certify the Raspberry Pi fleet signing key
  platformctl kms key csr rpi/fleet --out fleet.csr
  platformctl ca sign-csr fleet.csr --out fleet.pem`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runKeyCSR(getFlags(), args[0], out)
		},
	}

	cmd.Flags().StringVar(&out, "out", "", "Write the CSR to this file instead of stdout")

	return cmd
}

// runKeyCSR opens the SDK connections and delegates to createKeyCSR.
func runKeyCSR(flags *cli.CommonFlags, keyID, out string) error {
	base, err := cli.NewBaseCommand(flags)
	if err != nil {
		return err
	}
	defer base.Close()

	client, err := openKMSClient(base)
	if err != nil {
		return err
	}
	csrPEM, err := createKeyCSR(base.Context(), client, base.Client().KMS(), keyID)
	if err != nil {
		return err
	}
	return writeOutputData(out, csrPEM, false)
}

// createKeyCSR builds a PEM CSR for keyID: the public key comes from keys,
// and the signature from the KMS through signer, so the request proves the
// KMS holds the private key.
func createKeyCSR(ctx context.Context, keys quicbaassdk.KMSClient, signer secureboot.KMSSignClient, keyID string) ([]byte, error) {
	resp, err := keys.GetPublicKey(ctx, keyID)
	if err != nil {
		return nil, ErrKeyCSRFailed{KeyID: keyID, Step: "fetching the public key", Err: err}
	}
	public, err := parseKMSPublicKey(resp.PublicKey)
	if err != nil {
		return nil, ErrKeyCSRFailed{KeyID: keyID, Step: "parsing the public key", Err: err}
	}
	kmsSigner, err := secureboot.NewKMSKeySigner(signer, keyID, public)
	if err != nil {
		return nil, ErrKeyCSRFailed{KeyID: keyID, Step: "opening the key", Err: err}
	}

	// CreateCertificateRequest checks the signature against the public key,
	// so a KMS that signs with a key other than the one it reports fails
	// here rather than at the CA.
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: keyID}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, kmsSigner)
	if err != nil {
		return nil, ErrKeyCSRFailed{KeyID: keyID, Step: "signing the request", Err: err}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// parseKMSPublicKey parses a PKIX public key, PEM-armoured or raw DER.
func parseKMSPublicKey(raw []byte) (crypto.PublicKey, error) {
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	return x509.ParsePKIXPublicKey(raw)
}
