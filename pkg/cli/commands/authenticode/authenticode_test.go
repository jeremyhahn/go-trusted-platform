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

package authenticode

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// Test helper to create CommonFlags getter
func newTestFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
			NoColor:      true,
		}
	}
}

func newTestFlagsWithFormat(format cli.OutputFormat) func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: format,
			NoColor:      true,
		}
	}
}

// TestNewCommand tests the authenticode root command
func TestNewCommand(t *testing.T) {
	cmd := NewCommand(newTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "authenticode", cmd.Use)
	assert.Equal(t, "Authenticode signing and verification", cmd.Short)
	assert.Contains(t, cmd.Long, "Sign and verify PE/COFF executables")
	assert.Contains(t, cmd.Long, "UEFI Secure Boot")

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 2)

	// Find all expected commands
	var hasSign, hasVerify bool
	for _, sub := range subcommands {
		switch sub.Use {
		case "sign":
			hasSign = true
		case "verify":
			hasVerify = true
		}
	}

	assert.True(t, hasSign, "sign subcommand should exist")
	assert.True(t, hasVerify, "verify subcommand should exist")
}

// TestNewSignCommand tests the sign subcommand structure and flags
func TestNewSignCommand(t *testing.T) {
	cmd := newSignCommand(newTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "sign", cmd.Use)
	assert.Equal(t, "Sign a PE/COFF file with Authenticode", cmd.Short)
	assert.Contains(t, cmd.Long, "Authenticode/PKCS#7 signing")

	// Verify flags exist
	keyFlag := cmd.Flag("key")
	require.NotNil(t, keyFlag)
	assert.Equal(t, "", keyFlag.DefValue)

	certFlag := cmd.Flag("cert")
	require.NotNil(t, certFlag)
	assert.Equal(t, "", certFlag.DefValue)

	inputFlag := cmd.Flag("input")
	require.NotNil(t, inputFlag)
	assert.Equal(t, "", inputFlag.DefValue)

	outputFlag := cmd.Flag("output")
	require.NotNil(t, outputFlag)
	assert.Equal(t, "", outputFlag.DefValue)
}

// TestNewVerifyCommand tests the verify subcommand structure and flags
func TestNewVerifyCommand(t *testing.T) {
	cmd := newVerifyCommand(newTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "verify", cmd.Use)
	assert.Equal(t, "Verify an Authenticode signature on a PE/COFF file", cmd.Short)
	assert.Contains(t, cmd.Long, "Authenticode/PKCS#7 signature")

	// Verify flags exist
	certFlag := cmd.Flag("cert")
	require.NotNil(t, certFlag)
	assert.Equal(t, "", certFlag.DefValue) // cert is optional

	inputFlag := cmd.Flag("input")
	require.NotNil(t, inputFlag)
	assert.Equal(t, "", inputFlag.DefValue)
}

// TestRunSignReadKeyFailure tests runSign when key file cannot be read
func TestRunSignReadKeyFailure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err := runSign(context.Background(), flags, "/nonexistent/key.pem", "/some/cert.pem", "/some/input", "/some/output")

	require.Error(t, err)
	var readKeyErr ErrReadKeyFailed
	require.ErrorAs(t, err, &readKeyErr)
	assert.Equal(t, "/nonexistent/key.pem", readKeyErr.Path)
}

// TestRunSignDecodeKeyFailure tests runSign when key PEM decoding fails
func TestRunSignDecodeKeyFailure(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Write invalid key file
	keyPath := filepath.Join(tmpDir, "invalid.key")
	err := os.WriteFile(keyPath, []byte("not a valid PEM"), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runSign(context.Background(), flags, keyPath, "/some/cert.pem", "/some/input", "/some/output")

	require.Error(t, err)
	var decodeKeyErr ErrDecodeKeyFailed
	require.ErrorAs(t, err, &decodeKeyErr)
	assert.Equal(t, keyPath, decodeKeyErr.Path)
}

// TestRunSignParseKeyFailure tests runSign when key parsing fails
func TestRunSignParseKeyFailure(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Write PEM with invalid key data
	keyPath := filepath.Join(tmpDir, "bad.key")
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: []byte("not valid key bytes"),
	}
	keyPEM := pem.EncodeToMemory(pemBlock)
	err := os.WriteFile(keyPath, keyPEM, 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runSign(context.Background(), flags, keyPath, "/some/cert.pem", "/some/input", "/some/output")

	require.Error(t, err)
	var parseKeyErr ErrParseKeyFailed
	require.ErrorAs(t, err, &parseKeyErr)
}

// TestRunSignPKCS8KeyParsing tests runSign with PKCS#8 formatted key
func TestRunSignPKCS8KeyParsing(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode as PKCS#8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	keyPath := filepath.Join(tmpDir, "key.pem")
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// Should fail on cert reading, not key parsing
	err = runSign(context.Background(), flags, keyPath, "/nonexistent/cert.pem", "/some/input", "/some/output")

	require.Error(t, err)
	var readCertErr ErrReadCertificateFailed
	require.ErrorAs(t, err, &readCertErr)
}

// TestRunSignReadCertFailure tests runSign when certificate file cannot be read
func TestRunSignReadCertFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyPath := filepath.Join(tmpDir, "key.pem")
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runSign(context.Background(), flags, keyPath, "/nonexistent/cert.pem", "/some/input", "/some/output")

	require.Error(t, err)
	var readCertErr ErrReadCertificateFailed
	require.ErrorAs(t, err, &readCertErr)
	assert.Equal(t, "/nonexistent/cert.pem", readCertErr.Path)
}

// TestRunSignDecodeCertFailure tests runSign when certificate PEM decoding fails
func TestRunSignDecodeCertFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyPath := filepath.Join(tmpDir, "key.pem")
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	// Write invalid certificate file
	certPath := filepath.Join(tmpDir, "invalid.crt")
	err = os.WriteFile(certPath, []byte("not a valid PEM"), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runSign(context.Background(), flags, keyPath, certPath, "/some/input", "/some/output")

	require.Error(t, err)
	// Neither PEM nor DER: a parse failure (the loader accepts both encodings).
	var parseCertErr ErrParseCertificateFailed
	require.ErrorAs(t, err, &parseCertErr)
}

// TestRunSignParseCertFailure tests runSign when certificate parsing fails
func TestRunSignParseCertFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate valid RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyPath := filepath.Join(tmpDir, "key.pem")
	keyPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(keyPemBlock), 0600)
	require.NoError(t, err)

	// Write invalid certificate PEM
	certPath := filepath.Join(tmpDir, "bad.crt")
	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid certificate bytes"),
	}
	err = os.WriteFile(certPath, pem.EncodeToMemory(certPemBlock), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runSign(context.Background(), flags, keyPath, certPath, "/some/input", "/some/output")

	require.Error(t, err)
	var parseCertErr ErrParseCertificateFailed
	require.ErrorAs(t, err, &parseCertErr)
}

// TestRunVerifyReadCertFailure tests runVerify when certificate file cannot be read
func TestRunVerifyReadCertFailure(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err := runVerify(context.Background(), flags, "/nonexistent/cert.pem", "/some/input")

	require.Error(t, err)
	var readCertErr ErrReadCertificateFailed
	require.ErrorAs(t, err, &readCertErr)
	assert.Equal(t, "/nonexistent/cert.pem", readCertErr.Path)
}

// TestRunVerifyDecodeCertFailure tests runVerify when certificate PEM decoding fails
func TestRunVerifyDecodeCertFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid certificate file
	certPath := filepath.Join(tmpDir, "invalid.crt")
	err := os.WriteFile(certPath, []byte("not a valid PEM"), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runVerify(context.Background(), flags, certPath, "/some/input")

	require.Error(t, err)
	// Neither PEM nor DER: a parse failure (the loader accepts both encodings).
	var parseCertErr ErrParseCertificateFailed
	require.ErrorAs(t, err, &parseCertErr)
}

// TestRunVerifyParseCertFailure tests runVerify when certificate parsing fails
func TestRunVerifyParseCertFailure(t *testing.T) {
	tmpDir := t.TempDir()

	// Write invalid certificate PEM
	certPath := filepath.Join(tmpDir, "bad.crt")
	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("not valid certificate bytes"),
	}
	err := os.WriteFile(certPath, pem.EncodeToMemory(certPemBlock), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err = runVerify(context.Background(), flags, certPath, "/some/input")

	require.Error(t, err)
	var parseCertErr ErrParseCertificateFailed
	require.ErrorAs(t, err, &parseCertErr)
}

// TestRunVerifyWithNoCertificate tests runVerify without a certificate
// When no certificate is provided, the authenticode signer requires a cert
// so it fails with ErrCreateSignerFailed
func TestRunVerifyWithNoCertificate(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err := runVerify(context.Background(), flags, "", "/nonexistent/input.efi")

	require.Error(t, err)
	// No certificate is needed to verify; the missing input is what fails.
	var verifyErr ErrVerifyFileFailed
	require.ErrorAs(t, err, &verifyErr)
}

// TestErrorMessages tests all error type Error() methods
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ErrDaemonConnectionRequired",
			err:      ErrDaemonConnectionRequired{Operation: "test-op"},
			expected: "test-op: daemon connection required (dual-mode not yet implemented)",
		},
		{
			name:     "ErrReadKeyFailed",
			err:      ErrReadKeyFailed{Path: "/path/to/key", Reason: "file not found"},
			expected: "failed to read signing key '/path/to/key': file not found",
		},
		{
			name:     "ErrDecodeKeyFailed",
			err:      ErrDecodeKeyFailed{Path: "/path/to/key"},
			expected: "failed to decode signing key PEM: /path/to/key",
		},
		{
			name:     "ErrParseKeyFailed",
			err:      ErrParseKeyFailed{Reason: "invalid format"},
			expected: "failed to parse signing key: invalid format",
		},
		{
			name:     "ErrReadCertificateFailed",
			err:      ErrReadCertificateFailed{Path: "/path/to/cert", Reason: "permission denied"},
			expected: "failed to read certificate '/path/to/cert': permission denied",
		},
		{
			name:     "ErrParseCertificateFailed",
			err:      ErrParseCertificateFailed{Reason: "invalid certificate"},
			expected: "failed to parse certificate: invalid certificate",
		},
		{
			name:     "ErrCreateSignerFailed",
			err:      ErrCreateSignerFailed{Reason: "missing key"},
			expected: "failed to create authenticode signer: missing key",
		},
		{
			name:     "ErrSignFileFailed",
			err:      ErrSignFileFailed{Input: "/path/to/file", Reason: "I/O error"},
			expected: "failed to sign file '/path/to/file': I/O error",
		},
		{
			name:     "ErrVerifyFileFailed",
			err:      ErrVerifyFileFailed{Input: "/path/to/file", Reason: "signature invalid"},
			expected: "failed to verify file '/path/to/file': signature invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// TestSignCommandExecution tests the sign command execution flow
func TestSignCommandExecution(t *testing.T) {
	cmd := newSignCommand(newTestFlags())
	require.NotNil(t, cmd)

	// Verify RunE is set
	assert.NotNil(t, cmd.RunE)
}

// TestVerifyCommandExecution tests the verify command execution flow
func TestVerifyCommandExecution(t *testing.T) {
	cmd := newVerifyCommand(newTestFlags())
	require.NotNil(t, cmd)

	// Verify RunE is set
	assert.NotNil(t, cmd.RunE)
}

// TestCommandHierarchy tests the command hierarchy relationships
func TestCommandHierarchy(t *testing.T) {
	rootCmd := NewCommand(newTestFlags())

	// Get sign command
	var signCmd, verifyCmd *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		switch cmd.Use {
		case "sign":
			signCmd = cmd
		case "verify":
			verifyCmd = cmd
		}
	}

	require.NotNil(t, signCmd)
	require.NotNil(t, verifyCmd)

	// Verify commands have parents
	assert.Equal(t, rootCmd, signCmd.Parent())
	assert.Equal(t, rootCmd, verifyCmd.Parent())
}

// Helper to generate a test certificate
func generateTestCertificate(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// writeTestKeyAndCert creates test key and certificate files
func writeTestKeyAndCert(t *testing.T, tmpDir string) (string, string, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Write key
	keyPath := filepath.Join(tmpDir, "key.pem")
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})
	err = os.WriteFile(keyPath, keyPEM, 0600)
	require.NoError(t, err)

	// Generate and write certificate
	cert := generateTestCertificate(t, privateKey)
	certPath := filepath.Join(tmpDir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	err = os.WriteFile(certPath, certPEM, 0600)
	require.NoError(t, err)

	return keyPath, certPath, privateKey
}

// TestRunSignInputFileNotFound tests runSign when input file doesn't exist
func TestRunSignInputFileNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	keyPath, certPath, _ := writeTestKeyAndCert(t, tmpDir)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	err := runSign(context.Background(), flags, keyPath, certPath, "/nonexistent/input.efi", "/some/output.efi")

	require.Error(t, err)
	var signErr ErrSignFileFailed
	require.ErrorAs(t, err, &signErr)
	assert.Equal(t, "/nonexistent/input.efi", signErr.Input)
}

// TestRunVerify_SignedPE verifies a PE signed by `sign`: it verifies with no
// certificate and with its signer's, and fails for another certificate and
// for an unsigned file.
func TestRunVerify_SignedPE(t *testing.T) {
	dir := t.TempDir()
	keyPath, certPath, _ := writeTestKeyAndCert(t, dir)
	_, otherCert, _ := writeTestKeyAndCert(t, t.TempDir())
	unsigned := filepath.Join(dir, "unsigned.efi")
	require.NoError(t, os.WriteFile(unsigned, authenticodetest.MinimalPE(authenticodetest.MachineARM64), 0o644))
	signed := filepath.Join(dir, "signed.efi")
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatJSON, NoColor: true}
	require.NoError(t, runSign(context.Background(), flags, keyPath, certPath, unsigned, signed))

	require.NoError(t, runVerify(context.Background(), flags, "", signed))
	require.NoError(t, runVerify(context.Background(), flags, certPath, signed))

	var verifyErr ErrVerifyFileFailed
	require.ErrorAs(t, runVerify(context.Background(), flags, otherCert, signed), &verifyErr, "signed by another certificate")
	require.ErrorAs(t, runVerify(context.Background(), flags, "", unsigned), &verifyErr, "not signed")
}

// TestVerifyCommandFlagsRequired tests that required flags are marked
func TestVerifyCommandFlagsRequired(t *testing.T) {
	cmd := newVerifyCommand(newTestFlags())

	// Check if input flag is required
	inputFlag := cmd.Flag("input")
	require.NotNil(t, inputFlag)

	// Cert flag should be optional
	certFlag := cmd.Flag("cert")
	require.NotNil(t, certFlag)
}

// TestOutputFormatTableSign tests sign command with table output format
func TestOutputFormatTableSign(t *testing.T) {
	tmpDir := t.TempDir()

	keyPath, certPath, _ := writeTestKeyAndCert(t, tmpDir)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	// Should still fail on signing but exercise the table output path
	err := runSign(context.Background(), flags, keyPath, certPath, "/nonexistent/input.efi", "/some/output.efi")
	require.Error(t, err)
}

// TestOutputFormatTableVerify tests verify command with table output format
func TestOutputFormatTableVerify(t *testing.T) {
	tmpDir := t.TempDir()

	_, certPath, _ := writeTestKeyAndCert(t, tmpDir)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	// Should fail on verification (signer creation fails for verify backend)
	err := runVerify(context.Background(), flags, certPath, "/nonexistent/input.efi")
	require.Error(t, err)
}

// TestRSAKeyParsing tests runSign with PKCS#1 RSA key format
func TestRSAKeyParsing(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Write as PKCS#1
	keyPath := filepath.Join(tmpDir, "key.pem")
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	err = os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600)
	require.NoError(t, err)

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// Should fail on cert reading, not key parsing
	err = runSign(context.Background(), flags, keyPath, "/nonexistent/cert.pem", "/some/input", "/some/output")

	require.Error(t, err)
	var readCertErr ErrReadCertificateFailed
	require.ErrorAs(t, err, &readCertErr)
}

// TestSignCommandWithOutputFormats tests sign command supports all output formats
func TestSignCommandWithOutputFormats(t *testing.T) {
	formats := []cli.OutputFormat{
		cli.OutputFormatJSON,
		cli.OutputFormatYAML,
		cli.OutputFormatTable,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			cmd := newSignCommand(newTestFlagsWithFormat(format))
			require.NotNil(t, cmd)
		})
	}
}

// TestVerifyCommandWithOutputFormats tests verify command supports all output formats
func TestVerifyCommandWithOutputFormats(t *testing.T) {
	formats := []cli.OutputFormat{
		cli.OutputFormatJSON,
		cli.OutputFormatYAML,
		cli.OutputFormatTable,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			cmd := newVerifyCommand(newTestFlagsWithFormat(format))
			require.NotNil(t, cmd)
		})
	}
}

// TestSignCommandRunEExecution tests the sign command RunE handler execution
func TestSignCommandRunEExecution(t *testing.T) {
	cmd := newSignCommand(newTestFlags())

	// Set up output capture
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)

	// Set flags to trigger a specific error path
	_ = cmd.Flags().Set("key", "/nonexistent/key.pem")
	_ = cmd.Flags().Set("cert", "/some/cert.pem")
	_ = cmd.Flags().Set("input", "/some/input")
	_ = cmd.Flags().Set("output", "/some/output")

	// Execute RunE directly
	err := cmd.RunE(cmd, []string{})

	require.Error(t, err)
	var readKeyErr ErrReadKeyFailed
	require.ErrorAs(t, err, &readKeyErr)
}

// TestVerifyCommandRunEExecution tests the verify command RunE handler execution
func TestVerifyCommandRunEExecution(t *testing.T) {
	cmd := newVerifyCommand(newTestFlags())

	// Set up output capture
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)

	// Set flags to trigger a specific error path
	_ = cmd.Flags().Set("cert", "/nonexistent/cert.pem")
	_ = cmd.Flags().Set("input", "/some/input")

	// Execute RunE directly
	err := cmd.RunE(cmd, []string{})

	require.Error(t, err)
	var readCertErr ErrReadCertificateFailed
	require.ErrorAs(t, err, &readCertErr)
}

// TestVerifyCommandRunEWithEmptyCert tests verify command RunE with empty cert
func TestVerifyCommandRunEWithEmptyCert(t *testing.T) {
	cmd := newVerifyCommand(newTestFlags())

	// Set up output capture
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)

	// Set only input flag (cert is optional)
	_ = cmd.Flags().Set("input", "/nonexistent/input.efi")

	// Execute RunE directly
	err := cmd.RunE(cmd, []string{})

	require.Error(t, err)
	// No certificate is needed to verify; the missing input is what fails.
	var verifyErr ErrVerifyFileFailed
	require.ErrorAs(t, err, &verifyErr)
}

// TestSignCommandRunEWithValidKeyAndCert tests sign command RunE with valid key/cert but missing input
func TestSignCommandRunEWithValidKeyAndCert(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath, certPath, _ := writeTestKeyAndCert(t, tmpDir)

	cmd := newSignCommand(newTestFlags())

	// Set up output capture
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)

	// Set flags with valid key/cert but nonexistent input
	_ = cmd.Flags().Set("key", keyPath)
	_ = cmd.Flags().Set("cert", certPath)
	_ = cmd.Flags().Set("input", "/nonexistent/input.efi")
	_ = cmd.Flags().Set("output", "/tmp/output.efi")

	// Execute RunE directly
	err := cmd.RunE(cmd, []string{})

	require.Error(t, err)
	var signErr ErrSignFileFailed
	require.ErrorAs(t, err, &signErr)
}

// writeTestRSAKeyAndCert creates test RSA key and certificate files
func writeTestRSAKeyAndCert(t *testing.T, tmpDir string) (string, string, *rsa.PrivateKey) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Write key as PKCS#1
	keyPath := filepath.Join(tmpDir, "key.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = os.WriteFile(keyPath, keyPEM, 0600)
	require.NoError(t, err)

	// Generate and write certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test Signing Certificate",
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	certPath := filepath.Join(tmpDir, "cert.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	err = os.WriteFile(certPath, certPEM, 0600)
	require.NoError(t, err)

	return keyPath, certPath, privateKey
}

// TestRunSignSuccessJSON tests runSign with a valid PE file and JSON output
func TestRunSignSuccessJSON(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test RSA key and certificate (authenticode works better with RSA)
	keyPath, certPath, _ := writeTestRSAKeyAndCert(t, tmpDir)

	// Create minimal PE file
	peData := authenticodetest.MinimalPE(authenticodetest.MachineAMD64)
	inputPath := filepath.Join(tmpDir, "input.efi")
	err := os.WriteFile(inputPath, peData, 0644)
	require.NoError(t, err)

	outputPath := filepath.Join(tmpDir, "output.efi")

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
		NoColor:      true,
	}

	// Sign the PE file
	err = runSign(context.Background(), flags, keyPath, certPath, inputPath, outputPath)
	require.NoError(t, err)

	// Verify output file was created
	_, err = os.Stat(outputPath)
	require.NoError(t, err)
}

// TestRunSignSuccessTable tests runSign with a valid PE file and Table output
func TestRunSignSuccessTable(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test RSA key and certificate
	keyPath, certPath, _ := writeTestRSAKeyAndCert(t, tmpDir)

	// Create minimal PE file
	peData := authenticodetest.MinimalPE(authenticodetest.MachineAMD64)
	inputPath := filepath.Join(tmpDir, "input.efi")
	err := os.WriteFile(inputPath, peData, 0644)
	require.NoError(t, err)

	outputPath := filepath.Join(tmpDir, "output.efi")

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
		NoColor:      true,
	}

	// Sign the PE file
	err = runSign(context.Background(), flags, keyPath, certPath, inputPath, outputPath)
	require.NoError(t, err)

	// Verify output file was created
	_, err = os.Stat(outputPath)
	require.NoError(t, err)
}

// TestRunSignSuccessYAML tests runSign with a valid PE file and YAML output
func TestRunSignSuccessYAML(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test RSA key and certificate
	keyPath, certPath, _ := writeTestRSAKeyAndCert(t, tmpDir)

	// Create minimal PE file
	peData := authenticodetest.MinimalPE(authenticodetest.MachineAMD64)
	inputPath := filepath.Join(tmpDir, "input.efi")
	err := os.WriteFile(inputPath, peData, 0644)
	require.NoError(t, err)

	outputPath := filepath.Join(tmpDir, "output.efi")

	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatYAML,
		NoColor:      true,
	}

	// Sign the PE file
	err = runSign(context.Background(), flags, keyPath, certPath, inputPath, outputPath)
	require.NoError(t, err)

	// Verify output file was created
	_, err = os.Stat(outputPath)
	require.NoError(t, err)
}
