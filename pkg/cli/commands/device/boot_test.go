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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning"
)

// quoteHelperEnv selects how this test binary behaves when a test runs it
// as a --quote-command program.
const quoteHelperEnv = "DEVICE_BOOT_QUOTE_HELPER"

// quoteHelpers are the behaviours of the test binary run as a quote
// command; each returns the process exit code.
var quoteHelpers = map[string]func(args []string) int{
	"echo": func(args []string) int {
		fmt.Print("evidence-over:" + args[1])
		return 0
	},
	"fail": func([]string) int {
		fmt.Fprint(os.Stderr, "tpm busy")
		return 3
	},
	"silent": func([]string) int { return 0 },
}

func TestMain(m *testing.M) {
	if helper, ok := quoteHelpers[os.Getenv(quoteHelperEnv)]; ok {
		os.Exit(helper(os.Args))
	}
	os.Exit(m.Run())
}

func bootFlags() *cli.CommonFlags { return &cli.CommonFlags{} }

func TestNewBootCommand_Subcommands(t *testing.T) {
	cmd := newBootCommand(bootFlags)

	names := map[string]bool{}
	for _, sub := range cmd.Commands() {
		names[sub.Use] = true
	}
	assert.True(t, names["certificate"])
	assert.True(t, names["delivery"])
}

func TestBootCommands_RequireTheirFlags(t *testing.T) {
	for _, args := range [][]string{
		{"certificate"},
		{"certificate", "--identity", "node-1"},
		{"certificate", "--key", "idevid.key"},
		{"delivery"},
	} {
		cmd := newBootCommand(bootFlags)
		cmd.SetArgs(args)
		cmd.SilenceUsage = true
		cmd.SilenceErrors = true

		assert.Error(t, cmd.Execute(), "%v must be refused before any connection is made", args)
	}
}

func TestBootCommands_NoLongerTakeProofBytes(t *testing.T) {
	cmd := newBootCommand(bootFlags)
	for _, sub := range cmd.Commands() {
		assert.Nil(t, sub.Flags().Lookup("signature"), "%s: a proof is made on the live connection", sub.Use)
		assert.Nil(t, sub.Flags().Lookup("evidence"), "%s: a proof is made on the live connection", sub.Use)
	}
}

func TestRunBootCertificate_RefusesAnUnreadableKeyBeforeConnecting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.key")

	err := runBootCertificate(bootFlags(), "node-1", path)

	var typed ErrBootKeyUnreadable
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, path, typed.Path)
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

// Each PEM key form the CLI accepts loads as a signer whose proof over a
// binding verifies against the key's public half.
func TestLoadBootSigner_SignsAVerifiableProof(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	cases := map[string]struct {
		block *pem.Block
		pub   any
	}{
		"PKCS#8":     {&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}, &ecKey.PublicKey},
		"SEC 1 EC":   {&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}, &ecKey.PublicKey},
		"PKCS#1 RSA": {&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}, &rsaKey.PublicKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			signer, err := loadBootSigner(writeKeyFile(t, pem.EncodeToMemory(tc.block)))
			require.NoError(t, err)

			binding := exporterValue(0x11)
			proof, err := signBootCertificate(signer, "node-1.example")(context.Background(), binding)
			require.NoError(t, err)
			assert.NoError(t, provisioning.VerifyBootCertificateProof(tc.pub, "node-1.example", binding, proof))
			assert.Error(t, provisioning.VerifyBootCertificateProof(tc.pub, "node-1.example", exporterValue(0x22), proof),
				"the proof is bound to the binding it was made over")
		})
	}
}

func TestLoadBootSigner_RefusesWhatIsNotASigningKey(t *testing.T) {
	cases := map[string]struct {
		contents []byte
		cause    bool
	}{
		"not PEM":        {[]byte("not a key"), false},
		"a certificate":  {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), false},
		"corrupt PKCS#8": {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}), true},
		"corrupt EC":     {pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1, 2, 3}}), true},
		"corrupt RSA":    {pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}), true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeKeyFile(t, tc.contents)

			signer, err := loadBootSigner(path)

			assert.Nil(t, signer)
			var typed ErrBootKeyUnreadable
			require.ErrorAs(t, err, &typed)
			assert.Equal(t, path, typed.Path)
			assert.Equal(t, tc.cause, typed.Unwrap() != nil)
			assert.Contains(t, err.Error(), path)
		})
	}
}

// An Ed25519 key loads, but an IDevID proof is RSA or ECDSA only, so the
// signing callback refuses it rather than sending a proof that cannot verify.
func TestSignBootCertificate_RefusesAKeyTypeTheProofDoesNotUse(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)
	signer, err := loadBootSigner(writeKeyFile(t, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	require.NoError(t, err)

	proof, err := signBootCertificate(signer, "node-1")(context.Background(), []byte("binding"))

	assert.Nil(t, proof)
	assert.Error(t, err)
}

// The quote command receives the live connection's binding, base64-encoded,
// as its only argument, and its stdout is the evidence.
func TestRunQuoteCommand_PassesTheBindingAndReturnsStdout(t *testing.T) {
	t.Setenv(quoteHelperEnv, "echo")
	binding := []byte{0x00, 0xff, 0x10, 0x20}

	evidence, err := runQuoteCommand(os.Args[0])(context.Background(), binding)

	require.NoError(t, err)
	assert.Equal(t, "evidence-over:"+base64.StdEncoding.EncodeToString(binding), string(evidence))
}

func TestRunQuoteCommand_RefusesAFailedOrSilentProgram(t *testing.T) {
	t.Run("exits non-zero", func(t *testing.T) {
		t.Setenv(quoteHelperEnv, "fail")

		evidence, err := runQuoteCommand(os.Args[0])(context.Background(), []byte("binding"))

		assert.Nil(t, evidence)
		var typed ErrBootQuoteCommandFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, "tpm busy", typed.Stderr)
		assert.Contains(t, err.Error(), "tpm busy")
	})

	t.Run("prints nothing", func(t *testing.T) {
		t.Setenv(quoteHelperEnv, "silent")

		evidence, err := runQuoteCommand(os.Args[0])(context.Background(), []byte("binding"))

		assert.Nil(t, evidence)
		var typed ErrBootQuoteCommandFailed
		require.ErrorAs(t, err, &typed)
		assert.NoError(t, typed.Unwrap())
		assert.Contains(t, err.Error(), "printed no evidence")
	})

	t.Run("does not exist", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "no-such-quote")

		_, err := runQuoteCommand(missing)(context.Background(), []byte("binding"))

		var typed ErrBootQuoteCommandFailed
		require.ErrorAs(t, err, &typed)
		assert.Equal(t, missing, typed.Command)
		assert.True(t, errors.Is(err, fs.ErrNotExist))
	})
}

func TestBootErrors_NameTheirSubject(t *testing.T) {
	assert.Contains(t, ErrBootCertificateFailed{Identity: "node-1", Reason: "refused"}.Error(), "node-1")
	assert.Contains(t, ErrBootDeliveryFailed{Reason: "refused"}.Error(), "refused")
}

// exporterValue is a stand-in for one connection's full-length exporter
// value, filled with fill.
func exporterValue(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, provisioning.BootChannelNonceSize)
}

func writeKeyFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "idevid.key")
	require.NoError(t, os.WriteFile(path, contents, 0o600))
	return path
}
