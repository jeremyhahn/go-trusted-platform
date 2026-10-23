package diskimage

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot/secureboottest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestRPIEEPROMHSMCommand_MatchesUpstreamWrapperContract(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	kms := &secureboottest.KMS{Key: key}
	ca := &secureboottest.CA{Certs: map[string]*x509.Certificate{"rpi/fleet": cert}}
	input := filepath.Join(t.TempDir(), "bootconf.txt")
	require.NoError(t, os.WriteFile(input, []byte("SIGNED_BOOT=1\n"), 0o644))

	var out bytes.Buffer
	cmd := newRPIEEPROMHSMCommandWithClients(func() *cli.CommonFlags { return &cli.CommonFlags{} }, func() (*pkgiso.KMSClients, error) {
		return &pkgiso.KMSClients{KMS: kms, CA: ca}, nil
	})
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--fleet-key", "kms://rpi/fleet", "-a", "rsa2048-sha256", input})

	require.NoError(t, cmd.Execute())
	sigHex := strings.TrimSpace(out.String())
	sig, err := hex.DecodeString(sigHex)
	require.NoError(t, err)
	assert.Equal(t, strings.ToLower(sigHex), sigHex)

	digest := sha256.Sum256([]byte("SIGNED_BOOT=1\n"))
	require.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig))
	assert.Equal(t, "rpi/fleet", kms.LastReq.GetKeyId())
	assert.Equal(t, platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256, kms.LastReq.GetHashAlgorithm())
	assert.True(t, kms.LastReq.GetPreHashed())
	assert.Equal(t, digest[:], kms.LastReq.GetMessage())
}

func TestRPIEEPROMHSMCommand_Errors(t *testing.T) {
	key, cert := secureboottest.KeyPair(t, "fleet")
	clientsFor := func(kms *secureboottest.KMS, cert *x509.Certificate) pkgiso.KMSClientsFunc {
		return func() (*pkgiso.KMSClients, error) {
			return &pkgiso.KMSClients{
				KMS: kms,
				CA:  &secureboottest.CA{Certs: map[string]*x509.Certificate{"rpi/fleet": cert}},
			}, nil
		}
	}
	refusal := errors.New("kms: key disabled")
	bigKey, bigCert := rsaKeyPair(t, 3072)
	input := filepath.Join(t.TempDir(), "bootconf.txt")
	require.NoError(t, os.WriteFile(input, []byte("SIGNED_BOOT=1\n"), 0o644))
	signArgs := []string{"--fleet-key", "kms://rpi/fleet", "-a", "rsa2048-sha256", input}

	tests := map[string]struct {
		args    []string
		clients pkgiso.KMSClientsFunc
		as      any
		is      error
	}{
		"algorithm":   {args: []string{"--fleet-key", "kms://rpi/fleet", "-a", "sha256", input}, as: new(*ErrEEPROMHSMAlgorithm)},
		"missing key": {args: []string{"-a", "rsa2048-sha256", input}, as: new(*ErrEEPROMHSMFlag)},
		"missing file": {
			args: []string{"--fleet-key", "kms://rpi/fleet", "-a", "rsa2048-sha256", filepath.Join(t.TempDir(), "missing")},
			as:   new(*ErrEEPROMHSMSign),
		},
		"no platform connection": {
			args:    signArgs,
			clients: func() (*pkgiso.KMSClients, error) { return nil, refusal },
			as:      new(*ErrEEPROMHSMSign),
			is:      refusal,
		},
		"a fleet key that is not RSA-2048": {
			args:    signArgs,
			clients: clientsFor(&secureboottest.KMS{Key: bigKey}, bigCert),
			as:      new(*rpibootsig.KeyBitsError),
		},
		"the KMS refuses to sign": {
			args:    signArgs,
			clients: clientsFor(&secureboottest.KMS{Key: key, Err: refusal}, cert),
			as:      new(*rpibootsig.SignError),
			is:      refusal,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			clients := tc.clients
			if clients == nil {
				clients = clientsFor(&secureboottest.KMS{Key: key}, cert)
			}
			var out bytes.Buffer
			cmd := newRPIEEPROMHSMCommandWithClients(func() *cli.CommonFlags { return &cli.CommonFlags{} }, clients)
			cmd.SetOut(&out)
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tc.args)
			err := cmd.Execute()
			require.Error(t, err)
			assert.ErrorAs(t, err, tc.as)
			if tc.is != nil {
				assert.ErrorIs(t, err, tc.is)
			}
			assert.Empty(t, out.String(), "no signature is printed on failure")
		})
	}
}

// rsaKeyPair is secureboottest.KeyPair for a key of another size.
func rsaKeyPair(t *testing.T, bits int) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fleet"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return key, cert
}
