package diskimage

import (
	"bytes"
	"context"
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
	"sync"
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
	key, cert := rsaKeyPair(t, 2048)
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
	key, cert := rsaKeyPair(t, 2048)
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
		"no certificate for the fleet key": {
			args: signArgs,
			clients: func() (*pkgiso.KMSClients, error) {
				return &pkgiso.KMSClients{
					KMS: &secureboottest.KMS{Key: key},
					CA:  &secureboottest.CA{Certs: map[string]*x509.Certificate{}},
				}, nil
			},
			as: new(*ErrEEPROMHSMSign),
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

// failingWriter is a stdout that refuses every write, as a closed pipe does.
type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

// TestRPIEEPROMHSMCommand_ReportsAnUnwritableSignature checks that a
// signature rpi-eeprom-digest never receives is a failure, not a silent
// success: the wrapper's caller would otherwise sign with nothing.
func TestRPIEEPROMHSMCommand_ReportsAnUnwritableSignature(t *testing.T) {
	key, cert := rsaKeyPair(t, 2048)
	clients := func() (*pkgiso.KMSClients, error) {
		return &pkgiso.KMSClients{
			KMS: &secureboottest.KMS{Key: key},
			CA:  &secureboottest.CA{Certs: map[string]*x509.Certificate{"rpi/fleet": cert}},
		}, nil
	}
	input := filepath.Join(t.TempDir(), "bootconf.txt")
	require.NoError(t, os.WriteFile(input, []byte("SIGNED_BOOT=1\n"), 0o644))
	closed := errors.New("write |1: broken pipe")

	cmd := newRPIEEPROMHSMCommandWithClients(func() *cli.CommonFlags { return &cli.CommonFlags{} }, clients)
	cmd.SetOut(failingWriter{err: closed})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--fleet-key", "kms://rpi/fleet", "-a", "rsa2048-sha256", input})

	err := cmd.Execute()
	var signErr *ErrEEPROMHSMSign
	require.ErrorAs(t, err, &signErr)
	assert.Equal(t, "writing the signature", signErr.Step)
	assert.ErrorIs(t, err, closed)
}

// TestRPIEEPROMHSMCommand_ValidatesBeforeConnecting runs the production
// command, which reaches the KMS through the operator's platform client: a
// bad invocation is refused before any connection is opened, so the lazy
// client closes cleanly and the refusal is what the caller sees.
func TestRPIEEPROMHSMCommand_ValidatesBeforeConnecting(t *testing.T) {
	input := filepath.Join(t.TempDir(), "bootconf.txt")
	require.NoError(t, os.WriteFile(input, []byte("SIGNED_BOOT=1\n"), 0o644))

	var out bytes.Buffer
	cmd := newRPIEEPROMHSMCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"-a", "rsa2048-sha256", input})

	err := cmd.Execute()
	var flagErr *ErrEEPROMHSMFlag
	require.ErrorAs(t, err, &flagErr)
	assert.Equal(t, "fleet-key", flagErr.Flag)
	assert.Empty(t, out.String())
}

// TestRunRPIEEPROMHSM_NilFlagsAreRefused checks that a nil flag set is an
// unsupported (empty) algorithm, never a nil dereference.
func TestRunRPIEEPROMHSM_NilFlagsAreRefused(t *testing.T) {
	clients := func() (*pkgiso.KMSClients, error) {
		t.Fatal("the KMS is reached with no flags")
		return nil, nil
	}
	err := runRPIEEPROMHSM(context.Background(), nil, "unused", clients, &bytes.Buffer{})
	var algErr *ErrEEPROMHSMAlgorithm
	require.ErrorAs(t, err, &algErr)
	assert.Empty(t, algErr.Algorithm)
}

// rsaKeyPair returns the shared RSA key of the given size and a self-signed
// "fleet" certificate for it, as secureboottest.KeyPair does for a fresh key.
func rsaKeyPair(t *testing.T, bits int) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	fixture, ok := rsaFixtures[bits]
	require.True(t, ok, "no RSA fixture of %d bits", bits)
	pair, err := fixture()
	require.NoError(t, err)
	return pair.key, pair.cert
}

// rsaFixture is an RSA key and a self-signed certificate for it.
type rsaFixture struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// rsaFixtures generates each key size once per run: RSA key generation is
// the slowest step of these tests, and no test changes a key.
var rsaFixtures = map[int]func() (rsaFixture, error){
	2048: sync.OnceValues(func() (rsaFixture, error) { return newRSAFixture(2048) }),
	3072: sync.OnceValues(func() (rsaFixture, error) { return newRSAFixture(3072) }),
}

func newRSAFixture(bits int) (rsaFixture, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return rsaFixture{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fleet"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return rsaFixture{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return rsaFixture{}, err
	}
	return rsaFixture{key: key, cert: cert}, nil
}
