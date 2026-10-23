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

package agent

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const platformYAML = `tpm:
  device: /dev/tpmrm0
  idevid:
    handle: 0x81020000
    hash: SHA-256
    rsa:
      size: 2048
    signature-algorithm: SHA256-RSA
`

// writeFile writes data to name under a test directory and returns its path.
func writeFile(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, []byte(data), 0o600))
	return path
}

// useHostTPM makes OpenHostDevice open tpm (or fail with openErr) and
// records the configuration it was asked to open.
func useHostTPM(t *testing.T, tpm *fakeTPM, openErr error) **xkmssdk.TPMConfig {
	t.Helper()
	var opened *xkmssdk.TPMConfig
	saved := openHostTPM
	openHostTPM = func(cfg *xkmssdk.TPMConfig) (hostTPM, error) {
		opened = cfg
		if openErr != nil {
			return nil, openErr
		}
		return tpm, nil
	}
	t.Cleanup(func() { openHostTPM = saved })
	return &opened
}

func pemChain(certs ...*x509.Certificate) string {
	var out []byte
	for _, cert := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return string(out)
}

func TestOpenHostDevice_ReadsTheIDevIDFromTheTPM(t *testing.T) {
	tpm := newFakeTPM(t)
	opened := useHostTPM(t, tpm, nil)
	cfgPath := writeFile(t, "platformd.yaml", platformYAML)

	device, err := OpenHostDevice(HostDeviceOptions{ID: "laptop-1", ConfigPaths: []string{"/nonexistent/config.yaml", cfgPath}})
	require.NoError(t, err)

	require.NotNil(t, *opened)
	assert.Equal(t, "/dev/tpmrm0", (*opened).Device)
	require.NotNil(t, (*opened).IDevID)
	host, err := os.Hostname()
	require.NoError(t, err)
	assert.Equal(t, host+"-idevid", (*opened).IDevID.CN, "named as platformd names it")
	assert.Equal(t, "laptop-1", device.ID())
	cert, err := device.Certificate()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{tpm.idevid.Raw}, cert.Certificate)

	require.NoError(t, device.Close())
	assert.True(t, tpm.closed)
}

func TestHostDevice_CloseFailureIsTyped(t *testing.T) {
	tpm := newFakeTPM(t)
	useHostTPM(t, tpm, nil)
	device, err := OpenHostDevice(HostDeviceOptions{ID: "laptop-1", ConfigPaths: []string{writeFile(t, "platformd.yaml", platformYAML)}})
	require.NoError(t, err)

	tpm.closeErr = errors.New("transport closed")
	err = device.Close()
	var closeErr *ErrDeviceClose
	require.ErrorAs(t, err, &closeErr)
	assert.ErrorIs(t, err, tpm.closeErr)
}

func TestOpenHostDevice_ReadsTheChainFromCertFile(t *testing.T) {
	tpm := newFakeTPM(t)
	tpm.certErr = errors.New("certificate store not configured")
	useHostTPM(t, tpm, nil)
	issuer := deviceCertificate(t, "issuing-ca")
	certFile := writeFile(t, "idevid.pem", "# exported\n"+pemChain(tpm.idevid, issuer.Leaf))

	device, err := OpenHostDevice(HostDeviceOptions{
		ConfigPaths: []string{writeFile(t, "platformd.yaml", platformYAML)},
		CertFile:    certFile,
	})
	require.NoError(t, err)

	cert, err := device.Certificate()
	require.NoError(t, err)
	assert.Equal(t, [][]byte{tpm.idevid.Raw, issuer.Leaf.Raw}, cert.Certificate)
	assert.Empty(t, device.ID(), "no id is needed to disconnect")
}

func TestOpenHostDevice_NoTPMIsErrNoDevice(t *testing.T) {
	cases := map[string]struct {
		paths   func(t *testing.T) []string
		openErr error
	}{
		"no configuration": {
			paths: func(t *testing.T) []string { return []string{filepath.Join(t.TempDir(), "absent.yaml")} },
		},
		"no tpm section": {
			paths: func(t *testing.T) []string { return []string{writeFile(t, "platformd.yaml", "log-level: info\n")} },
		},
		"the TPM does not open": {
			paths:   func(t *testing.T) []string { return []string{writeFile(t, "platformd.yaml", platformYAML)} },
			openErr: errors.New("open /dev/tpmrm0: no such file or directory"),
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			useHostTPM(t, newFakeTPM(t), tc.openErr)
			_, err := OpenHostDevice(HostDeviceOptions{ID: "laptop-1", ConfigPaths: tc.paths(t)})
			var none *ErrNoDevice
			require.ErrorAs(t, err, &none)
			assert.Contains(t, err.Error(), "this host has no TPM device identity for the VPN client")
			assert.Equal(t, ExitFailure, ExitCode(err))
			if tc.openErr != nil {
				assert.ErrorIs(t, err, tc.openErr)
			}
		})
	}
}

func TestOpenHostDevice_BadConfiguration(t *testing.T) {
	useHostTPM(t, newFakeTPM(t), nil)
	cases := map[string]string{
		"not YAML":   writeFile(t, "platformd.yaml", "tpm: [unterminated\n"),
		"unreadable": t.TempDir(),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := OpenHostDevice(HostDeviceOptions{ConfigPaths: []string{path}})
			var bad *ErrPlatformConfig
			require.ErrorAs(t, err, &bad)
			assert.Equal(t, path, bad.Path)
		})
	}
}

func TestOpenHostDevice_IdentityFailuresCloseTheTPM(t *testing.T) {
	cfgPath := writeFile(t, "platformd.yaml", platformYAML)
	cases := map[string]struct {
		setup func(t *testing.T, tpm *fakeTPM) HostDeviceOptions
		check func(t *testing.T, err error)
	}{
		"no certificate in the TPM": {
			setup: func(t *testing.T, tpm *fakeTPM) HostDeviceOptions {
				tpm.certErr = errors.New("certificate store not configured")
				return HostDeviceOptions{}
			},
			check: func(t *testing.T, err error) {
				var missing *ErrIDevIDCertificate
				require.ErrorAs(t, err, &missing)
				assert.Contains(t, err.Error(), "--idevid-cert")
			},
		},
		"unreadable cert file": {
			setup: func(t *testing.T, tpm *fakeTPM) HostDeviceOptions {
				return HostDeviceOptions{CertFile: filepath.Join(t.TempDir(), "absent.pem")}
			},
			check: func(t *testing.T, err error) {
				var missing *ErrIDevIDCertificate
				require.ErrorAs(t, err, &missing)
				assert.ErrorIs(t, err, os.ErrNotExist)
			},
		},
		"cert file without a certificate": {
			setup: func(t *testing.T, tpm *fakeTPM) HostDeviceOptions {
				return HostDeviceOptions{CertFile: writeFile(t, "idevid.pem", "not pem\n")}
			},
			check: func(t *testing.T, err error) {
				var none *ErrNoCertificate
				require.ErrorAs(t, err, &none)
			},
		},
		"cert file with a corrupt certificate": {
			setup: func(t *testing.T, tpm *fakeTPM) HostDeviceOptions {
				block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
				return HostDeviceOptions{CertFile: writeFile(t, "idevid.pem", string(block))}
			},
			check: func(t *testing.T, err error) {
				var missing *ErrIDevIDCertificate
				require.ErrorAs(t, err, &missing)
			},
		},
		"no IDevID key": {
			setup: func(t *testing.T, tpm *fakeTPM) HostDeviceOptions {
				tpm.signerErr = errors.New("invalid key attributes")
				return HostDeviceOptions{}
			},
			check: func(t *testing.T, err error) {
				var none *ErrNoDevice
				require.ErrorAs(t, err, &none)
			},
		},
		"close fails too": {
			setup: func(t *testing.T, tpm *fakeTPM) HostDeviceOptions {
				tpm.signerErr = errors.New("invalid key attributes")
				tpm.closeErr = errors.New("transport closed")
				return HostDeviceOptions{}
			},
			check: func(t *testing.T, err error) {
				var closeErr *ErrDeviceClose
				require.ErrorAs(t, err, &closeErr)
				var none *ErrNoDevice
				require.ErrorAs(t, err, &none)
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tpm := newFakeTPM(t)
			useHostTPM(t, tpm, nil)
			opts := tc.setup(t, tpm)
			opts.ConfigPaths = []string{cfgPath}
			device, err := OpenHostDevice(opts)
			assert.Nil(t, device)
			tc.check(t, err)
			assert.True(t, tpm.closed, "a TPM opened for a device that could not be built is closed")
		})
	}
}

func TestOpenXKMSTPM_RequiresAnIDevIDSection(t *testing.T) {
	_, err := openXKMSTPM(&xkmssdk.TPMConfig{Device: "/dev/tpmrm0"})
	var none *ErrNoIDevIDConfig
	require.ErrorAs(t, err, &none)
}

func TestXKMSTPM_IDevIDSignerFromConfiguration(t *testing.T) {
	cfg, err := loadTPMConfig([]string{writeFile(t, "platformd.yaml", platformYAML)})
	require.NoError(t, err)
	require.NoError(t, identityCNs(cfg, func() (string, error) { return "laptop-1", nil }))

	signer, err := (&xkmsTPM{idevid: cfg.IDevID}).IDevIDSigner()
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestXKMSTPM_IDevIDSignerNeedsAName(t *testing.T) {
	cfg, err := loadTPMConfig([]string{writeFile(t, "platformd.yaml", platformYAML)})
	require.NoError(t, err)
	tpm := &xkmsTPM{idevid: cfg.IDevID}
	_, err = tpm.IDevIDSigner()
	require.Error(t, err)
}

func TestIdentityCNs_NamesUnnamedKeysAfterTheHost(t *testing.T) {
	cfg := &xkmssdk.TPMConfig{
		IAK:    &xkmssdk.IAKConfig{},
		IDevID: &xkmssdk.IDevIDConfig{CN: "configured"},
	}
	require.NoError(t, identityCNs(cfg, func() (string, error) { return "laptop-1", nil }))
	assert.Equal(t, "laptop-1-iak", cfg.IAK.CN)
	assert.Equal(t, "configured", cfg.IDevID.CN, "a configured name is kept")
}

func TestIdentityCNs_NamedKeysNeedNoHostname(t *testing.T) {
	cfg := &xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{CN: "configured"}}
	hostnameErr := errors.New("uname failed")
	require.NoError(t, identityCNs(cfg, func() (string, error) { return "", hostnameErr }))
}

func TestIdentityCNs_HostnameFailureIsErrNoDevice(t *testing.T) {
	cfg := &xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{}}
	hostnameErr := errors.New("uname failed")
	err := identityCNs(cfg, func() (string, error) { return "", hostnameErr })
	var none *ErrNoDevice
	require.ErrorAs(t, err, &none)
	assert.ErrorIs(t, err, hostnameErr)
	assert.Empty(t, cfg.IDevID.CN)
}
