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
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	"github.com/jeremyhahn/go-trusted-platform/pkg/memguard"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"
)

// testPin is a syntactically valid SPKI SHA-256 pin; the fake certificate
// manager never dials, so it only has to satisfy the trust resolver.
var testPin = strings.Repeat("ab", sha256.Size)

// fakeCertManager is an in-memory bmc.CertificateManager that records the
// replacement it was asked to install.
type fakeCertManager struct {
	cert       *x509.Certificate
	getErr     error
	replaceErr error

	replacedCert []byte
	replacedKey  string
	closed       bool
}

func (f *fakeCertManager) GetWebCertificate(_ context.Context) (*x509.Certificate, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.cert, nil
}

func (f *fakeCertManager) ReplaceWebCertificate(_ context.Context, certPEM []byte, keyPEM *memguard.MemoryEnclave) error {
	if f.replaceErr != nil {
		return f.replaceErr
	}
	f.replacedCert = certPEM
	f.replacedKey = string(keyPEM.Bytes())
	return nil
}

func (f *fakeCertManager) Backend() bmc.CertBackend { return bmc.CertBackendRedfish }

func (f *fakeCertManager) Close() error {
	f.closed = true
	return nil
}

// withFakeCertManager swaps the standalone certificate manager constructor
// and returns a pointer to the config it was opened with.
func withFakeCertManager(t *testing.T, mgr *fakeCertManager, newErr error) **bmc.Config {
	t.Helper()
	var got *bmc.Config
	orig := newStandaloneCertManager
	newStandaloneCertManager = func(cfg *bmc.Config, _ *slog.Logger) (standaloneCertManager, error) {
		got = cfg
		if newErr != nil {
			return nil, newErr
		}
		return mgr, nil
	}
	t.Cleanup(func() { newStandaloneCertManager = orig })
	return &got
}

// newTestCert builds a self-signed certificate with one DNS and one IP SAN
// that expires ten and a half days from now.
func newTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0xbeef),
		Subject:      pkix.Name{CommonName: "bmc.example"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(10*24*time.Hour + 12*time.Hour),
		DNSNames:     []string{"bmc.example"},
		IPAddresses:  []net.IP{net.ParseIP("192.0.2.10")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// writeCertFiles writes a PEM certificate and key pair into a temp dir.
func writeCertFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, []byte("CERT-PEM"), 0o600))
	require.NoError(t, os.WriteFile(keyPath, []byte("KEY-PEM"), 0o600))
	return certPath, keyPath
}

func daemonCert() *platformv1.BMCGetWebCertificateResponse {
	return &platformv1.BMCGetWebCertificateResponse{
		Subject:                 "CN=bmc-7",
		Issuer:                  "CN=Platform CA",
		SerialNumber:            "0a1b",
		NotBefore:               timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		NotAfter:                timestamppb.New(time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)),
		DaysRemaining:           75,
		SubjectAlternativeNames: []string{"bmc-7.lan", "10.0.0.7"},
		Fingerprint:             "deadbeef",
	}
}

const wantDaemonCertTable = "Subject:        CN=bmc-7\n" +
	"Issuer:         CN=Platform CA\n" +
	"Serial Number:  0a1b\n" +
	"Not Before:     2026-01-02T03:04:05Z\n" +
	"Not After:      2027-01-02T03:04:05Z\n" +
	"Days Remaining: 75\n" +
	"SANs:           bmc-7.lan, 10.0.0.7\n" +
	"Fingerprint:    deadbeef\n"

func TestDaemonCertGet_Table(t *testing.T) {
	// status shares get's implementation; both must render the same view.
	for _, sub := range []string{"get", "status"} {
		t.Run(sub, func(t *testing.T) {
			srv := &inProcBMCServer{cert: daemonCert()}
			table, _ := serveInProcBMC(t, srv)
			out, err := runBMC(t, table, "cert", sub, "--profile-id", "7")
			require.NoError(t, err)
			assert.Equal(t, wantDaemonCertTable, out)
			require.NotNil(t, srv.getCertReq)
			assert.Equal(t, uint64(7), srv.getCertReq.ProfileId)
		})
	}
}

func TestDaemonCertGet_TableWithoutSANs(t *testing.T) {
	resp := daemonCert()
	resp.SubjectAlternativeNames = nil
	table, _ := serveInProcBMC(t, &inProcBMCServer{cert: resp})
	out, err := runBMC(t, table, "cert", "get", "--profile-id", "7")
	require.NoError(t, err)
	assert.NotContains(t, out, "SANs:")
	assert.Equal(t, strings.Replace(wantDaemonCertTable, "SANs:           bmc-7.lan, 10.0.0.7\n", "", 1), out)
}

func TestDaemonCertGet_JSON(t *testing.T) {
	_, jsonFlags := serveInProcBMC(t, &inProcBMCServer{cert: daemonCert()})
	out, err := runBMC(t, jsonFlags, "cert", "get", "--profile-id", "7")
	require.NoError(t, err)

	var got bmcsvc.CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "CN=bmc-7", got.Subject)
	assert.Equal(t, "CN=Platform CA", got.Issuer)
	assert.Equal(t, "0a1b", got.SerialNumber)
	assert.Equal(t, int32(75), got.DaysRemaining)
	assert.Equal(t, []string{"bmc-7.lan", "10.0.0.7"}, got.SubjectAlternativeNames)
	assert.True(t, got.NotAfter.Equal(time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)))
}

func TestDaemonCertReplace(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{"with message", "web server restarted", "Profile: 7\nStatus:  success\nMessage: web server restarted\n"},
		{"without message", "", "Profile: 7\nStatus:  success\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &inProcBMCServer{replaceMsg: tt.message}
			table, _ := serveInProcBMC(t, srv)
			out, err := runBMC(t, table, "cert", "replace", "--profile-id", "7", "--cert", certPath, "--key", keyPath)
			require.NoError(t, err)
			assert.Equal(t, tt.want, out)
			require.NotNil(t, srv.replaceReq)
			assert.Equal(t, uint64(7), srv.replaceReq.ProfileId)
			assert.Equal(t, []byte("CERT-PEM"), srv.replaceReq.CertPem)
			assert.Equal(t, []byte("KEY-PEM"), srv.replaceReq.KeyPem)
		})
	}
}

func TestDaemonCertReplace_JSON(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	_, jsonFlags := serveInProcBMC(t, &inProcBMCServer{replaceMsg: "restarted"})
	out, err := runBMC(t, jsonFlags, "cert", "replace", "--profile-id", "7", "--cert", certPath, "--key", keyPath)
	require.NoError(t, err)
	assert.JSONEq(t, `{"profile_id":"7","status":"success","message":"restarted"}`, out)
}

func TestDaemonCert_ServerErrors(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	tests := []struct {
		args   []string
		action string
	}{
		{[]string{"cert", "get", "--profile-id", "7"}, "get"},
		{[]string{"cert", "replace", "--profile-id", "7", "--cert", certPath, "--key", keyPath}, "replace"},
	}
	for _, tt := range tests {
		t.Run(tt.action, func(t *testing.T) {
			table, _ := serveInProcBMC(t, &inProcBMCServer{err: status.Error(codes.Unavailable, "bmc offline")})
			out, err := runBMC(t, table, tt.args...)
			var failed *bmcsvc.ErrCertificateFailed
			require.ErrorAs(t, err, &failed)
			assert.Equal(t, tt.action, failed.Action)
			assert.Equal(t, uint64(7), failed.ProfileID)
			assert.Empty(t, out)
		})
	}
}

func TestDaemonCert_ValidationErrors(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, err error)
	}{
		{"get without profile", []string{"cert", "get"}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrProfileIDRequired))
		}},
		{"get with bad profile", []string{"cert", "get", "--profile-id", "seven"}, func(t *testing.T, err error) {
			var parse ErrProfileIDParseFailed
			require.ErrorAs(t, err, &parse)
			assert.Equal(t, "seven", parse.Value)
		}},
		{"replace without profile", []string{"cert", "replace", "--cert", certPath, "--key", keyPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrProfileIDRequired))
		}},
		{"replace without cert", []string{"cert", "replace", "--profile-id", "7", "--key", keyPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrCertFileRequired))
		}},
		{"replace without key", []string{"cert", "replace", "--profile-id", "7", "--cert", certPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrKeyFileRequired))
		}},
		{"replace with bad profile", []string{"cert", "replace", "--profile-id", "-1", "--cert", certPath, "--key", keyPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrProfileIDParseFailed))
		}},
		{"replace with missing cert", []string{"cert", "replace", "--profile-id", "7", "--cert", missing, "--key", keyPath}, func(t *testing.T, err error) {
			var read ErrCertFileReadFailed
			require.ErrorAs(t, err, &read)
			assert.Equal(t, missing, read.Path)
			assert.ErrorIs(t, err, fs.ErrNotExist)
		}},
		{"replace with missing key", []string{"cert", "replace", "--profile-id", "7", "--cert", certPath, "--key", missing}, func(t *testing.T, err error) {
			var read ErrKeyFileReadFailed
			require.ErrorAs(t, err, &read)
			assert.Equal(t, missing, read.Path)
			assert.ErrorIs(t, err, fs.ErrNotExist)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runBMC(t, tableGetFlags(), tt.args...)
			require.Error(t, err)
			tt.check(t, err)
			assert.Empty(t, out)
		})
	}
}

func TestStandaloneCertGet_Table(t *testing.T) {
	cert := newTestCert(t)
	mgr := &fakeCertManager{cert: cert}
	cfg := withFakeCertManager(t, mgr, nil)

	out, err := runBMC(t, tableGetFlags(), withArgs([]string{"cert", "get", "--bmc-pin", testPin}, standaloneIPMIArgs...)...)
	require.NoError(t, err)

	sum := sha256.Sum256(cert.Raw)
	want := "Subject:        CN=bmc.example\n" +
		"Issuer:         CN=bmc.example\n" +
		"Serial Number:  beef\n" +
		"Not Before:     " + cert.NotBefore.UTC().Format(time.RFC3339) + "\n" +
		"Not After:      " + cert.NotAfter.UTC().Format(time.RFC3339) + "\n" +
		"Days Remaining: 10\n" +
		"SANs:           bmc.example, 192.0.2.10\n" +
		"Fingerprint:    " + hex.EncodeToString(sum[:]) + "\n"
	assert.Equal(t, want, out)
	assert.True(t, mgr.closed, "manager must be closed after use")

	// The web certificate lives on the HTTPS interface, so an IPMI
	// session is upgraded to Redfish on its default port with the pin.
	require.NotNil(t, *cfg)
	assert.Equal(t, bmc.ProtocolRedfish, (*cfg).Protocol)
	assert.Equal(t, 443, (*cfg).Port)
	assert.Equal(t, "192.0.2.10", (*cfg).Address)
	assert.NotNil(t, (*cfg).TLS)
}

func TestStandaloneCertStatus_JSON(t *testing.T) {
	cert := newTestCert(t)
	withFakeCertManager(t, &fakeCertManager{cert: cert}, nil)

	out, err := runBMC(t, jsonGetFlags(), withArgs([]string{"cert", "status", "--bmc-pin", testPin}, standaloneIPMIArgs...)...)
	require.NoError(t, err)

	var got bmcsvc.CertificateInfo
	require.NoError(t, json.Unmarshal([]byte(out), &got))
	assert.Equal(t, "CN=bmc.example", got.Subject)
	assert.Equal(t, "beef", got.SerialNumber)
	assert.Equal(t, int32(10), got.DaysRemaining)
	assert.Equal(t, []string{"bmc.example", "192.0.2.10"}, got.SubjectAlternativeNames)
}

func TestStandaloneCertReplace(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	tests := []struct {
		name  string
		flags func() *cli.CommonFlags
		check func(t *testing.T, out string)
	}{
		{"table", tableGetFlags(), func(t *testing.T, out string) {
			assert.Equal(t, "Host:    192.0.2.10\nStatus:  success\nMessage: certificate replaced and BMC web server restarted\n", out)
		}},
		{"json", jsonGetFlags(), func(t *testing.T, out string) {
			assert.JSONEq(t, `{"profile_id":"192.0.2.10","status":"success","message":"certificate replaced and BMC web server restarted"}`, out)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &fakeCertManager{}
			withFakeCertManager(t, mgr, nil)
			out, err := runBMC(t, tt.flags, withArgs([]string{"cert", "replace", "--bmc-pin", testPin, "--cert", certPath, "--key", keyPath}, standaloneIPMIArgs...)...)
			require.NoError(t, err)
			tt.check(t, out)
			assert.Equal(t, []byte("CERT-PEM"), mgr.replacedCert)
			assert.Equal(t, "KEY-PEM", mgr.replacedKey)
			assert.True(t, mgr.closed)
		})
	}
}

func TestStandaloneCert_ManagerErrorsPropagate(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	boom := errors.New("redfish session refused")
	tests := []struct {
		name string
		mgr  *fakeCertManager
		args []string
	}{
		{"get", &fakeCertManager{getErr: boom}, []string{"cert", "get"}},
		{"replace", &fakeCertManager{replaceErr: boom}, []string{"cert", "replace", "--cert", certPath, "--key", keyPath}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withFakeCertManager(t, tt.mgr, nil)
			args := withArgs(append(tt.args, "--bmc-pin", testPin), standaloneIPMIArgs...)
			out, err := runBMC(t, tableGetFlags(), args...)
			require.ErrorIs(t, err, boom)
			assert.Empty(t, out)
			assert.True(t, tt.mgr.closed)
		})
	}
}

func TestStandaloneCert_ManagerConstructionError(t *testing.T) {
	boom := errors.New("no certificate backend")
	withFakeCertManager(t, nil, boom)
	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"cert", "get", "--bmc-pin", testPin}, standaloneIPMIArgs...)...)
	require.ErrorIs(t, err, boom)
}

func TestStandaloneCert_ValidationErrors(t *testing.T) {
	certPath, keyPath := writeCertFiles(t)
	missing := filepath.Join(t.TempDir(), "missing.pem")
	tests := []struct {
		name  string
		args  []string
		check func(t *testing.T, err error)
	}{
		{"replace without cert", []string{"cert", "replace", "--key", keyPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrCertFileRequired))
		}},
		{"replace without key", []string{"cert", "replace", "--cert", certPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrKeyFileRequired))
		}},
		{"replace with missing cert", []string{"cert", "replace", "--cert", missing, "--key", keyPath}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrCertFileReadFailed))
			assert.ErrorIs(t, err, fs.ErrNotExist)
		}},
		{"replace with missing key", []string{"cert", "replace", "--cert", certPath, "--key", missing}, func(t *testing.T, err error) {
			assert.ErrorAs(t, err, new(ErrKeyFileReadFailed))
			assert.ErrorIs(t, err, fs.ErrNotExist)
		}},
		{"invalid protocol", []string{"cert", "get", "--bmc-protocol", "telnet"}, func(t *testing.T, err error) {
			var proto ErrBMCInvalidProtocol
			require.ErrorAs(t, err, &proto)
			assert.Equal(t, "telnet", proto.Value)
		}},
		{"pin and CA file", []string{"cert", "get", "--bmc-ca-file", certPath}, func(t *testing.T, err error) {
			var conflict ErrBMCFlagConflict
			require.ErrorAs(t, err, &conflict)
			assert.Equal(t, []string{"--bmc-pin", "--bmc-ca-file"}, conflict.Fields)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr := &fakeCertManager{}
			withFakeCertManager(t, mgr, nil)
			// Later flags win, so --bmc-protocol telnet overrides the ipmi default.
			args := withArgs(withArgs(standaloneIPMIArgs, "--bmc-pin", testPin), tt.args...)
			out, err := runBMC(t, tableGetFlags(), args...)
			require.Error(t, err)
			tt.check(t, err)
			assert.Empty(t, out)
			assert.Nil(t, mgr.replacedCert, "nothing may be uploaded after a validation error")
		})
	}
}

func TestStandaloneCert_NoPinNonInteractive(t *testing.T) {
	withStdin(t, "")
	mgr := &fakeCertManager{cert: newTestCert(t)}
	cfg := withFakeCertManager(t, mgr, nil)
	_, err := runBMC(t, tableGetFlags(), withArgs([]string{"cert", "get"}, standaloneIPMIArgs...)...)
	require.ErrorAs(t, err, new(ErrBMCNoPinOrCAFile))
	assert.Nil(t, *cfg, "no manager may be opened without a verified trust anchor")
}

func TestStandaloneCert_CAFileTrust(t *testing.T) {
	cert := newTestCert(t)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600))

	cfg := withFakeCertManager(t, &fakeCertManager{cert: cert}, nil)
	out, err := runBMC(t, tableGetFlags(), withArgs([]string{"cert", "get", "--bmc-ca-file", caPath}, standaloneIPMIArgs...)...)
	require.NoError(t, err)
	assert.Contains(t, out, "Subject:        CN=bmc.example\n")
	require.NotNil(t, *cfg)
	require.NotNil(t, (*cfg).TLS)

	tlsCfg, err := (*cfg).TLS.TLSConfig(context.Background(), "192.0.2.10:443")
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)
}
