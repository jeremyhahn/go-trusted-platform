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

package commands

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Shared test doubles (used by both migration_tls_test and
// migration_coordinator_test)
// =============================================================================

// fakeCAIssuer is a minimal migrationCertIssuer that returns real, verifiable
// self-signed PEM material so tls.X509KeyPair and CertPool.AppendCertsFromPEM
// succeed without standing up a real platform CA.
type fakeCAIssuer struct {
	issueErr  error
	bundleErr error
	lastReq   *quicbaasca.CACertificateRequest
}

func (f *fakeCAIssuer) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	f.lastReq = req
	if f.issueErr != nil {
		return nil, f.issueErr
	}
	certPEM, keyPEM := generateSelfSigned(req.Subject.CommonName)
	return &quicbaasca.IssuedCertificate{
		CertificatePEM:   certPEM,
		PrivateKeyPEM:    keyPEM,
		CACertificatePEM: certPEM, // self-signed: the leaf is its own trust anchor
	}, nil
}

func (f *fakeCAIssuer) CABundle() ([]byte, error) {
	if f.bundleErr != nil {
		return nil, f.bundleErr
	}
	certPEM, _ := generateSelfSigned("test-ca")
	return certPEM, nil
}

// generateSelfSigned returns a PEM cert + PKCS#8 key for the given common name.
func generateSelfSigned(cn string) (certPEM, keyPEM []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:              []string{cn},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// fakeMigrationSession records ObjectAdd and no-ops the rest of the
// compute.MigrationSession contract.
type fakeMigrationSession struct {
	objectType string
	objectID   string
	objectDir  string
	objectEP   string
	verifyPeer bool
	addErr     error
}

func (f *fakeMigrationSession) Pause(context.Context) error  { return nil }
func (f *fakeMigrationSession) Resume(context.Context) error { return nil }
func (f *fakeMigrationSession) ObjectAdd(_ context.Context, qomType, id string, props map[string]interface{}) error {
	if f.addErr != nil {
		return f.addErr
	}
	f.objectType = qomType
	f.objectID = id
	if v, ok := props["dir"].(string); ok {
		f.objectDir = v
	}
	if v, ok := props["endpoint"].(string); ok {
		f.objectEP = v
	}
	if v, ok := props["verify-peer"].(bool); ok {
		f.verifyPeer = v
	}
	return nil
}
func (f *fakeMigrationSession) SetParameters(context.Context, *qemu.MigrationParams) error {
	return nil
}
func (f *fakeMigrationSession) SetCapabilities(context.Context, []string) error { return nil }
func (f *fakeMigrationSession) Migrate(context.Context, string) error           { return nil }
func (f *fakeMigrationSession) Status(context.Context) (*qemu.MigrationStatus, error) {
	return &qemu.MigrationStatus{}, nil
}
func (f *fakeMigrationSession) Cancel(context.Context) error { return nil }
func (f *fakeMigrationSession) Quit(context.Context) error   { return nil }

// =============================================================================
// caMigrationTLS tests
// =============================================================================

func TestNewCAMigrationTLS_NilCA(t *testing.T) {
	require.Nil(t, newCAMigrationTLS(nil, "", nil))
}

func TestCAMigrationTLS_EnsureTLSCreds(t *testing.T) {
	ca := &fakeCAIssuer{}
	prov := newCAMigrationTLS(ca, t.TempDir(), logging.DefaultLogger())
	require.NotNil(t, prov)

	sess := &fakeMigrationSession{}
	credsID, err := prov.EnsureTLSCreds(context.Background(), sess, &compute.IncomingEndpoint{TLSHostname: "dest.example"})
	require.NoError(t, err)
	assert.Contains(t, credsID, "migtls-client-")

	// The client credential object is installed on the source session,
	// under the ID handed back for the migrate call to reference.
	assert.Equal(t, "tls-creds-x509", sess.objectType)
	assert.Equal(t, credsID, sess.objectID)
	assert.Equal(t, "client", sess.objectEP)
	assert.True(t, sess.verifyPeer)
	require.NotEmpty(t, sess.objectDir)

	// QEMU's expected client credential trio exists.
	for _, name := range []string{"client-cert.pem", "client-key.pem", "ca-cert.pem"} {
		_, statErr := os.Stat(filepath.Join(sess.objectDir, name))
		require.NoError(t, statErr, name)
	}

	// The issued client certificate carries the ClientAuth EKU.
	require.NotNil(t, ca.lastReq)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ca.lastReq.ExtKeyUsage)
}

func TestCAMigrationTLS_EnsureTLSCreds_IssueError(t *testing.T) {
	ca := &fakeCAIssuer{issueErr: errors.New("ca down")}
	prov := newCAMigrationTLS(ca, t.TempDir(), logging.DefaultLogger())

	_, err := prov.EnsureTLSCreds(context.Background(), &fakeMigrationSession{}, &compute.IncomingEndpoint{})
	require.Error(t, err)
	var issueErr *ErrMigrationTLSIssue
	require.True(t, errors.As(err, &issueErr))
	assert.Equal(t, "client", issueErr.Role)
}

func TestCAMigrationTLS_EnsureTLSCreds_ObjectAddError(t *testing.T) {
	ca := &fakeCAIssuer{}
	prov := newCAMigrationTLS(ca, t.TempDir(), logging.DefaultLogger())

	_, err := prov.EnsureTLSCreds(context.Background(), &fakeMigrationSession{addErr: errors.New("qmp closed")}, &compute.IncomingEndpoint{})
	require.Error(t, err)
	var writeErr *ErrMigrationTLSWrite
	require.True(t, errors.As(err, &writeErr))
}

func TestCAMigrationTLS_MaterializeServerCreds(t *testing.T) {
	ca := &fakeCAIssuer{}
	prov := newCAMigrationTLS(ca, t.TempDir(), logging.DefaultLogger())

	dir, cleanup, err := prov.MaterializeServerCreds(context.Background(), "dest.example")
	require.NoError(t, err)
	require.NotEmpty(t, dir)

	for _, name := range []string{"server-cert.pem", "server-key.pem", "ca-cert.pem"} {
		_, statErr := os.Stat(filepath.Join(dir, name))
		require.NoError(t, statErr, name)
	}
	// Server cert carries the hostname SAN and ServerAuth EKU.
	require.NotNil(t, ca.lastReq)
	require.NotNil(t, ca.lastReq.SANS)
	assert.Equal(t, []string{"dest.example"}, ca.lastReq.SANS.DNS)
	assert.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ca.lastReq.ExtKeyUsage)

	// Cleanup removes the directory.
	cleanup()
	_, statErr := os.Stat(dir)
	assert.True(t, os.IsNotExist(statErr))
}

func TestCAMigrationTLS_MaterializeServerCreds_IssueError(t *testing.T) {
	ca := &fakeCAIssuer{issueErr: errors.New("ca down")}
	prov := newCAMigrationTLS(ca, t.TempDir(), logging.DefaultLogger())

	_, _, err := prov.MaterializeServerCreds(context.Background(), "dest.example")
	require.Error(t, err)
	var issueErr *ErrMigrationTLSIssue
	require.True(t, errors.As(err, &issueErr))
	assert.Equal(t, "server", issueErr.Role)
}
