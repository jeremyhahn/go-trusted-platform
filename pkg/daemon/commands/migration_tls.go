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
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// migrationCertIssuer is the narrow slice of the platform CA the migration TLS
// machinery needs: issue a leaf certificate and read the CA trust bundle. The
// platform CA reached through the QuicBaaS SDK
// (quicbaasca.CACertificateAuthority, i.e. app.CA) satisfies it, and unit tests
// fake it without standing up a real CA. Keeping the dependency this narrow is
// the interface-segregation counterpart of the vtpmCAAdapter seam.
type migrationCertIssuer interface {
	IssueCertificate(ctx context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error)
	CABundle() ([]byte, error)
}

// caMigrationTLS provisions QEMU migration tls-creds-x509 material from platform
// CA certificates, reached through the QuicBaaS SDK CA surface (the same CA
// app.CA / the vTPM EK issuer use). It satisfies BOTH migration TLS seams:
//
//   - compute.MigrationTLSProvider (source side): EnsureTLSCreds issues a
//     short-lived CLIENT certificate, writes QEMU's expected client-cert.pem /
//     client-key.pem / ca-cert.pem into a private directory, and adds a
//     tls-creds-x509 (endpoint=client, verify-peer=on) object on the live source
//     QMP session.
//   - compute.MigrationServerTLSProvider (destination side): MaterializeServerCreds
//     issues a short-lived SERVER certificate for the receiver hostname and lays
//     out server-cert.pem / server-key.pem / ca-cert.pem for the receiving
//     QEMU's "-object tls-creds-x509,endpoint=server".
//
// Every migration stream is therefore mutually authenticated against the shared
// platform CA. No plaintext channel and no InsecureSkipVerify is ever configured.
type caMigrationTLS struct {
	ca      migrationCertIssuer
	baseDir string
	logger  *logging.Logger
}

// Compile-time proof the concrete satisfies both migration TLS seams.
var (
	_ compute.MigrationTLSProvider       = (*caMigrationTLS)(nil)
	_ compute.MigrationServerTLSProvider = (*caMigrationTLS)(nil)
)

// migrationCertValidityDays is the lifetime of an issued migration certificate.
// Migrations complete in seconds to minutes; a one-day certificate is generous
// headroom while keeping the credential short-lived.
const migrationCertValidityDays = 1

// ErrMigrationTLSNoCA is returned when a caMigrationTLS is constructed or used
// without a backing certificate authority. newCAMigrationTLS returns nil for a
// nil CA so callers fail closed (the orchestrator then reports
// ErrMigrationTLSNotConfigured), but the guard keeps the type safe if built
// directly.
type ErrMigrationTLSNoCA struct{}

// Error returns a human-readable description of the error.
func (ErrMigrationTLSNoCA) Error() string {
	return "migration TLS: certificate authority is not configured"
}

// ErrMigrationTLSIssue wraps a CA issuance failure for a migration certificate.
type ErrMigrationTLSIssue struct {
	Role  string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrMigrationTLSIssue) Error() string {
	return fmt.Sprintf("migration TLS: %s certificate issuance failed: %v", e.Role, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigrationTLSIssue) Unwrap() error { return e.Cause }

// ErrMigrationTLSWrite wraps a failure to lay out the QEMU credential files.
type ErrMigrationTLSWrite struct {
	Path  string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrMigrationTLSWrite) Error() string {
	return fmt.Sprintf("migration TLS: failed to write %s: %v", e.Path, e.Cause)
}

// Unwrap returns the underlying cause.
func (e ErrMigrationTLSWrite) Unwrap() error { return e.Cause }

// newCAMigrationTLS builds a migration TLS provider over ca. It returns nil when
// ca is nil so the orchestrator fails closed on migration rather than attempting
// a plaintext transfer. baseDir is where per-migration credential directories
// are created; when empty it defaults to a subdirectory of the OS temp dir.
func newCAMigrationTLS(ca migrationCertIssuer, baseDir string, logger *logging.Logger) *caMigrationTLS {
	if ca == nil {
		return nil
	}
	if baseDir == "" {
		baseDir = filepath.Join(os.TempDir(), "platformd-migration-tls")
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &caMigrationTLS{ca: ca, baseDir: baseDir, logger: logger}
}

// EnsureTLSCreds implements compute.MigrationTLSProvider. It issues a client
// migration certificate, materializes the QEMU client credential directory, and
// installs a tls-creds-x509 (endpoint=client) object on the source session.
func (m *caMigrationTLS) EnsureTLSCreds(ctx context.Context, session compute.MigrationSession, endpoint *compute.IncomingEndpoint) (string, error) {
	if m.ca == nil {
		return "", ErrMigrationTLSNoCA{}
	}

	hostname, _ := os.Hostname()
	commonName := fmt.Sprintf("migration-client-%s-%s", hostname, randomToken())

	dir, err := m.issueCredsDir(ctx, "client", commonName, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		return "", err
	}

	credsID := "migtls-client-" + randomToken()
	props := map[string]interface{}{
		"dir":         dir,
		"endpoint":    "client",
		"verify-peer": true,
	}
	if err := session.ObjectAdd(ctx, "tls-creds-x509", credsID, props); err != nil {
		_ = os.RemoveAll(dir)
		return "", &ErrMigrationTLSWrite{Path: dir, Cause: err}
	}
	m.logger.Debugf("Installed source migration TLS creds %s (dir %s) pinning %s", credsID, dir, endpoint.TLSHostname)
	return credsID, nil
}

// MaterializeServerCreds implements compute.MigrationServerTLSProvider. It issues
// a server migration certificate for hostname and lays out the QEMU server
// credential directory. The returned cleanup removes that directory.
func (m *caMigrationTLS) MaterializeServerCreds(ctx context.Context, hostname string) (string, func(), error) {
	if m.ca == nil {
		return "", func() {}, ErrMigrationTLSNoCA{}
	}
	commonName := fmt.Sprintf("migration-server-%s-%s", hostname, randomToken())
	dir, err := m.issueCredsDir(ctx, "server", commonName, []string{hostname}, x509.ExtKeyUsageServerAuth)
	if err != nil {
		return "", func() {}, err
	}
	cleanup := func() {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			m.logger.Warnf("migration TLS: failed to remove server creds dir %s: %v", dir, rmErr)
		}
	}
	return dir, cleanup, nil
}

// issueCredsDir issues a certificate and writes the QEMU tls-creds-x509 file
// trio (<role>-cert.pem, <role>-key.pem, ca-cert.pem) into a fresh private
// directory, returning the directory path.
func (m *caMigrationTLS) issueCredsDir(ctx context.Context, role, commonName string, dnsSANs []string, eku x509.ExtKeyUsage) (string, error) {
	req := &quicbaasca.CACertificateRequest{
		Subject:     quicbaasca.CASubject{CommonName: commonName},
		Valid:       migrationCertValidityDays,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	if len(dnsSANs) > 0 {
		req.SANS = &quicbaasca.CASubjectAlternativeNames{DNS: dnsSANs}
	}

	issued, err := m.ca.IssueCertificate(ctx, req)
	if err != nil {
		return "", &ErrMigrationTLSIssue{Role: role, Cause: err}
	}

	caPEM := issued.CACertificatePEM
	if len(caPEM) == 0 {
		bundle, bundleErr := m.ca.CABundle()
		if bundleErr != nil {
			return "", &ErrMigrationTLSIssue{Role: role, Cause: bundleErr}
		}
		caPEM = bundle
	}

	dir := filepath.Join(m.baseDir, role+"-"+randomToken())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", &ErrMigrationTLSWrite{Path: dir, Cause: err}
	}

	files := map[string][]byte{
		filepath.Join(dir, role+"-cert.pem"): issued.CertificatePEM,
		filepath.Join(dir, role+"-key.pem"):  issued.PrivateKeyPEM,
		filepath.Join(dir, "ca-cert.pem"):    caPEM,
	}
	for path, data := range files {
		if len(data) == 0 {
			_ = os.RemoveAll(dir)
			return "", &ErrMigrationTLSWrite{Path: path, Cause: &ErrMigrationTLSIssue{Role: role, Cause: os.ErrInvalid}}
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			_ = os.RemoveAll(dir)
			return "", &ErrMigrationTLSWrite{Path: path, Cause: err}
		}
	}
	return dir, nil
}

// randomToken returns a short random hex token used to keep migration
// certificate common names and credential directories unique.
func randomToken() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic; fall back to a fixed marker so the
		// caller still produces a usable (if less unique) identifier rather than
		// panicking in the migration path.
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
