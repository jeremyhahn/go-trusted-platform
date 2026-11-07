// Copyright (c) 2024 Jeremy Hahn
// Copyright (c) 2024 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed under the GNU Affero General Public
// License v3.0 and a Commercial License. See LICENSE file in the root
// directory.

package commands

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptedIssuer is a migrationCertIssuer that returns a fixed issued
// certificate and CA bundle. Like the platform CA it refuses a request
// without a subject, and it records every request and bundle read.
type scriptedIssuer struct {
	issued      quicbaasca.IssuedCertificate
	bundle      []byte
	bundleErr   error
	requests    []*quicbaasca.CACertificateRequest
	bundleCalls int
}

func (s *scriptedIssuer) IssueCertificate(_ context.Context, req *quicbaasca.CACertificateRequest) (*quicbaasca.IssuedCertificate, error) {
	if req == nil || req.Subject.CommonName == "" {
		return nil, &MessageError{Msg: "certificate request has no common name"}
	}
	s.requests = append(s.requests, req)
	issued := s.issued
	return &issued, nil
}

func (s *scriptedIssuer) CABundle() ([]byte, error) {
	s.bundleCalls++
	if s.bundleErr != nil {
		return nil, s.bundleErr
	}
	return s.bundle, nil
}

func TestIssueCredsDir_CAMaterialAndFailures(t *testing.T) {
	leafPEM, keyPEM := generateSelfSigned("vm1.example")
	issuedCAPEM, _ := generateSelfSigned("issuing-ca")
	bundlePEM, _ := generateSelfSigned("bundle-ca")
	bundleDown := &MessageError{Msg: "bundle unavailable"}

	cases := []struct {
		name string
		// base returns the directory the provider writes under.
		base            func(t *testing.T) string
		issuer          *scriptedIssuer
		wantCA          []byte
		wantBundleCalls int
		check           func(t *testing.T, base string, err error)
	}{
		{
			name:            "no CA PEM on the issued certificate falls back to the bundle",
			base:            func(t *testing.T) string { return t.TempDir() },
			issuer:          &scriptedIssuer{issued: quicbaasca.IssuedCertificate{CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM}, bundle: bundlePEM},
			wantCA:          bundlePEM,
			wantBundleCalls: 1,
		},
		{
			name:            "the issued CA PEM is used without reading the bundle",
			base:            func(t *testing.T) string { return t.TempDir() },
			issuer:          &scriptedIssuer{issued: quicbaasca.IssuedCertificate{CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM, CACertificatePEM: issuedCAPEM}, bundle: bundlePEM},
			wantCA:          issuedCAPEM,
			wantBundleCalls: 0,
		},
		{
			name:            "a bundle failure is an issue error and writes nothing",
			base:            func(t *testing.T) string { return t.TempDir() },
			issuer:          &scriptedIssuer{issued: quicbaasca.IssuedCertificate{CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM}, bundleErr: bundleDown},
			wantBundleCalls: 1,
			check: func(t *testing.T, base string, err error) {
				var issueErr *ErrMigrationTLSIssue
				require.ErrorAs(t, err, &issueErr)
				assert.Equal(t, "server", issueErr.Role)
				assert.ErrorIs(t, err, bundleDown)
				entries, readErr := os.ReadDir(base)
				require.NoError(t, readErr)
				assert.Empty(t, entries)
			},
		},
		{
			name:   "a base directory that is a file is a write error",
			base:   regularFile,
			issuer: &scriptedIssuer{issued: quicbaasca.IssuedCertificate{CertificatePEM: leafPEM, PrivateKeyPEM: keyPEM, CACertificatePEM: issuedCAPEM}},
			check: func(t *testing.T, base string, err error) {
				var writeErr *ErrMigrationTLSWrite
				require.ErrorAs(t, err, &writeErr)
				assert.True(t, strings.HasPrefix(writeErr.Path, filepath.Join(base, "server-")), writeErr.Path)
				assert.Error(t, writeErr.Cause)
			},
		},
		{
			name:   "an empty private key is refused and the directory removed",
			base:   func(t *testing.T) string { return t.TempDir() },
			issuer: &scriptedIssuer{issued: quicbaasca.IssuedCertificate{CertificatePEM: leafPEM, CACertificatePEM: issuedCAPEM}},
			check: func(t *testing.T, base string, err error) {
				var writeErr *ErrMigrationTLSWrite
				require.ErrorAs(t, err, &writeErr)
				assert.Equal(t, "server-key.pem", filepath.Base(writeErr.Path))
				var issueErr *ErrMigrationTLSIssue
				require.ErrorAs(t, err, &issueErr)
				assert.Equal(t, "server", issueErr.Role)
				assert.ErrorIs(t, err, os.ErrInvalid)
				entries, readErr := os.ReadDir(base)
				require.NoError(t, readErr)
				assert.Empty(t, entries, "a partial credential directory must not be left behind")
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := tc.base(t)
			prov := newCAMigrationTLS(tc.issuer, base, logging.DefaultLogger())
			require.NotNil(t, prov)

			dir, err := prov.issueCredsDir(context.Background(), "server", "vm1.example", []string{"vm1.example"}, x509.ExtKeyUsageServerAuth)
			assert.Equal(t, tc.wantBundleCalls, tc.issuer.bundleCalls)
			require.Len(t, tc.issuer.requests, 1)
			assert.Equal(t, "vm1.example", tc.issuer.requests[0].Subject.CommonName)
			if tc.check != nil {
				require.Error(t, err)
				assert.Empty(t, dir)
				tc.check(t, base, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, base, filepath.Dir(dir))
			info, statErr := os.Stat(dir)
			require.NoError(t, statErr)
			assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
			want := map[string][]byte{"server-cert.pem": leafPEM, "server-key.pem": keyPEM, "ca-cert.pem": tc.wantCA}
			for name, data := range want {
				got, readErr := os.ReadFile(filepath.Join(dir, name))
				require.NoError(t, readErr, name)
				assert.Equal(t, data, got, name)
			}
		})
	}
}

func TestApplyDaemonTLSIdentity_UnwritableTLSDirFailsClosed(t *testing.T) {
	platformDir := regularFile(t)
	cfg := tlsTransportConfig()

	err := applyDaemonTLSIdentity(context.Background(), newTestLogger(), &app.App{CA: newFakeKeystoreCA(t), PlatformDir: platformDir}, cfg, true)
	var persist ErrProvisionPersist
	require.ErrorAs(t, err, &persist)
	assert.Equal(t, daemonTLSDir(platformDir), persist.Path)
	assert.Error(t, persist.Cause)
	assert.Nil(t, cfg.TLSIdentity, "no identity is served when the TLS directory cannot be created")
	assert.Nil(t, cfg.MTLSClientCAPool)
	assert.False(t, cfg.EnableMTLS)
}

func TestInitSDNEnrollmentHook_BuildsOrRefuses(t *testing.T) {
	eng, err := policy.NewEngine(policy.Config{
		BridgeName:     "br-fabric",
		FlowController: nullOVSPort{},
		PortController: nullOVSPort{},
		Zones:          zone.Defaults(),
		Logger:         quietLogger(),
	})
	require.NoError(t, err)

	storage := quicbaas.NewMockStorage()
	require.NoError(t, storage.Start(context.Background()))
	ds := device.NewDatastore(storage, logging.NewLogger(logging.LevelTrace, nil))
	profiles, err := device.NewProfileService(ds)
	require.NoError(t, err)
	devices, err := device.NewService(ds)
	require.NoError(t, err)

	t.Run("a real profile service builds the hook", func(t *testing.T) {
		logger, logs := bufferLogger()
		hook := initSDNEnrollmentHook(eng, devices, profiles, zone.Defaults(), logger)
		require.NotNil(t, hook)
		assert.Contains(t, logs.String(), "SDN enrollment hook initialized")
		assert.Contains(t, logs.String(), "resolved_zones")
		assert.NotContains(t, logs.String(), "failed to construct SDN enrollment hook")
	})
	t.Run("a profile service without a DAO is refused", func(t *testing.T) {
		logger, logs := bufferLogger()
		assert.Nil(t, initSDNEnrollmentHook(eng, devices, &device.ProfileService{}, zone.Defaults(), logger))
		assert.Contains(t, logs.String(), "failed to construct SDN enrollment hook")
		assert.Contains(t, logs.String(), "profile DAO is required")
	})
}
