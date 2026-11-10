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

package daemon

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	xkmsbackend "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/backend"
	xkmsca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	certstore "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/certstore"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// issueGatewaydFromPlatformCA issues gatewayd's client certificate from a
// real in-memory platform root CA and returns it with a pool of that root.
func issueGatewaydFromPlatformCA(t *testing.T, trustDomain string) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	ctx := context.Background()
	root, _, err := xkmsca.NewCA(ctx, &xkmsca.Params{
		Identity: []xkmsca.CAIdentity{{
			Subject: xkmsca.CASubject{CommonName: "gatewayd-test-root", Organization: "Test Org", Country: "US"},
			Valid:   1,
			Keys: []*xkmssdk.KeyConfig{{
				KeyAlgorithm:       "RSA",
				Hash:               "SHA-256",
				SignatureAlgorithm: "SHA256-RSAPSS",
				RSAConfig:          &xkmssdk.KeyRSAConfig{KeySize: 2048},
			}},
			KeystoreType: xkmssdk.StoreSoftware,
			IsRoot:       true,
		}},
		KeyStoreFactory: func(string) (xkmsbackend.Backend, error) {
			pkcs8, err := xkmssdk.NewPKCS8Backend(&xkmssdk.PKCS8BackendConfig{
				KeyStorage:         xkmssdk.NewStorageMemory(),
				AllowPlaintextKeys: true,
			})
			if err != nil {
				return nil, err
			}
			return xkmssdk.NewServiceBackend(&xkmssdk.ServiceBackendConfig{
				Backend:     pkcs8,
				CertStorage: xkmssdk.NewStorageMemory(),
			})
		},
		CertStoreFactory: func(string) (certstore.CertStore, error) {
			return xkmssdk.NewCertStore(&xkmssdk.CertStoreConfig{
				CertStorage: xkmssdk.NewStorageCertAdapter(xkmssdk.NewStorageMemory()),
			})
		},
	})
	require.NoError(t, err)
	require.NotNil(t, root)

	csrPEM := issuancetest.CSRFrom(t, newECKey(t), &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "gw-01", Organization: []string{app.SystemTenantID}},
	})
	leaf, err := root.SignCSR(ctx, csrPEM, &xkmsca.SignOptions{
		ValidityDays:      1,
		KeyUsage:          x509.KeyUsageDigitalSignature,
		ExtKeyUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		SPIFFETrustDomain: trustDomain,
		TenantID:          app.SystemTenantID,
		SPIFFEKind:        "svc",
		SPIFFEName:        "gatewayd",
	})
	require.NoError(t, err)

	tcg, ok := root.(xkmsca.CACertificateAuthority)
	require.True(t, ok, "the platform CA must implement the TCG CA surface")
	bundlePEM, err := tcg.CABundle()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(bundlePEM))
	return leaf, pool
}

// A gatewayd certificate the platform CA issues through its service-identity
// path is a service principal, and the interceptor holds it to gatewayd's role.
func TestMTLSServicePrincipal_PlatformCAIssuedIdentity(t *testing.T) {
	leaf, pool := issueGatewaydFromPlatformCA(t, testOperatorTrustDomain)

	require.Len(t, leaf.URIs, 1)
	require.Equal(t, "spiffe://platform.test/tenant/system/svc/gatewayd", leaf.URIs[0].String())
	require.Equal(t, []string{app.SystemTenantID}, leaf.Subject.Organization)

	service, ok := mtlsServicePrincipal(leaf, testOperatorTrustDomain)
	assert.True(t, ok)
	assert.Equal(t, "gatewayd", service)
	assert.False(t, isMTLSPrincipal(leaf, testOperatorTrustDomain), "a service principal gets no platform grant")

	f := newInstallerScopeFixture(t)
	f.config.MTLSClientCAPool = pool

	method := platformv1.ProxyService_GetProxyConfig_FullMethodName
	reached, err := f.callUnary(t, leaf, method)
	require.NoError(t, err, method)
	assert.True(t, reached, "gatewayd must reach %s", method)

	method = platformv1.ProxyService_ReloadProxyConfig_FullMethodName
	reached, err = f.callUnary(t, leaf, method)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), method)
	assert.Contains(t, status.Convert(err).Message(),
		ErrMTLSServiceMethodDenied{Service: "gatewayd", Method: method}.Error())
	assert.False(t, reached, "gatewayd must not reach %s", method)
}
