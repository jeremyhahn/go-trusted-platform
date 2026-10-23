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

package adminclaim_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance/issuancetest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/adminclaim"
)

// The admin bundle /init hands the operator is the certificate admin-claim
// later demands: the two sides must agree on the system-admin identity.
func TestInitAdminBundle_PassesTheAdminClaimVerifier(t *testing.T) {
	ca := issuancetest.NewCA(t)
	identity := backends.AdminIdentity{TrustDomain: "tp.internal", TenantID: app.SystemTenantID}

	bundle, err := backends.NewAdminBundleIssuer(backends.PlatformCertIssuer(ca, nil), identity).
		IssueAdminBundle(context.Background())
	require.NoError(t, err)

	cert := parseCertificate(t, bundle.CertPEM)
	require.NoError(t, adminclaim.VerifyAdminCertificate(cert, rootPool(ca), common.AdminUsername, app.SystemTenantID))
}

// An admin certificate the CA issued without the SPIFFE identity is refused.
func TestAdminCertificateWithoutSPIFFESAN_FailsTheAdminClaimVerifier(t *testing.T) {
	ca := issuancetest.NewCA(t)

	resp, err := backends.PlatformCertIssuer(ca, nil).
		IssueCertificate(context.Background(), backends.AdminCertificateRequest())
	require.NoError(t, err)

	cert := parseCertificate(t, resp.CertificatePEM)
	require.Empty(t, cert.URIs)
	err = adminclaim.VerifyAdminCertificate(cert, rootPool(ca), common.AdminUsername, app.SystemTenantID)
	require.ErrorAs(t, err, &adminclaim.ErrIdentityMismatch{})
}

func parseCertificate(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(certPEM))
	require.NotNil(t, block, "certificate is not PEM")
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	return cert
}

func rootPool(ca *issuancetest.CA) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Root)
	return pool
}
