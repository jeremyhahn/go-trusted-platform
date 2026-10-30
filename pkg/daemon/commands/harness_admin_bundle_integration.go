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

//go:build integration

// harness_admin_bundle_integration.go is compiled only into the platformd
// binary the devcontainer integration harness builds. That harness starts
// platformd without a barrier, so the pre-unseal /init gate never binds and
// the harness cannot take its admin credential from the one-shot /init
// bundle. This file gives it one instead. No production build contains it:
// a production daemon mints no admin key.

package commands

import (
	"context"
	"os"
	"path/filepath"

	appbackends "github.com/jeremyhahn/go-trusted-platform/pkg/app/backends"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const (
	// harnessAdminBundleName is the file the harness reads as both
	// PLATFORM_CLIENT_CERT and PLATFORM_CLIENT_KEY.
	harnessAdminBundleName = "client-bundle.pem"

	// harnessTenantBundleName is the file the harness reads as both
	// PLATFORM_TENANT_CLIENT_CERT and PLATFORM_TENANT_CLIENT_KEY: a client
	// certificate bound to harnessTenantID, for the suites that assert what
	// a non-system tenant is refused.
	harnessTenantBundleName = "tenant-client-bundle.pem"

	// harnessTenantID is the fixed non-system tenant the tenant bundle's
	// subject O names.
	harnessTenantID = "harness-tenant"
)

func init() {
	harnessAdminBundle = writeHarnessAdminBundle
}

// writeHarnessAdminBundle issues two CN=admin client certificates and writes
// each, key included, mode 0600: one in harnessTenantID to
// <dir>/tenant-client-bundle.pem, then the system tenant's to
// <dir>/client-bundle.pem. The system bundle is minted through the
// identity-aware admin bundle issuer, so its leaf carries identity's operator
// SPIFFE URI and passes the mTLS operator check. It issues fresh certificates
// on every start; the harness wipes the directory before each run anyway.
func writeHarnessAdminBundle(ctx context.Context, logger *logging.Logger, issuer appbackends.CertIssuer, identity appbackends.AdminIdentity, dir string) error {
	if issuer == nil {
		return ErrProvisionMissingSDK{}
	}
	// The tenant bundle is written first: the harness waits for
	// client-bundle.pem, so once that file exists both bundles do.
	tenant := appbackends.AdminIdentity{TrustDomain: identity.TrustDomain, TenantID: harnessTenantID}
	if err := writeHarnessIdentityBundle(ctx, logger, issuer, tenant, "tenant admin", filepath.Join(dir, harnessTenantBundleName)); err != nil {
		return err
	}
	return writeHarnessIdentityBundle(ctx, logger, issuer, identity, "admin", filepath.Join(dir, harnessAdminBundleName))
}

// writeHarnessIdentityBundle issues the admin client bundle for identity and
// writes it to path. role names the bundle in the error a failed issue
// returns.
func writeHarnessIdentityBundle(ctx context.Context, logger *logging.Logger, issuer appbackends.CertIssuer, identity appbackends.AdminIdentity, role, path string) error {
	bundle, err := appbackends.NewAdminBundleIssuer(issuer, identity).IssueAdminBundle(ctx)
	if err != nil {
		return ErrProvisionIssue{Role: role, Cause: err}
	}
	if err := writeBundle(path, bundle.CertPEM, bundle.KeyPEM, 0600); err != nil {
		return ErrProvisionPersist{Path: path, Cause: err}
	}
	logger.Warn("integration build: wrote a test-only "+role+" client bundle",
		"path", path,
		"tenant", identity.TenantID,
	)
	return nil
}

// writeBundle persists a single PEM cert+key bundle file with the given
// mode. The format (CERTIFICATE block(s) followed by an EC PRIVATE KEY
// block) is compatible with tls.LoadX509KeyPair(bundle, bundle).
func writeBundle(path, certPEM, keyPEM string, mode os.FileMode) error {
	bundle := bytesJoin(certPEM, keyPEM)
	return os.WriteFile(path, bundle, mode)
}

// bytesJoin concatenates two PEM strings, ensuring exactly one newline
// separator between them.
func bytesJoin(a, b string) []byte {
	out := []byte(a)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(out, []byte(b)...)
}
