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

// harnessAdminBundleName is the file the harness reads as both
// PLATFORM_CLIENT_CERT and PLATFORM_CLIENT_KEY.
const harnessAdminBundleName = "client-bundle.pem"

func init() {
	harnessAdminBundle = writeHarnessAdminBundle
}

// writeHarnessAdminBundle issues a CN=admin client certificate and writes
// it, key included, to <dir>/client-bundle.pem (mode 0600). It issues a
// fresh certificate on every start; the harness wipes the directory before
// each run anyway.
func writeHarnessAdminBundle(ctx context.Context, logger *logging.Logger, issuer appbackends.CertIssuer, dir string) error {
	if issuer == nil {
		return ErrProvisionMissingSDK{}
	}
	resp, err := issuer.IssueCertificate(ctx, appbackends.AdminCertificateRequest())
	if err != nil {
		return ErrProvisionIssue{Role: "admin", Cause: err}
	}
	path := filepath.Join(dir, harnessAdminBundleName)
	if err := writeBundle(path, resp.CertificatePEM, resp.PrivateKeyPEM, 0600); err != nil {
		return ErrProvisionPersist{Path: path, Cause: err}
	}
	logger.Warn("integration build: wrote a test-only admin client bundle",
		"path", path,
		"serial", resp.SerialNumber,
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
