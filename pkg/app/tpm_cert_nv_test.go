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

package app

import (
	"bytes"
	"log/slog"
	"strconv"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyCertHandleNVInterim pins the #81 interim. go-xkms
// writeCertToNVRAM authorizes its NV define on the owner hierarchy with an
// empty password, so once the platform has set the owner auth the TPM
// rejects the define with TPM_RC_BAD_AUTH — fatally, on every boot. Clearing
// the handle sends both the Provision call and the read accessor to the
// certificate store, which is the only value that makes the path work rather
// than fail differently.
//
// Remove this behavior — and these expectations — when go-xkms authorizes
// the identity NV writes with the owner hierarchy auth; tracked as #81.
func TestApplyCertHandleNVInterim(t *testing.T) {
	// 0x01C90000 is the IDevID handle every shipped template sets.
	const shippedHandle = 0x01C90000

	t.Run("clears a configured IDevID cert-handle and warns", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{CertHandle: shippedHandle}}
		var logged bytes.Buffer

		applyCertHandleNVInterim(cfg, logging.NewLogger(slog.LevelDebug, &logged))

		assert.Zero(t, cfg.IDevID.CertHandle,
			"a non-zero cert-handle routes IDevID to the NV path, which fails with TPM_RC_BAD_AUTH on an owned TPM")

		// The warning is the whole mitigation for overriding operator
		// intent — silently discarding it would be the defect.
		out := logged.String()
		// The stable phrase is the assertion that matters: an operator (and
		// the deploy agent, and its author) all searched for exactly this
		// and found nothing while the identity was spliced into the middle
		// of it (#94). Keep the message constant.
		assert.Contains(t, out, "ignoring the configured cert-handle",
			"the warning must carry a constant, greppable phrase")
		assert.Contains(t, out, "#81",
			"the warning must name the tracking issue so the override is traceable")
		assert.Contains(t, out, "TPM_RC_BAD_AUTH",
			"the warning must name the failure the override avoids")
		assert.Contains(t, out, strconv.Itoa(shippedHandle),
			"the warning must report the handle that was ignored")
		assert.Contains(t, out, "IDevID", "the warning must name the affected identity")
	})

	// writeCertToNVRAM is shared, so ProvisionIAKCert hits the identical
	// defect for any configuration that sets iak.cert-handle. No shipped
	// template does today — this guards the latent trap, and it is what
	// makes the "no identity takes the NV path" claim actually true.
	t.Run("clears a configured IAK cert-handle and warns", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IAK: &xkmssdk.IAKConfig{CertHandle: shippedHandle}}
		var logged bytes.Buffer

		applyCertHandleNVInterim(cfg, logging.NewLogger(slog.LevelDebug, &logged))

		assert.Zero(t, cfg.IAK.CertHandle,
			"the IAK NV path is broken by the same upstream defect and must be guarded too")
		assert.Contains(t, logged.String(), "IAK")
	})

	t.Run("leaves already-zero handles alone and stays silent", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{
			IAK:    &xkmssdk.IAKConfig{CertHandle: 0},
			IDevID: &xkmssdk.IDevIDConfig{CertHandle: 0},
		}
		var logged bytes.Buffer

		applyCertHandleNVInterim(cfg, logging.NewLogger(slog.LevelDebug, &logged))

		assert.Zero(t, cfg.IAK.CertHandle)
		assert.Zero(t, cfg.IDevID.CertHandle)
		assert.Empty(t, logged.String(),
			"configurations already using the certificate store must not be warned at")
	})

	t.Run("absent sections are a no-op", func(t *testing.T) {
		require.NotPanics(t, func() {
			applyCertHandleNVInterim(nil, logging.DefaultLogger())
			applyCertHandleNVInterim(&xkmssdk.TPMConfig{}, logging.DefaultLogger())
		})
	})
}

// TestTPMIdentityPersistenceIsRoutedToTheCertStore pins the ROUTING DECISION
// that #62's four persistence calls depend on.
//
// Scope, stated precisely: this asserts the configuration bring-up settles
// on — it does NOT execute the four call sites in ProvisionPlatform
// (pkg/app/app.go, IAK and IDevID on both the local-issuance and ACME
// paths). Those need a live TPM and, for the ACME pair, an ACME server, so
// they are out of reach at unit level. What they share is this config: all
// four resolve their destination from the same CertHandle/CN fields, and
// each identity's Provision call and read accessor branch on the same
// CertHandle. Pinning the settled values therefore pins the route all four
// take, and TestCertStorePersistsBothIdentityCertClasses (pkg/store/certstore)
// covers the store boundary they converge on.
//
// This exists because #62's four calls failed serially, each masking the
// next — #74 was the IAK CN, #80 the IDevID NV index — with the ACME twins
// never executing at all. A routing assertion is what turns the next such
// failure into a red test instead of a dead node.
func TestTPMIdentityPersistenceIsRoutedToTheCertStore(t *testing.T) {
	// The shipped x10 template shape: an IDevID NV handle, no IAK handle.
	cfg := &xkmssdk.TPMConfig{
		IAK:    &xkmssdk.IAKConfig{},
		IDevID: &xkmssdk.IDevIDConfig{CertHandle: 0x01C90000},
	}

	applyTPMIdentityCNs(cfg, "node-07", logging.DefaultLogger())
	applyCertHandleNVInterim(cfg, logging.DefaultLogger())

	// IAK: no NV handle, so ProvisionIAKCert takes the certificate-store
	// branch, and its CN is populated so the store has a key (#78: an
	// empty CN is what the store rejects on a fresh provision).
	assert.Zero(t, cfg.IAK.CertHandle,
		"IAK must not take the NV path — writeCertToNVRAM authorizes with an empty owner password (#81)")
	assert.Equal(t, "node-07-iak", cfg.IAK.CN,
		"the certificate store keys on the CN, so the IAK needs a non-empty one")

	// IDevID: handle cleared, so both the write and the read use the
	// certificate store, and its CN is populated so the store has a key.
	assert.Zero(t, cfg.IDevID.CertHandle,
		"IDevID must not take the NV path until go-xkms authorizes it with the owner auth (#81)")
	assert.Equal(t, "node-07-idevid", cfg.IDevID.CN,
		"the certificate store keys on the CN, so IDevID needs a non-empty one")
}
