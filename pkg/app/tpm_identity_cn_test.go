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
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplyTPMIdentityCNs_IDevID pins the surviving half of the hostname
// naming contract (docs/tpm/engineering.md): IDevID still derives its CN
// from the hostname, and an explicitly configured value still wins.
func TestApplyTPMIdentityCNs_IDevID(t *testing.T) {
	t.Run("derives the CN from the hostname when unset", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{}}

		applyTPMIdentityCNs(cfg, "node-07", logging.DefaultLogger())

		assert.Equal(t, "node-07-idevid", cfg.IDevID.CN)
	})

	t.Run("preserves an explicitly configured CN", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{CN: "operator-choice"}}

		applyTPMIdentityCNs(cfg, "node-07", logging.DefaultLogger())

		assert.Equal(t, "operator-choice", cfg.IDevID.CN,
			"an operator-supplied IDevID CN must not be overridden")
	})
}

// TestApplyTPMIdentityCNs_IAKInterim pins the #74 interim. go-xkms
// IAKAttributes() assigns KeyAttributes.CN ONLY on its empty-CN fallback
// path, so any non-empty config.IAK.CN is discarded and the attributes
// reach the certificate store with an empty CN — which the store rejects,
// fatally, on every boot. Both the write (ProvisionIAKCert) and the read
// (IAKCertificate) derive the storage key from those same attributes, so a
// non-empty IAK CN here is unusable in both directions.
//
// The platform therefore leaves the IAK CN empty so the upstream fallback
// applies consistently. Remove this behavior — and these expectations —
// when go-xkms#137 is adopted; tracked as #78.
func TestApplyTPMIdentityCNs_IAKInterim(t *testing.T) {
	t.Run("does not derive an IAK CN from the hostname", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IAK: &xkmssdk.IAKConfig{}}

		applyTPMIdentityCNs(cfg, "node-07", logging.DefaultLogger())

		assert.Empty(t, cfg.IAK.CN,
			"a hostname-derived IAK CN is discarded upstream and fatals the daemon (go-xkms#137)")
	})

	t.Run("clears an explicitly configured IAK CN and warns", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IAK: &xkmssdk.IAKConfig{CN: "operator-choice"}}
		var logged bytes.Buffer

		applyTPMIdentityCNs(cfg, "node-07", logging.NewLogger(slog.LevelDebug, &logged))

		// Honouring the operator's value is not an option: it is the exact
		// input that produces the empty-CN fatal. Clearing it keeps the
		// node bootable.
		assert.Empty(t, cfg.IAK.CN,
			"an explicitly configured IAK CN is equally fatal upstream and must be cleared, not passed through")

		// The warning is the whole mitigation for overriding operator
		// intent — silently discarding it would be the defect.
		out := logged.String()
		assert.Contains(t, out, "go-xkms#137",
			"the warning must name the upstream issue so the override is traceable")
		assert.Contains(t, out, "operator-choice",
			"the warning must report the value that was ignored")
	})
}

// TestApplyTPMIdentityCNs_AbsentSections asserts the helper tolerates a
// configuration with either identity section missing, since bring-up calls
// it before any TPM section is guaranteed present.
func TestApplyTPMIdentityCNs_AbsentSections(t *testing.T) {
	t.Run("nil identity sections are left alone", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{}

		require.NotPanics(t, func() {
			applyTPMIdentityCNs(cfg, "node-07", logging.DefaultLogger())
		})

		assert.Nil(t, cfg.IAK)
		assert.Nil(t, cfg.IDevID)
	})

	t.Run("nil config is a no-op", func(t *testing.T) {
		require.NotPanics(t, func() {
			applyTPMIdentityCNs(nil, "node-07", logging.DefaultLogger())
		})
	})

	t.Run("an empty hostname leaves the IDevID CN unset rather than bare-suffixed", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IDevID: &xkmssdk.IDevIDConfig{}}

		applyTPMIdentityCNs(cfg, "", logging.DefaultLogger())

		// IDevID has no upstream default — the CN left here is what the
		// identity is stored under — so a bare "-idevid" would be a
		// meaningless name shared by every affected node. Empty fails
		// loudly at the point of use instead. Unreachable in practice:
		// App.Hostname is filled from os.Hostname() during bring-up.
		assert.Empty(t, cfg.IDevID.CN)
	})
}
