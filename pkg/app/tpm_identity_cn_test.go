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

// TestApplyTPMIdentityCNs_IAK pins the IAK half of the hostname naming
// contract (docs/tpm/engineering.md item 8), restored by #78 now that
// go-xkms honours a configured IAK CN: the IAK derives its CN from the
// hostname when unset and an operator-configured CN is preserved. The #74
// interim that cleared it is gone — on a fresh provision an empty CN is
// exactly what the certificate store rejects.
func TestApplyTPMIdentityCNs_IAK(t *testing.T) {
	t.Run("derives the CN from the hostname when unset", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IAK: &xkmssdk.IAKConfig{}}
		var logged bytes.Buffer

		applyTPMIdentityCNs(cfg, "node-07", logging.NewLogger(slog.LevelDebug, &logged))

		assert.Equal(t, "node-07-iak", cfg.IAK.CN)
		assert.Contains(t, logged.String(), "node-07-iak", "the derived name is logged so the store key is traceable")
	})

	t.Run("preserves an explicitly configured CN", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IAK: &xkmssdk.IAKConfig{CN: "operator-choice"}}

		applyTPMIdentityCNs(cfg, "node-07", logging.DefaultLogger())

		assert.Equal(t, "operator-choice", cfg.IAK.CN,
			"an operator-supplied IAK CN must not be overridden")
	})

	t.Run("an empty hostname leaves the IAK CN unset rather than bare-suffixed", func(t *testing.T) {
		cfg := &xkmssdk.TPMConfig{IAK: &xkmssdk.IAKConfig{}}

		applyTPMIdentityCNs(cfg, "", logging.DefaultLogger())

		assert.Empty(t, cfg.IAK.CN)
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
