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

package initrd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/luks"
)

// newMarkerChain builds a chain writing its marker inside a temp dir.
func newMarkerChain(t *testing.T) (*StrategyChain, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run", "platform", "unlock-strategy")
	chain := NewStrategyChain(logging.DefaultLogger())
	chain.SetMarkerPath(path)
	return chain, path
}

func readMarker(t *testing.T, path string) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return "", false
	}
	require.NoError(t, err)
	return string(data), true
}

// TestStrategyChain_RecordsTheStrategyThatUnlocked is the property #63's wipe
// will depend on: the marker names what SUCCEEDED.
func TestStrategyChain_RecordsTheStrategyThatUnlocked(t *testing.T) {
	chain, path := newMarkerChain(t)
	chain.Add(&mockSuccessStrategy{mockStrategy: mockStrategy{name: "TPM-PCR", priority: 10}})

	require.NoError(t, chain.Execute(context.Background(), &luks.VolumeConfig{}))

	got, ok := readMarker(t, path)
	require.True(t, ok, "a successful unlock must record the winning strategy")
	assert.Equal(t, "TPM-PCR\n", got)
}

// TestStrategyChain_RecordsTheWINNERNotTheAttempt asserts that after a
// fallback the marker names the strategy that unlocked, not the one that
// failed first: TPM-PCR is tried and fails, Keyfile succeeds, marker says
// Keyfile.
//
// NOTE ON WHAT THIS DOES *NOT* CATCH, because the name would otherwise
// overclaim. Moving the record to the attempt site does not fail this test:
// each attempt would overwrite the last, and the final attempt in a successful
// chain IS the winner, so the end state is identical.
//
// The test that catches attempt-recording is
// TestStrategyChain_WritesNoMarkerWhenNothingUnlocked -- with the record at
// the attempt site, a chain where NOTHING unlocks still leaves a marker naming
// the strategy it tried. That is the mutation-verified one, and it is the case
// that matters: a boot that fell back to the keyfile, or unlocked by no
// strategy at all, must never leave a marker saying TPM-PCR for #63's wipe to
// act on.
func TestStrategyChain_RecordsTheWINNERNotTheAttempt(t *testing.T) {
	chain, path := newMarkerChain(t)
	chain.Add(&mockFailStrategy{mockStrategy: mockStrategy{name: "TPM-PCR", priority: 10}})
	chain.Add(&mockSuccessStrategy{mockStrategy: mockStrategy{name: "Keyfile", priority: 20}})

	require.NoError(t, chain.Execute(context.Background(), &luks.VolumeConfig{}))

	got, ok := readMarker(t, path)
	require.True(t, ok)
	assert.Equal(t, "Keyfile\n", got,
		"the marker must name the strategy that UNLOCKED the volume, not one that was tried; "+
			"a wipe gated on this value would otherwise fire on a keyfile boot")
	assert.NotContains(t, got, "TPM-PCR",
		"an attempted-and-failed strategy must never appear in the marker")
}

// TestStrategyChain_WritesNoMarkerWhenNothingUnlocked pins the fail-closed
// direction: no unlock, no marker, and therefore no wipe downstream.
func TestStrategyChain_WritesNoMarkerWhenNothingUnlocked(t *testing.T) {
	chain, path := newMarkerChain(t)
	chain.Add(&mockFailStrategy{mockStrategy: mockStrategy{name: "TPM-PCR", priority: 10}})

	require.Error(t, chain.Execute(context.Background(), &luks.VolumeConfig{}))

	_, ok := readMarker(t, path)
	assert.False(t, ok, "a failed unlock must leave no marker -- absence is what keeps a wipe from firing")
}

// TestStrategyChain_UnwritableMarkerDoesNotFailTheUnlock pins the other
// asymmetry: the volume is already unlocked when the marker is written, so a
// write failure must not turn an observability record into a failed boot.
func TestStrategyChain_UnwritableMarkerDoesNotFailTheUnlock(t *testing.T) {
	chain := NewStrategyChain(logging.DefaultLogger())
	// A path under a regular file cannot be created.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o644))
	chain.SetMarkerPath(filepath.Join(file, "unlock-strategy"))
	chain.Add(&mockSuccessStrategy{mockStrategy: mockStrategy{name: "TPM-PCR", priority: 10}})

	assert.NoError(t, chain.Execute(context.Background(), &luks.VolumeConfig{}),
		"an unwritable marker must not fail an unlock that already succeeded")
}
