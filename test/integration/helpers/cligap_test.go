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

package helpers

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errTestCLIFailed stands in for a CLI adapter's command failure, whose text
// carries platformctl's stderr.
type errTestCLIFailed struct {
	stderr string
}

func (e errTestCLIFailed) Error() string {
	return "CLI command failed (output: \nstderr: " + e.stderr + ")"
}

func TestCLIUpstreamGapClassifiesUnservedMethods(t *testing.T) {
	for _, stderr := range []string{
		"Error: rotate secret db: unknown method: quicbaas.Secrets/Rotate",
		"Error: status secret db: invalid request type for quicbaas.Secrets/UpdateStatus",
	} {
		cause := errTestCLIFailed{stderr: stderr}
		err := CLIUpstreamGap("kms secrets rotate", SecretsSDKGapIssue, cause)

		require.ErrorIs(t, err, ErrCLIUpstreamGap{})
		var gap ErrCLIUpstreamGap
		require.ErrorAs(t, err, &gap)
		assert.Equal(t, "kms secrets rotate", gap.Operation)
		assert.Equal(t, SecretsSDKGapIssue, gap.Issue)
		assert.ErrorIs(t, err, cause, "the gap must keep the command failure")
		assert.Contains(t, err.Error(), SecretsSDKGapIssue)
	}
}

func TestCLIUpstreamGapLeavesOtherErrorsAlone(t *testing.T) {
	assert.NoError(t, CLIUpstreamGap("kms secrets get", SecretsSDKGapIssue, nil))

	cause := errTestCLIFailed{stderr: "Error: get secret db: secret not found"}
	err := CLIUpstreamGap("kms secrets get", SecretsSDKGapIssue, cause)
	assert.Equal(t, cause, err)
	assert.False(t, errors.Is(err, ErrCLIUpstreamGap{}))
}

func TestErrCLINoFlagMatchesByType(t *testing.T) {
	err := ErrCLINoFlag{Operation: "kms secrets store", Flag: "--expires-at"}

	require.ErrorIs(t, err, ErrCLINoFlag{})
	assert.Equal(t, "platformctl kms secrets store has no flag for --expires-at", err.Error())
	assert.False(t, errors.Is(err, ErrCLIUpstreamGap{}), "a missing flag is not an upstream gap")
}
