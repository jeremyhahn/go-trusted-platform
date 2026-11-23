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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		"Error: kms secrets version: the go-quicbaas SDK does not serve SecretsClient.GetVersion: UNIMPLEMENTED: " +
			"secretsHandler.handleRequest: method not exposed by SecretsManagement gRPC proto: GetVersion",
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

// TestCLIUpstreamGapClassifiesKMSKeyStatusRefusal pins the text the daemon's
// KMS adapter answers a key status update with while the SDK's embedded
// transport refuses *kms.UpdateKeyStatusRequest.
func TestCLIUpstreamGapClassifiesKMSKeyStatusRefusal(t *testing.T) {
	cause := errTestCLIFailed{stderr: "rpc error: code = InvalidArgument desc = key status update failed: " +
		"INVALID_INPUT: embedded: invalid request type for quicbaas.KMS/UpdateKeyStatus: " +
		"expected *service.UpdateKeyStatusRequest"}
	err := CLIUpstreamGap("kms key status", KMSKeyStatusSDKGap, cause)

	var gap ErrCLIUpstreamGap
	require.ErrorAs(t, err, &gap)
	assert.Equal(t, "kms key status", gap.Operation)
	assert.Equal(t, KMSKeyStatusSDKGap, gap.Issue)
	assert.Contains(t, err.Error(), "kms.Client.UpdateKeyStatus")
}

func TestErrCLINoFlagMatchesByType(t *testing.T) {
	err := ErrCLINoFlag{Operation: "kms secrets store", Flag: "--expires-at"}

	require.ErrorIs(t, err, ErrCLINoFlag{})
	assert.Equal(t, "platformctl kms secrets store has no flag for --expires-at", err.Error())
	assert.False(t, errors.Is(err, ErrCLIUpstreamGap{}), "a missing flag is not an upstream gap")
}

// recordingT is a require.TestingT that records a failed assertion instead of
// stopping the test, so RequireCLIRefusal's failure path can be observed.
type recordingT struct {
	failed bool
}

func (r *recordingT) Errorf(string, ...interface{}) { r.failed = true }

func (r *recordingT) FailNow() { r.failed = true }

func TestRequireCLIRefusalAssertsOnlyForTheCLIAdapter(t *testing.T) {
	gap := ErrCLIUpstreamGap{Operation: "kms secrets rotate", Issue: SecretsSDKGapIssue}

	cli := &recordingT{}
	assert.True(t, RequireCLIRefusal(cli, "CLI", gap, ErrCLIUpstreamGap{}))
	assert.False(t, cli.failed)

	rest := &recordingT{}
	assert.False(t, RequireCLIRefusal(rest, "REST", nil, ErrCLIUpstreamGap{}))
	assert.False(t, rest.failed, "a non-CLI adapter asserts nothing")
}

func TestRequireCLIRefusalFailsOnTheWrongRefusal(t *testing.T) {
	noFlag := &recordingT{}
	RequireCLIRefusal(noFlag, "CLI", ErrCLINoFlag{Operation: "kms secrets store", Flag: "--key-id"}, ErrCLIUpstreamGap{})
	assert.True(t, noFlag.failed, "a missing flag is not the upstream gap the leaf expects")

	success := &recordingT{}
	RequireCLIRefusal(success, "CLI", nil, ErrCLINoFlag{})
	assert.True(t, success.failed, "a CLI success where a refusal is expected fails the leaf")
}

const platformctlHelp = `platformctl drives platformd.

Usage:
  platformctl [command]

Available Commands:
  ca          Certificate authority operations
  dnsx        Not the dns group
  tenant      Tenant management

Flags:
  -h, --help   help for platformctl
      --dns    a flag, not a command
`

func TestCLIHasCommandGroupFindsAListedGroup(t *testing.T) {
	assert.True(t, CLIHasCommandGroup(platformctlHelp, "tenant"))
	assert.True(t, CLIHasCommandGroup(platformctlHelp, "ca"))
}

func TestCLIHasCommandGroupRejectsAbsentGroups(t *testing.T) {
	assert.False(t, CLIHasCommandGroup(platformctlHelp, "dns"), "a prefix or a flag is not the group")
	assert.False(t, CLIHasCommandGroup("", "dns"), "empty help lists nothing")
	assert.False(t, CLIHasCommandGroup("Usage:\n  dns\n", "dns"), "only Available Commands counts")
}

// TestRequireSDKGapRefusal checks that the pinned SDK's embedded refusals, as
// each adapter reports them in CI, count as the declared gap on every
// adapter, and that nil or any other error does not.
func TestRequireSDKGapRefusal(t *testing.T) {
	cases := []struct {
		name    string
		adapter string
		err     error
		want    bool
	}{
		{
			name:    "gRPC unknown method",
			adapter: "gRPC",
			err:     status.Error(codes.Unimplemented, "secret rotation failed: UNIMPLEMENTED: embedded: unknown method: quicbaas.Secrets/Rotate"),
			want:    true,
		},
		{
			name:    "QUIC unknown method",
			adapter: "QUIC",
			err:     errors.New("QUIC request PolicySet failed (status 0x04): QUIC operation SecretsSetRotationPolicy failed: rpc error: code = Unimplemented desc = rotation policy update failed: UNIMPLEMENTED: embedded: unknown method: quicbaas.Secrets/SetRotationPolicy"),
			want:    true,
		},
		{
			name:    "MCP invalid request type",
			adapter: "MCP",
			err:     errors.New("MCP tool \"tools/call\" call failed (code -32603): INVALID_INPUT: embedded: invalid request type for quicbaas.KMS/UpdateKeyStatus: expected *service.UpdateKeyStatusRequest, got *kms.UpdateKeyStatusRequest"),
			want:    true,
		},
		{
			name:    "REST unknown method",
			adapter: "REST",
			err:     errors.New("REST API error (status 500): UNIMPLEMENTED: embedded: unknown method: quicbaas.Secrets/UpdateStatus"),
			want:    true,
		},
		{
			name:    "CLI typed refusal",
			adapter: "CLI",
			err:     ErrCLIUpstreamGap{Operation: "kms secrets rotate", Issue: SecretsSDKGapIssue, Err: errors.New("x")},
			want:    true,
		},
		{
			name:    "MCP unknown method",
			adapter: "MCP",
			err:     errors.New("MCP tool \"tools/call\" call failed (code -32601): secrets operation RollbackSecret failed: rpc error: code = Unimplemented desc = secret rollback failed: UNIMPLEMENTED: embedded: unknown method: quicbaas.Secrets/Rollback"),
			want:    true,
		},
		{name: "gRPC nil", adapter: "gRPC", err: nil, want: false},
		{name: "REST nil", adapter: "REST", err: nil, want: false},
		{
			name:    "REST other error",
			adapter: "REST",
			err:     errors.New("REST API error (status 400): invalid kms request"),
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, RequireSDKGapRefusal(t, tc.adapter, SecretsSDKGapIssue, tc.err))
		})
	}
}
