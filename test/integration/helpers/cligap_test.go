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

// TestCLIUpstreamGapClassifiesIAMRefusals pins the texts platformd's gRPC IAM
// service answers role assignment and permission checks with while the SDK's
// embedded transport refuses them (CI run 63031, TestMultiProtocolMatrix/iam).
func TestCLIUpstreamGapClassifiesIAMRefusals(t *testing.T) {
	for _, tc := range []struct {
		operation string
		gap       string
		text      string
	}{
		{"iam AssignRole", IAMAssignRoleSDKGap,
			"UNIMPLEMENTED: embedded: unknown method: quicbaas.IAM.User/AssignRole"},
		{"iam CheckPermission", IAMCheckPermissionSDKGap,
			"INVALID_INPUT: embedded: invalid request type for quicbaas.IAM.PEP/Check: " +
				"expected *iam.CheckRequest, got *iam.checkRequestInternal"},
	} {
		cause := errTestCLIFailed{stderr: tc.text}
		err := CLIUpstreamGap(tc.operation, tc.gap, cause)

		var gap ErrCLIUpstreamGap
		require.ErrorAs(t, err, &gap, tc.operation)
		assert.Equal(t, tc.operation, gap.Operation)
		assert.Equal(t, tc.gap, gap.Issue)
		assert.ErrorIs(t, err, cause, "the gap must keep the transport failure")
	}
}

// TestCLIUpstreamGapRejectsIAMConflicts keeps a real IAM failure, such as a
// leftover role, from passing as the declared SDK gap.
func TestCLIUpstreamGapRejectsIAMConflicts(t *testing.T) {
	cause := errTestCLIFailed{stderr: "rpc error: code = AlreadyExists desc = CreateRole: already_exists"}
	err := CLIUpstreamGap("iam AssignRole", IAMAssignRoleSDKGap, cause)
	assert.Equal(t, cause, err)
	assert.False(t, errors.Is(err, ErrCLIUpstreamGap{}))
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

func TestErrCLINoCommandGroupMatchesByType(t *testing.T) {
	err := ErrCLINoCommandGroup{Group: "dns", Operation: "CreateZone", Issue: "#954"}

	require.ErrorIs(t, err, ErrCLINoCommandGroup{})
	assert.False(t, errors.Is(err, ErrCLINoFlag{}), "a missing group is not a missing flag")
	assert.False(t, errors.Is(err, ErrCLIUpstreamGap{}), "a missing group is not an SDK gap")
	assert.Equal(t, "platformctl has no dns command group, so CreateZone has no CLI (#954)", err.Error())
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
