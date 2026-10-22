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
	"fmt"
	"strings"

	"github.com/stretchr/testify/require"
)

// SecretsSDKGapIssue is the upstream issue that carries the secrets verbs
// the pinned go-quicbaas SDK does not serve. Its embedded transport serves
// only quicbaas.Secrets/{Store,Get,List,Delete,Ensure}, so platformctl kms
// secrets rotate, version, versions, rollback, status and policy fail there;
// its gRPC transport has no SecretsManagement proto method for GetVersion,
// GetRotationPolicy or SetRotationPolicy, so version and policy fail there.
const SecretsSDKGapIssue = "go-quicbaas #1619"

// KMSKeyStatusSDKGap names the KMS verb the pinned go-quicbaas SDK's embedded
// transport refuses: kms.Client.UpdateKeyStatus sends *kms.UpdateKeyStatusRequest
// and the embedded handler for quicbaas.KMS/UpdateKeyStatus accepts only
// *service.UpdateKeyStatusRequest, so disabling or enabling a key fails there.
const KMSKeyStatusSDKGap = "go-quicbaas sdk/go kms.Client.UpdateKeyStatus: embedded transport rejects *kms.UpdateKeyStatusRequest"

// cliUpstreamGapMarkers are the texts platformctl prints on stderr when the
// SDK does not serve a method: the embedded transport's own answers, and the
// CLI's ErrSecretsSDKGap, which carries any transport's unimplemented refusal.
var cliUpstreamGapMarkers = []string{
	"unknown method: quicbaas.",
	"invalid request type for quicbaas.",
	"the go-quicbaas SDK does not serve SecretsClient.",
}

// ErrCLINoFlag is returned by a CLI test adapter when the caller passes an
// option platformctl has no flag for. The adapter refuses rather than drop
// the option silently, so a leaf that relies on it fails visibly.
type ErrCLINoFlag struct {
	Operation string
	Flag      string
}

func (e ErrCLINoFlag) Error() string {
	return fmt.Sprintf("platformctl %s has no flag for %s", e.Operation, e.Flag)
}

// Is matches any ErrCLINoFlag, so a leaf asserts the refusal with
// require.ErrorIs(t, err, helpers.ErrCLINoFlag{}).
func (e ErrCLINoFlag) Is(target error) bool {
	_, ok := target.(ErrCLINoFlag)
	return ok
}

// ErrCLIUpstreamGap is returned by a CLI test adapter when platformctl failed
// because the go-quicbaas SDK does not serve the method behind the verb.
// Err is the command failure, which carries platformctl's stderr.
type ErrCLIUpstreamGap struct {
	Operation string
	Issue     string
	Err       error
}

func (e ErrCLIUpstreamGap) Error() string {
	return fmt.Sprintf("platformctl %s: the go-quicbaas SDK does not serve it (%s): %v", e.Operation, e.Issue, e.Err)
}

func (e ErrCLIUpstreamGap) Unwrap() error {
	return e.Err
}

// Is matches any ErrCLIUpstreamGap, so a leaf asserts the refusal with
// require.ErrorIs(t, err, helpers.ErrCLIUpstreamGap{}).
func (e ErrCLIUpstreamGap) Is(target error) bool {
	_, ok := target.(ErrCLIUpstreamGap)
	return ok
}

// CLIUpstreamGap returns err as an ErrCLIUpstreamGap naming issue when its
// text carries one of the SDK's unserved-method answers, and err unchanged
// otherwise (nil included).
func CLIUpstreamGap(operation, issue string, err error) error {
	if err == nil {
		return nil
	}
	text := err.Error()
	for _, marker := range cliUpstreamGapMarkers {
		if strings.Contains(text, marker) {
			return ErrCLIUpstreamGap{Operation: operation, Issue: issue, Err: err}
		}
	}
	return err
}

// RequireCLIRefusal asserts, for the CLI adapter only, that err is the typed
// refusal want (ErrCLINoFlag{} or ErrCLIUpstreamGap{}) and reports true so the
// leaf returns; for every other adapter it reports false and asserts nothing.
func RequireCLIRefusal(t require.TestingT, adapter string, err, want error) bool {
	if adapter != "CLI" {
		return false
	}
	require.ErrorIs(t, err, want)
	return true
}

// ErrCLINoCommandGroup is a suite CLI adapter's refusal of an operation whose
// platformctl command group does not exist. The SDK serves the operation over
// every other transport; only the operator CLI is missing, and Issue names the
// issue that records the omission.
type ErrCLINoCommandGroup struct {
	Group     string
	Operation string
	Issue     string
}

func (e ErrCLINoCommandGroup) Error() string {
	return fmt.Sprintf("platformctl has no %s command group, so %s has no CLI (%s)", e.Group, e.Operation, e.Issue)
}

// Is matches any ErrCLINoCommandGroup, so a suite asserts the refusal with
// errors.Is against the zero value.
func (e ErrCLINoCommandGroup) Is(target error) bool {
	_, ok := target.(ErrCLINoCommandGroup)
	return ok
}

// ErrCLICommandGroupPresent is returned by a suite CLI adapter's Setup when
// platformctl lists a command group the adapter still declares missing. The
// declared gap has closed: the adapter must drive the group instead.
type ErrCLICommandGroupPresent struct {
	Group string
	Issue string
}

func (e ErrCLICommandGroupPresent) Error() string {
	return fmt.Sprintf("platformctl now has a %s command group, but the CLI adapter still declares it missing (%s): drive the group", e.Group, e.Issue)
}

// CLIHasCommandGroup reports whether platformctl help output lists group under
// "Available Commands:".
func CLIHasCommandGroup(help, group string) bool {
	listing := false
	for _, line := range strings.Split(help, "\n") {
		if strings.HasPrefix(line, "Available Commands:") {
			listing = true
			continue
		}
		if !listing {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			return false
		}
		if fields[0] == group {
			return true
		}
	}
	return false
}
