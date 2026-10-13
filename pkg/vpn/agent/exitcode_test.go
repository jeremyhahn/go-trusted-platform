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

package agent

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

func TestExitCode_MapsEachOutcomeToTheDocumentedCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"success", nil, ExitOK},
		{"refused", &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalAttestationFailed}, ExitRefused},
		{"unavailable is a refusal", &RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalPoolExhausted}, ExitRefused},
		{"posture violation", &RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation, Rules: []string{"fde"}}, ExitPostureViolation},
		{"not connected", &ErrNotConnected{}, ExitNotConnected},
		{"refusal under a rollback", &ErrRollback{Cause: &RefusedError{Class: gwvpn.RefusalPostureViolation}, Rollback: &ErrNotConnected{}}, ExitPostureViolation},
		{"joined with a refusal", errors.Join(&RefusedError{Class: "not-listed"}, &ErrDataPlane{Op: "down", Cause: &ErrNotConnected{}}), ExitRefused},
		{"local failure", &ErrEvidence{Step: "quote", Cause: &ErrInvalidOptions{Field: "tpm", Reason: "absent"}}, ExitFailure},
		{"unreachable", &ErrGatewayUnreachable{Gateway: "gw:4433"}, ExitFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ExitCode(tt.err))
		})
	}
}

func TestRefusedError_PrintsTheTroubleshootingPhrases(t *testing.T) {
	// The phrases are the Symptom column of docs/vpn/user.md.
	tests := []struct {
		err  *RefusedError
		want string
	}{
		{&RefusedError{Status: http.StatusUnauthorized, Class: "untrusted-issuer"}, "refused: untrusted issuer"},
		{&RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalAttestationFailed}, "refused: attestation failed"},
		{&RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPostureViolation, Rules: []string{"secure_boot"}}, "refused: posture violation: secure_boot"},
		{&RefusedError{Status: http.StatusUnauthorized, Class: gwvpn.RefusalPersonFactorRequired}, "refused: person factor required"},
		{&RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalPostureUnavailable}, "unavailable: posture policy"},
		{&RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalPoolExhausted}, "unavailable: pool exhausted"},
		{&RefusedError{Status: http.StatusServiceUnavailable, Class: gwvpn.RefusalDataPlaneUnavailable}, "unavailable: data plane"},
		{&RefusedError{Status: http.StatusForbidden, Class: gwvpn.RefusalPeerNotEnrolled}, "refused: peer not enrolled"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.err.Error())
	}
}

func TestErrDataPlaneUnsupported_NamesThePlane(t *testing.T) {
	assert.Equal(t, "data plane wireguard not available", (&ErrDataPlaneUnsupported{Kind: "wireguard"}).Error())
}

func TestErrRollback_UnwrapsToTheFailureOnly(t *testing.T) {
	cause := &ErrDataPlane{Op: "up", Kind: gwvpn.DataPlaneMASQUE, Cause: &ErrNotConnected{}}
	err := &ErrRollback{Cause: cause, Rollback: &RefusedError{Class: gwvpn.RefusalLeaseStoreUnavailable}}

	var refused *RefusedError
	assert.False(t, errors.As(err, &refused), "the cleanup's refusal must not decide the exit code")
	assert.ErrorIs(t, err, cause)
	assert.Contains(t, err.Error(), "rollback: refused: lease store")
}
