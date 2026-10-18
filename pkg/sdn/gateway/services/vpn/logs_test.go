// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package vpn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

func TestRefuse_LogsThePostureRules(t *testing.T) {
	h := newHarness(t, testConfig())
	h.posture.result = &opa.EvaluationResult{Violations: []opa.Violation{{Rule: "fde-root-encrypted"}, {Rule: "secure-boot"}}}
	req := h.request(t)
	_, err := h.svc.Admit(context.Background(), req)
	var viol *ErrPostureViolation
	require.True(t, errors.As(err, &viol), "got %v", err)

	events := h.logs.events("vpn.refuse")
	require.Len(t, events, 1)
	assert.Equal(t, map[string]string{
		"device": req.DeviceID,
		"reason": string(RefusalPostureViolation),
		"rules":  "[fde-root-encrypted secure-boot]",
	}, events[0])
}

func TestRefuse_LogsAPolicyRefusalByClassOnly(t *testing.T) {
	h := newHarness(t, testConfig())
	h.identity.decision = calleradmission.Decision{Admitted: false, Reason: calleradmission.ReasonNotListed}
	_, err := h.svc.Admit(context.Background(), h.request(t))
	var refused *ErrPeerRefused
	require.True(t, errors.As(err, &refused), "got %v", err)

	events := h.logs.events("vpn.refuse")
	require.Len(t, events, 1)
	assert.Equal(t, string(calleradmission.ReasonNotListed), events[0]["reason"])
	assert.NotContains(t, events[0], "error", "a policy refusal logs its class, not its error text")
	assert.NotContains(t, events[0], "rules")
}

func TestRefuse_LogsTheCauseOfAGatewayFailure(t *testing.T) {
	h := newHarness(t, testConfig())
	h.posture.err = errors.New("engine down")
	_, err := h.svc.Admit(context.Background(), h.request(t))
	var unavailable *ErrPostureUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)

	events := h.logs.events("vpn.refuse")
	require.Len(t, events, 1)
	assert.Equal(t, string(RefusalPostureUnavailable), events[0]["reason"])
	assert.Contains(t, events[0]["error"], "engine down", "a 5xx refusal names the failing dependency")
}

func TestSweep_LogsEachExpiredLease(t *testing.T) {
	h := newHarness(t, testConfig())
	ctx := context.Background()
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)

	h.svc.Sweep(ctx)
	assert.Empty(t, h.logs.events("vpn.lease.expire"), "a live lease does not expire")

	h.clock.Advance(DefaultLeaseTTL + time.Second)
	h.svc.Sweep(ctx)
	events := h.logs.events("vpn.lease.expire")
	require.Len(t, events, 1)
	assert.Equal(t, string(lease.ID), events[0]["lease"])
	assert.Equal(t, lease.DeviceID, events[0]["device"])
	assert.Equal(t, lease.ExpiresAt.String(), events[0]["expired_at"])
	assert.Len(t, h.logs.events("vpn.revoke"), 1, "the expiry is followed by its revocation")

	h.svc.Sweep(ctx)
	assert.Len(t, h.logs.events("vpn.lease.expire"), 1, "a swept lease is gone; it does not expire twice")
}
