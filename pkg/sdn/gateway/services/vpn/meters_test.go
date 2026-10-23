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
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/policy/opa"
)

func TestDurationHistogram_BucketsAreCumulative(t *testing.T) {
	h := newDurationHistogram([]float64{0.1, 1})
	h.observe(50 * time.Millisecond)
	h.observe(100 * time.Millisecond) // on a bound: counts in that bucket
	h.observe(500 * time.Millisecond)
	h.observe(3 * time.Second) // over every bound: only in Count

	got := h.snapshot()
	assert.Equal(t, uint64(4), got.Count)
	assert.Equal(t, 3650*time.Millisecond, got.Sum)
	assert.Equal(t, []HistogramBucket{{UpperBoundSeconds: 0.1, Count: 2}, {UpperBoundSeconds: 1, Count: 3}}, got.Buckets)
}

func TestDurationHistogram_NegativeDurationCountsAsZero(t *testing.T) {
	h := newDurationHistogram([]float64{0.1})
	h.observe(-time.Second)
	got := h.snapshot()
	assert.Equal(t, uint64(1), got.Count)
	assert.Equal(t, time.Duration(0), got.Sum, "a clock stepped back never subtracts from the sum")
	assert.Equal(t, uint64(1), got.Buckets[0].Count)
}

func TestLabelledCounters_CountsByLabel(t *testing.T) {
	var c labelledCounters
	assert.Nil(t, c.snapshot(), "nothing counted is no map")

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.inc("a")
		}()
	}
	wg.Wait()
	c.inc("b")
	assert.Equal(t, map[string]uint64{"a": 10, "b": 1}, c.snapshot())
}

func TestLabelledCounters_OverflowPastTheLimit(t *testing.T) {
	c := labelledCounters{limit: 2, overflow: OtherPostureRule}
	for i := range 5 {
		c.inc("rule-" + strconv.Itoa(i))
	}
	c.inc("rule-0")
	assert.Equal(t, map[string]uint64{"rule-0": 2, "rule-1": 1, OtherPostureRule: 3}, c.snapshot(),
		"labels past the limit count under the overflow label; a known one keeps counting")
}

func TestHealth_CountsNothingBeforeAnyEvent(t *testing.T) {
	h := newHarness(t, testConfig())
	health := h.svc.Health()
	assert.Nil(t, health.Revocations)
	assert.Nil(t, health.PostureViolations)
	assert.Equal(t, uint64(0), health.Reattest.Count)
	assert.Len(t, health.Reattest.Buckets, len(reattestBuckets), "an empty histogram still has its buckets")
}

func TestHealth_CountsRevocationsByReason(t *testing.T) {
	h := newHarness(t, testConfig())
	ctx := context.Background()
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	require.NoError(t, h.svc.Revoke(ctx, lease.ID, RevokeOperator))

	lease, err = h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.clock.Advance(DefaultLeaseTTL + time.Second)
	h.svc.Sweep(ctx)

	assert.Equal(t, map[RevokeReason]uint64{RevokeOperator: 1, RevokeExpired: 1}, h.svc.Health().Revocations)

	var nf *ErrLeaseNotFound
	require.True(t, errors.As(h.svc.Revoke(ctx, lease.ID, RevokeOperator), &nf))
	assert.Equal(t, uint64(1), h.svc.Health().Revocations[RevokeOperator], "a revoke that finds no lease counts nothing")
}

func TestHealth_CountsPostureViolationsByRule(t *testing.T) {
	h := newHarness(t, testConfig())
	ctx := context.Background()
	h.posture.result = &opa.EvaluationResult{Violations: []opa.Violation{{Rule: "fde-root-encrypted"}, {Rule: "secure-boot"}}}
	_, err := h.svc.Admit(ctx, h.request(t))
	var viol *ErrPostureViolation
	require.True(t, errors.As(err, &viol), "got %v", err)

	h.posture.result = &opa.EvaluationResult{Allowed: false}
	_, err = h.svc.Admit(ctx, h.request(t))
	require.True(t, errors.As(err, &viol), "got %v", err)

	h.posture.err = errors.New("engine down")
	_, err = h.svc.Admit(ctx, h.request(t))
	var unavailable *ErrPostureUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)

	// A renewal without a posture report is refused by the rule
	// posture-missing; an admission without one never reaches posture.
	h.posture.err = nil
	h.posture.result = &opa.EvaluationResult{Allowed: true}
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	h.intoRenewWindow()
	ev := h.evidence(t)
	ev.Posture = nil
	_, err = h.svc.Renew(ctx, lease.ID, ev)
	require.True(t, errors.As(err, &viol), "got %v", err)

	assert.Equal(t, map[string]uint64{"fde-root-encrypted": 1, "secure-boot": 1, "denied": 1, "posture-missing": 1},
		h.svc.Health().PostureViolations, "an engine failure is a refusal, not a rule violation")
}

func TestHealth_TimesRenewalReattestation(t *testing.T) {
	h := newHarness(t, testConfig())
	ctx := context.Background()
	lease, err := h.svc.Admit(ctx, h.request(t))
	require.NoError(t, err)
	assert.Equal(t, uint64(0), h.svc.Health().Reattest.Count, "the admission attestation is not a re-attestation")

	h.verifier.clock = h.clock
	h.verifier.takes = 300 * time.Millisecond
	h.intoRenewWindow()
	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	require.NoError(t, err)

	h.verifier.takes = 20 * time.Second
	h.verifier.verdict = &verdict.DeviceVerdict{Passed: false, Cryptographic: true, Reason: "drift"}
	h.intoRenewWindow()
	_, err = h.svc.Renew(ctx, lease.ID, h.evidence(t))
	var failed *ErrAttestationFailed
	require.True(t, errors.As(err, &failed), "got %v", err)

	got := h.svc.Health().Reattest
	assert.Equal(t, uint64(2), got.Count, "a failed re-attestation is timed too")
	assert.Equal(t, 20300*time.Millisecond, got.Sum)
	for _, b := range got.Buckets {
		want := uint64(0)
		if b.UpperBoundSeconds >= 0.3 {
			want = 1
		}
		assert.Equal(t, want, b.Count, "bucket le=%v", b.UpperBoundSeconds)
	}
	assert.Equal(t, uint64(1), h.svc.Health().Revocations[RevokeAttestation])
}
