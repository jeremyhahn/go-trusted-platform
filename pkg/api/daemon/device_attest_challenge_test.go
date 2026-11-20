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

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// challengeService builds the fixture's DeviceGRPCService with its
// challenge store on a clock the test controls (#2136).
func challengeService(t *testing.T, f *quoteFixture, clock *time.Time, opts ...DeviceGRPCOption) *DeviceGRPCService {
	t.Helper()
	s := NewDeviceGRPCService(f.devices, f.profiles, nil, append(f.deviceOptions(), opts...)...)
	s.verifier.now = func() time.Time { return f.now }
	s.challenges.now = func() time.Time { return *clock }
	return s
}

func issueChallenge(t *testing.T, ctx context.Context, svc *DeviceGRPCService, deviceID string) *platformv1.IssueAttestationChallengeResponse {
	t.Helper()
	resp, err := svc.IssueAttestationChallenge(ctx, &platformv1.IssueAttestationChallengeRequest{DeviceId: deviceID})
	require.NoError(t, err)
	return resp
}

func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, want, status.Code(err), "error: %v", err)
}

func TestDeviceAttestChallenge_IssueAndVerify(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
	ctx := tokenCallerContext("tenant-a")

	ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
	assert.True(t, ch.GetStatus().GetSuccess())
	assert.Len(t, ch.GetNonce(), 32)
	assert.NotEmpty(t, ch.GetChallengeId())
	assert.Equal(t, f.now.Add(5*time.Minute), ch.GetExpiresAt().AsTime())

	resp, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	require.NoError(t, err)
	assert.True(t, resp.GetVerified())
	assert.True(t, resp.GetNonceValid())
}

func TestDeviceAttestChallenge_IssueRequiresADeviceID(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)

	_, err := svc.IssueAttestationChallenge(tokenCallerContext("tenant-a"), &platformv1.IssueAttestationChallengeRequest{})
	requireCode(t, err, codes.InvalidArgument)
}

func TestDeviceAttestChallenge_RefusesAMissingChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())

	_, err := svc.AttestDevice(tokenCallerContext("tenant-a"), &platformv1.AttestDeviceRequest{
		DeviceId: itoa(f.device.ID),
		Evidence: f.evidence(t, []byte("caller-chosen-nonce"), goldenPCRs()),
	})
	requireCode(t, err, codes.InvalidArgument)
}

func TestDeviceAttestChallenge_RefusesAnUnknownChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())

	_, err := svc.AttestDevice(tokenCallerContext("tenant-a"), &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, []byte("caller-chosen-nonce"), goldenPCRs()),
		ChallengeId: "deadbeef",
	})
	requireCode(t, err, codes.FailedPrecondition)
}

func TestDeviceAttestChallenge_RefusesAnExpiredChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
	ctx := tokenCallerContext("tenant-a")

	ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
	clock = f.now.Add(5*time.Minute + time.Second)

	_, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireCode(t, err, codes.FailedPrecondition)
}

func TestDeviceAttestChallenge_RefusesAReusedChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
	ctx := tokenCallerContext("tenant-a")
	otherKey, _ := newAttestTestKey(t)

	ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))

	// The first attempt fails verification (wrong key) but still consumes
	// the challenge.
	first, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    signedEvidence(t, otherKey, ch.GetNonce(), goldenPCRs(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	require.NoError(t, err)
	assert.False(t, first.GetVerified())

	_, err = svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireCode(t, err, codes.FailedPrecondition)
}

func TestDeviceAttestChallenge_RefusesANonceMismatch(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
	ctx := tokenCallerContext("tenant-a")

	ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))

	_, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, []byte("a-replayed-older-nonce"), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireCode(t, err, codes.FailedPrecondition)

	// The mismatch consumed the challenge: the right nonce is now too late.
	_, err = svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireCode(t, err, codes.FailedPrecondition)
}

func TestDeviceAttestChallenge_RefusesAnotherDevicesChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
	ctx := tokenCallerContext("tenant-a")

	ch := issueChallenge(t, ctx, svc, "some-other-device")

	_, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireCode(t, err, codes.FailedPrecondition)
}

func TestDeviceAttestChallenge_RefusesAnotherTenantsChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())

	ch := issueChallenge(t, tokenCallerContext("tenant-a"), svc, itoa(f.device.ID))

	_, err := svc.AttestDevice(tokenCallerContext("tenant-b"), &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireCode(t, err, codes.PermissionDenied)
}
