package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// Issue #2136, owner ruling 1234: a challenge is issued over MCP, gRPC, REST
// or the Unix socket and presented to QUIC opcode 0x3A. QUIC must check it
// against the daemon's one challenge store, so it is honoured, single use
// across every transport, and follows the daemon's challenge requirement.

// sharedChallengeQUICHandler builds a QUIC handler whose attest delegate
// shares svc's challenge store.
func sharedChallengeQUICHandler(t *testing.T, f *quoteFixture, svc *DeviceGRPCService) *QUICServiceHandler {
	t.Helper()
	h := &QUICServiceHandler{
		deviceService:  f.devices,
		profileService: f.profiles,
		logger:         logging.DefaultLogger(),
		akTrust:        f.trust,
		deviceVerdicts: f.sink,
	}
	if svc != nil {
		h.SetDeviceAttestChallenges(svc)
	} else {
		h.rebuildDeviceGRPC()
	}
	h.deviceGRPC.verifier.now = func() time.Time { return f.now }
	return h
}

// quicAttestWithChallenge sends OpDeviceAttest carrying challengeID and
// returns the raw QUIC response.
func quicAttestWithChallenge(t *testing.T, ctx context.Context, h *QUICServiceHandler, f *quoteFixture, nonce []byte, challengeID string) *quicwire.Response {
	t.Helper()
	payload, err := quicwire.EncodePayload(&platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, nonce, goldenPCRs()),
		ChallengeId: challengeID,
	})
	require.NoError(t, err)
	return h.handleDeviceOperation(ctx, &quicwire.Request{
		Opcode:  quicwire.OpDeviceAttest,
		Payload: payload,
	})
}

func requireQUICVerified(t *testing.T, resp *quicwire.Response) {
	t.Helper()
	require.Equal(t, quicwire.StatusOK, resp.Status, "payload: %s", resp.Payload)
	var decoded platformv1.AttestDeviceResponse
	require.NoError(t, quicwire.DecodePayload(resp.Payload, &decoded))
	assert.True(t, decoded.GetVerified(), "message: %s", decoded.GetMessage())
}

func TestQUICDeviceAttest_HonoursAChallengeIssuedByTheDaemonService(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)
	h := sharedChallengeQUICHandler(t, f, svc)
	ctx := tokenCallerContext("tenant-a")

	ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))
	requireQUICVerified(t, quicAttestWithChallenge(t, ctx, h, f, ch.GetNonce(), ch.GetChallengeId()))

	again := quicAttestWithChallenge(t, ctx, h, f, ch.GetNonce(), ch.GetChallengeId())
	assert.NotEqual(t, quicwire.StatusOK, again.Status, "a challenge is single use over QUIC")

	_, err := svc.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId:    itoa(f.device.ID),
		Evidence:    f.evidence(t, ch.GetNonce(), goldenPCRs()),
		ChallengeId: ch.GetChallengeId(),
	})
	requireChallengeCode(t, err, codes.FailedPrecondition)
}

func TestQUICDeviceAttest_SharedChallengesSurviveARebuild(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)
	ctx := tokenCallerContext("tenant-a")
	ch := issueChallenge(t, ctx, svc, itoa(f.device.ID))

	h := &QUICServiceHandler{
		deviceService:  f.devices,
		profileService: f.profiles,
		logger:         logging.DefaultLogger(),
		akTrust:        f.trust,
		deviceVerdicts: f.sink,
	}
	h.SetDeviceAttestChallenges(svc)
	h.SetDeviceProfileService(f.profiles)
	h.SetDeviceVerdictSink(f.sink)
	h.deviceGRPC.verifier.now = func() time.Time { return f.now }

	assert.Same(t, svc.challenges, h.deviceGRPC.challenges, "a rebuild must keep the daemon's store")
	requireQUICVerified(t, quicAttestWithChallenge(t, ctx, h, f, ch.GetNonce(), ch.GetChallengeId()))
}

func TestQUICDeviceAttest_FollowsTheDaemonChallengeRequirement(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock, WithDeviceAttestChallengeRequired())
	ctx := tokenCallerContext("tenant-a")

	shared := sharedChallengeQUICHandler(t, f, svc)
	resp := quicAttestWithChallenge(t, ctx, shared, f, []byte("no-challenge-nonce-01"), "")
	assert.NotEqual(t, quicwire.StatusOK, resp.Status)
	assert.Contains(t, string(resp.Payload), "challenge_id is required")

	private := sharedChallengeQUICHandler(t, f, nil)
	requireQUICVerified(t, quicAttestWithChallenge(t, ctx, private, f, []byte("no-challenge-nonce-02"), ""))
}

func TestQUICDeviceAttest_RefusesAnotherTenantsChallenge(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)
	h := sharedChallengeQUICHandler(t, f, svc)

	ch := issueChallenge(t, tokenCallerContext("tenant-a"), svc, itoa(f.device.ID))

	other := quicAttestWithChallenge(t, tokenCallerContext("tenant-b"), h, f, ch.GetNonce(), ch.GetChallengeId())
	assert.NotEqual(t, quicwire.StatusOK, other.Status, "another tenant's challenge must be refused")

	later := quicAttestWithChallenge(t, tokenCallerContext("tenant-a"), h, f, ch.GetNonce(), ch.GetChallengeId())
	assert.NotEqual(t, quicwire.StatusOK, later.Status, "the refused attempt consumed the challenge")
}
