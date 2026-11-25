package daemon

import (
	"testing"

	"google.golang.org/grpc/codes"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// An attestation challenge is issued only for a device that exists: the
// shared service looks the device up first, so gRPC, REST, MCP and the CLI
// refuse an unknown device the way GetDevice does (#2136, Codex round 1 P1).

func TestDeviceAttestChallenge_IssueRefusesAnUnknownDevice(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)

	_, err := svc.IssueAttestationChallenge(tokenCallerContext("tenant-a"), &platformv1.IssueAttestationChallengeRequest{
		DeviceId: itoa(f.device.ID + 1000),
	})
	requireChallengeCode(t, err, codes.NotFound)
}

func TestDeviceAttestChallenge_IssueRefusesAMalformedDeviceID(t *testing.T) {
	f := newQuoteFixture(t)
	clock := f.now
	svc := challengeService(t, f, &clock)

	_, err := svc.IssueAttestationChallenge(tokenCallerContext("tenant-a"), &platformv1.IssueAttestationChallengeRequest{
		DeviceId: "abc",
	})
	requireChallengeCode(t, err, codes.InvalidArgument)
}

func TestDeviceAttestChallenge_IssueWithoutADeviceServiceIsUnavailable(t *testing.T) {
	f := newQuoteFixture(t)
	svc := NewDeviceGRPCService(nil, f.profiles, nil, f.deviceOptions()...)

	_, err := svc.IssueAttestationChallenge(tokenCallerContext("tenant-a"), &platformv1.IssueAttestationChallengeRequest{
		DeviceId: itoa(f.device.ID),
	})
	requireChallengeCode(t, err, codes.Unavailable)
}
