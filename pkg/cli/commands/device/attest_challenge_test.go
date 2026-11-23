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

package device

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// testChallengeExpiry is the expires_at the in-process server answers.
var testChallengeExpiry = time.Date(2026, 11, 23, 12, 5, 0, 0, time.UTC)

// IssueAttestationChallenge answers a challenge for device 42, the one
// registered device, and NotFound for any other.
func (s *inProcProfileServer) IssueAttestationChallenge(_ context.Context, r *platformv1.IssueAttestationChallengeRequest) (*platformv1.IssueAttestationChallengeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastChallenge = r
	if s.fail != nil {
		return nil, s.fail
	}
	if r.GetDeviceId() != "42" {
		return nil, status.Error(codes.NotFound, "device not found")
	}
	return &platformv1.IssueAttestationChallengeResponse{
		ChallengeId: "c-42",
		Nonce:       []byte("nonce-42"),
		ExpiresAt:   timestamppb.New(testChallengeExpiry),
	}, nil
}

func TestRunAttestChallenge(t *testing.T) {
	srv, flags := startProfileServer(t)

	require.NoError(t, runAttestChallenge(flags(cli.OutputFormatTable), "42"))

	out, err := captureStdout(t, func() error { return runAttestChallenge(flags(cli.OutputFormatJSON), "42") })
	require.NoError(t, err)

	var got struct {
		DeviceID    uint64    `json:"device_id"`
		ChallengeID string    `json:"challenge_id"`
		Nonce       string    `json:"nonce"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	require.NoError(t, json.Unmarshal([]byte(out), &got), "output %q", out)
	assert.Equal(t, uint64(42), got.DeviceID)
	assert.Equal(t, "c-42", got.ChallengeID)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("nonce-42")), got.Nonce)
	assert.True(t, got.ExpiresAt.Equal(testChallengeExpiry), "expires_at = %v", got.ExpiresAt)

	srv.mu.Lock()
	defer srv.mu.Unlock()
	assert.Equal(t, "42", srv.lastChallenge.GetDeviceId())
}

func TestRunAttestChallenge_Errors(t *testing.T) {
	srv, flags := startProfileServer(t)
	f := flags(cli.OutputFormatJSON)

	t.Run("InvalidID", func(t *testing.T) {
		for _, id := range []string{"0", "abc"} {
			assert.Equal(t, ErrInvalidDeviceID{ID: id}, runAttestChallenge(&cli.CommonFlags{}, id))
		}
	})

	t.Run("UnknownDevice", func(t *testing.T) {
		assert.Equal(t, ErrDeviceNotFound{ID: 4242}, runAttestChallenge(f, "4242"))
	})

	t.Run("ServerFailure", func(t *testing.T) {
		srv.mu.Lock()
		srv.fail = status.Error(codes.Unavailable, "challenge store unavailable")
		srv.mu.Unlock()
		err := runAttestChallenge(f, "42")
		var challengeErr ErrAttestChallengeFailed
		require.True(t, errors.As(err, &challengeErr), "err = %v", err)
		assert.Equal(t, uint64(42), challengeErr.ID)
		assert.Contains(t, err.Error(), "challenge store unavailable", "the server's reason is shown")
	})
}

func TestAttestChallengeCommand_Flags(t *testing.T) {
	cmd := newAttestChallengeCommand(nil)
	assert.Equal(t, "attest-challenge <id>", cmd.Use)
	assert.Error(t, cmd.Args(cmd, nil), "the device id is required")

	found := false
	for _, sub := range NewCommand(nil).Commands() {
		if sub.Use == "attest-challenge <id>" {
			found = true
		}
	}
	assert.True(t, found, "attest-challenge is registered under device")
}

func TestRunAttest_SendsTheChallengeID(t *testing.T) {
	srv, flags := startProfileServer(t)
	path := writeEvidenceFile(t, testEvidence)

	require.NoError(t, runAttest(flags(cli.OutputFormatJSON), "42", path, "c-42"))
	srv.mu.Lock()
	assert.Equal(t, "c-42", srv.lastAttest.GetChallengeId())
	srv.mu.Unlock()

	require.NoError(t, runAttest(flags(cli.OutputFormatJSON), "42", path, ""))
	srv.mu.Lock()
	assert.Empty(t, srv.lastAttest.GetChallengeId())
	srv.mu.Unlock()
}
