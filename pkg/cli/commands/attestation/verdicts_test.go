// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// verdictStream replays events, then ends with end (io.EOF when nil).
type verdictStream struct {
	grpc.ClientStream
	events []*platformv1.DeviceVerdictEvent
	end    error
}

func (s *verdictStream) Recv() (*platformv1.DeviceVerdictEvent, error) {
	if len(s.events) == 0 {
		if s.end == nil {
			return nil, io.EOF
		}
		return nil, s.end
	}
	event := s.events[0]
	s.events = s.events[1:]
	return event, nil
}

// verdictClient is the fake attestation client with StreamDeviceVerdicts
// stubbed; every other RPC still panics.
type verdictClient struct {
	fakeAttestationClient
	stream  *verdictStream
	openErr error
	opened  int
}

func (c *verdictClient) StreamDeviceVerdicts(context.Context, *platformv1.StreamDeviceVerdictsRequest, ...grpc.CallOption) (grpc.ServerStreamingClient[platformv1.DeviceVerdictEvent], error) {
	c.opened++
	if c.openErr != nil {
		return nil, c.openErr
	}
	return c.stream, nil
}

var verdictAt = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

// verdictEvents is a pass, a cryptographic failure and a failure from a check
// that could not run, in the order platformd recorded them.
func verdictEvents() []*platformv1.DeviceVerdictEvent {
	return []*platformv1.DeviceVerdictEvent{
		{EventId: "ev-1", RecordedAt: timestamppb.New(verdictAt), DeviceId: 9, TenantId: "t1",
			HostId: "h9", Serial: "SN-9", Passed: true},
		{EventId: "ev-2", RecordedAt: timestamppb.New(verdictAt.Add(time.Second)), DeviceId: 12, TenantId: "t1",
			Serial: "SN-12", Cryptographic: true, Reason: "PCR 7 does not match the baseline"},
		{EventId: "ev-3", RecordedAt: timestamppb.New(verdictAt.Add(2 * time.Second)), DeviceId: 15,
			Reason: "device has no attestation certificate on record"},
	}
}

func TestFollowVerdicts_TablePrintsOneLinePerVerdict(t *testing.T) {
	r, out := newRunner(&verdictClient{stream: &verdictStream{events: verdictEvents()}}, cli.OutputFormatTable)
	require.NoError(t, r.followVerdicts(), "the stream ending is the follow ending, not an error")

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 3)
	assert.Equal(t, "2026-10-09T12:00:00Z  device 9  serial SN-9  tenant t1  verified", lines[0])
	assert.Equal(t, "2026-10-09T12:00:01Z  device 12  serial SN-12  tenant t1  failed: PCR 7 does not match the baseline", lines[1])
	// A failure from a check that could not run is never printed as "failed".
	assert.Equal(t, "2026-10-09T12:00:02Z  device 15  serial -  tenant -  not verified: device has no attestation certificate on record", lines[2])
}

func TestFollowVerdicts_JSONIsOneObjectPerVerdict(t *testing.T) {
	r, out := newRunner(&verdictClient{stream: &verdictStream{events: verdictEvents()}}, cli.OutputFormatJSON)
	require.NoError(t, r.followVerdicts())

	decoder := json.NewDecoder(out)
	var got []map[string]any
	for decoder.More() {
		var v map[string]any
		require.NoError(t, decoder.Decode(&v))
		got = append(got, v)
	}
	require.Len(t, got, 3)
	assert.Equal(t, "ev-1", got[0]["event_id"])
	assert.Equal(t, "2026-10-09T12:00:00Z", got[0]["recorded_at"])
	assert.EqualValues(t, 9, got[0]["device_id"])
	assert.Equal(t, true, got[0]["passed"])
	// A failed verdict is present as passed:false, not omitted.
	assert.Equal(t, false, got[1]["passed"])
	assert.Equal(t, true, got[1]["cryptographic"])
	assert.Equal(t, "PCR 7 does not match the baseline", got[1]["reason"])
}

func TestFollowVerdicts_YAMLIsOneDocumentPerVerdict(t *testing.T) {
	r, out := newRunner(&verdictClient{stream: &verdictStream{events: verdictEvents()}}, cli.OutputFormatYAML)
	require.NoError(t, r.followVerdicts())

	decoder := yaml.NewDecoder(bytes.NewReader(out.Bytes()))
	var ids []string
	for {
		var v map[string]any
		err := decoder.Decode(&v)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		ids = append(ids, v["event_id"].(string))
	}
	assert.Equal(t, []string{"ev-1", "ev-2", "ev-3"}, ids)
}

func TestFollowVerdicts_OpenFails(t *testing.T) {
	client := &verdictClient{openErr: status.Error(codes.PermissionDenied, "attestation:read required")}
	r, _ := newRunner(client, cli.OutputFormatTable)
	err := r.followVerdicts()
	var failed ErrFollowVerdictsFailed
	require.ErrorAs(t, err, &failed)
	assert.Contains(t, failed.Reason, "attestation:read required")
}

// TestFollowVerdicts_StreamFailsAfterVerdicts pins that a broken stream is an
// error, never a quiet end: the verdicts already received are printed, then
// the follow fails with the cause.
func TestFollowVerdicts_StreamFailsAfterVerdicts(t *testing.T) {
	stream := &verdictStream{events: verdictEvents()[:1], end: status.Error(codes.ResourceExhausted, "verdicts were missed")}
	r, out := newRunner(&verdictClient{stream: stream}, cli.OutputFormatTable)
	err := r.followVerdicts()
	var failed ErrFollowVerdictsFailed
	require.ErrorAs(t, err, &failed)
	assert.Contains(t, failed.Reason, "verdicts were missed")
	assert.Contains(t, out.String(), "device 9")
}

// TestFollowVerdicts_InterruptEndsCleanly pins that stopping a follow (the
// command's context ending on SIGINT/SIGTERM) is a clean exit.
func TestFollowVerdicts_InterruptEndsCleanly(t *testing.T) {
	stream := &verdictStream{end: status.Error(codes.Canceled, "context canceled")}
	r, _ := newRunner(&verdictClient{stream: stream}, cli.OutputFormatTable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.ctx = ctx
	assert.NoError(t, r.followVerdicts())
}

func TestVerdictsCommand_Surface(t *testing.T) {
	cmd := NewCommand(func() *cli.CommonFlags { return &cli.CommonFlags{} })
	verdicts, _, err := cmd.Find([]string{"verdicts", "follow"})
	require.NoError(t, err)
	assert.Equal(t, "follow", verdicts.Name())
}

func TestErrFollowVerdictsFailed_Message(t *testing.T) {
	assert.Equal(t, "failed to follow device verdicts: boom", ErrFollowVerdictsFailed{Reason: "boom"}.Error())
}
