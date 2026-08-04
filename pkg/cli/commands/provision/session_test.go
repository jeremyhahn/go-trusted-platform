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

package provision

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func testGetFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{}
	}
}

func TestNewSessionCommand_Structure(t *testing.T) {
	cmd := newSessionCommand(testGetFlags())

	if cmd.Use != "session" {
		t.Errorf("Use = %q, want session", cmd.Use)
	}

	subcommands := map[string]bool{}
	for _, sub := range cmd.Commands() {
		subcommands[sub.Name()] = true
	}
	for _, want := range []string{"list", "get", "fulfill", "poll"} {
		if !subcommands[want] {
			t.Errorf("missing %q subcommand; have %v", want, subcommands)
		}
	}
}

func TestNewSessionSubcommands_Structure(t *testing.T) {
	getFlags := testGetFlags()

	list := newSessionListCommand(getFlags)
	if list.Use != "list" || list.RunE == nil {
		t.Errorf("list command malformed: Use=%q RunE set=%t", list.Use, list.RunE != nil)
	}

	get := newSessionGetCommand(getFlags)
	if get.Use != "get <session-id>" || get.RunE == nil || get.Args == nil {
		t.Errorf("get command malformed: Use=%q", get.Use)
	}

	fulfill := newSessionFulfillCommand(getFlags)
	if fulfill.Use != "fulfill <session-id>" || fulfill.RunE == nil {
		t.Errorf("fulfill command malformed: Use=%q", fulfill.Use)
	}
	if fulfill.Flags().Lookup("profile-id") == nil {
		t.Error("fulfill command missing --profile-id flag")
	}

	poll := newSessionPollCommand(getFlags)
	if poll.Use != "poll <session-id>" || poll.RunE == nil {
		t.Errorf("poll command malformed: Use=%q", poll.Use)
	}
	if poll.Flags().Lookup("output") == nil {
		t.Error("poll command missing --output flag")
	}
}

func TestSessionGetCommand_RequiresSessionIDArg(t *testing.T) {
	cmd := newSessionGetCommand(testGetFlags())
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected arg-count error when session ID is missing")
	}
}

func TestSessionFulfill_ProfileIDValidation(t *testing.T) {
	tests := []struct {
		name      string
		profileID string
		wantErr   error
	}{
		{"missing", "", ErrProfileIDRequired{}},
		{"zero", "0", ErrProfileIDRequired{}},
		{"non-numeric", "abc", ErrInvalidProfileID{}},
		{"negative", "-1", ErrInvalidProfileID{}},
		{"overflow", "99999999999999999999999", ErrInvalidProfileID{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseProfileID(tt.profileID)
			if err == nil {
				t.Fatal("expected validation error")
			}
			switch tt.wantErr.(type) {
			case ErrProfileIDRequired:
				var typed ErrProfileIDRequired
				if !errors.As(err, &typed) {
					t.Errorf("expected ErrProfileIDRequired, got %T: %v", err, err)
				}
			case ErrInvalidProfileID:
				var typed ErrInvalidProfileID
				if !errors.As(err, &typed) {
					t.Errorf("expected ErrInvalidProfileID, got %T: %v", err, err)
				}
			}
		})
	}
}

func TestSetSessionClientFactory_SwapAndRestore(t *testing.T) {
	sentinel := errors.New("factory called")

	restore := SetSessionClientFactory(func(base *cli.BaseCommand) (sessionAPI, error) {
		return nil, sentinel
	})

	got, err := activeSessionClientFactory(nil)
	if got != nil || !errors.Is(err, sentinel) {
		t.Errorf("swapped factory not in effect: client=%v err=%v", got, err)
	}

	restore()
	// The default factory must be back in place (pointer comparison is not
	// possible for funcs; assert behaviorally that it no longer returns
	// the sentinel).
	defer func() {
		// defaultSessionClientFactory dereferences base.Client(); calling
		// it with a nil base panics, which proves the default (daemon-
		// dialing) factory was restored rather than the sentinel fake.
		if recover() == nil {
			t.Error("expected default factory to be restored")
		}
	}()
	if _, err := activeSessionClientFactory(nil); errors.Is(err, sentinel) {
		t.Error("restore() did not reinstate the default factory")
	}
}

func TestSessionToInfo_MapsAllFields(t *testing.T) {
	created := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	expires := created.Add(15 * time.Minute)

	info := sessionToInfo(&platformv1.ProvisioningSession{
		Id:         "sess-1",
		EkSerial:   "EK1",
		MacAddress: "aa:bb",
		TenantId:   "tenant-1",
		ProfileId:  18446744073709551615,
		Fulfilled:  true,
		CreatedAt:  timestamppb.New(created),
		ExpiresAt:  timestamppb.New(expires),
	})

	if info.ID != "sess-1" || info.EKSerial != "EK1" || info.MACAddress != "aa:bb" ||
		info.TenantID != "tenant-1" || !info.Fulfilled {
		t.Errorf("info = %+v", info)
	}
	if info.ProfileID != 18446744073709551615 {
		t.Errorf("ProfileID = %d, want max uint64", info.ProfileID)
	}
	if info.CreatedAt != "2026-08-01T10:00:00Z" {
		t.Errorf("CreatedAt = %q", info.CreatedAt)
	}
	if info.ExpiresAt != "2026-08-01T10:15:00Z" {
		t.Errorf("ExpiresAt = %q", info.ExpiresAt)
	}
}

// TestSessionInfo_ProfileIDMarshalsAsString pins the uint64-as-string JSON
// convention for profile IDs in CLI output.
func TestSessionInfo_ProfileIDMarshalsAsString(t *testing.T) {
	data, err := json.Marshal(sessionInfo{ID: "s", ProfileID: 18446744073709551615})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	profileID, ok := decoded["profile_id"].(string)
	if !ok {
		t.Fatalf("profile_id = %v (%T), want JSON string", decoded["profile_id"], decoded["profile_id"])
	}
	if profileID != "18446744073709551615" {
		t.Errorf("profile_id = %q, want full uint64 precision", profileID)
	}
}

func TestFormatTimestamp(t *testing.T) {
	if got := formatTimestamp(nil); got != "" {
		t.Errorf("formatTimestamp(nil) = %q, want empty", got)
	}
	ts := timestamppb.New(time.Date(2026, 8, 2, 12, 30, 0, 0, time.UTC))
	if got := formatTimestamp(ts); got != "2026-08-02T12:30:00Z" {
		t.Errorf("formatTimestamp() = %q", got)
	}
}

// fakeSessionAPI provides programmable session responses for verb tests.
type fakeSessionAPI struct {
	err      error
	sessions []*platformv1.ProvisioningSession
	session  *platformv1.ProvisioningSession
	fulfill  *platformv1.FulfillSessionResponse
	poll     *platformv1.PollSessionResponse

	lastFulfillSessionID string
	lastFulfillProfileID uint64
}

func (f *fakeSessionAPI) ListSessions(ctx context.Context) ([]*platformv1.ProvisioningSession, error) {
	return f.sessions, f.err
}

func (f *fakeSessionAPI) GetSession(ctx context.Context, sessionID string) (*platformv1.ProvisioningSession, error) {
	return f.session, f.err
}

func (f *fakeSessionAPI) FulfillSession(ctx context.Context, sessionID string, profileID uint64) (*platformv1.FulfillSessionResponse, error) {
	f.lastFulfillSessionID = sessionID
	f.lastFulfillProfileID = profileID
	return f.fulfill, f.err
}

func (f *fakeSessionAPI) PollSession(ctx context.Context, sessionID string) (*platformv1.PollSessionResponse, error) {
	return f.poll, f.err
}

// Compile-time check: the fake satisfies the verb-facing interface.
var _ sessionAPI = (*fakeSessionAPI)(nil)

func TestParseProfileID_Valid(t *testing.T) {
	id, err := parseProfileID("18446744073709551615")
	if err != nil {
		t.Fatalf("parseProfileID() unexpected error: %v", err)
	}
	if id != 18446744073709551615 {
		t.Errorf("id = %d, want max uint64", id)
	}
}

func TestSessionListOutput(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := &fakeSessionAPI{
			sessions: []*platformv1.ProvisioningSession{
				{Id: "a", ProfileId: 1},
				{Id: "b", Fulfilled: true},
			},
		}
		infos, err := sessionListOutput(context.Background(), fake)
		if err != nil {
			t.Fatalf("sessionListOutput() unexpected error: %v", err)
		}
		if len(infos) != 2 || infos[0].ID != "a" || !infos[1].Fulfilled {
			t.Errorf("infos = %+v", infos)
		}
	})

	t.Run("error", func(t *testing.T) {
		fake := &fakeSessionAPI{err: errors.New("boom")}
		if _, err := sessionListOutput(context.Background(), fake); err == nil {
			t.Fatal("expected error passthrough")
		}
	})
}

func TestSessionGetOutput(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := &fakeSessionAPI{session: &platformv1.ProvisioningSession{Id: "sess-1"}}
		info, err := sessionGetOutput(context.Background(), fake, "sess-1")
		if err != nil {
			t.Fatalf("sessionGetOutput() unexpected error: %v", err)
		}
		if info.ID != "sess-1" {
			t.Errorf("info = %+v", info)
		}
	})

	t.Run("error", func(t *testing.T) {
		fake := &fakeSessionAPI{err: errors.New("boom")}
		if _, err := sessionGetOutput(context.Background(), fake, "sess-1"); err == nil {
			t.Fatal("expected error passthrough")
		}
	})
}

func TestSessionFulfillOutput(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		fake := &fakeSessionAPI{fulfill: &platformv1.FulfillSessionResponse{Status: "fulfilled"}}
		out, err := sessionFulfillOutput(context.Background(), fake, "sess-1", 42)
		if err != nil {
			t.Fatalf("sessionFulfillOutput() unexpected error: %v", err)
		}
		if out["status"] != "fulfilled" || out["profile_id"] != "42" || out["session_id"] != "sess-1" {
			t.Errorf("out = %v", out)
		}
		if fake.lastFulfillSessionID != "sess-1" || fake.lastFulfillProfileID != 42 {
			t.Errorf("client args = %q/%d", fake.lastFulfillSessionID, fake.lastFulfillProfileID)
		}
	})

	t.Run("error", func(t *testing.T) {
		fake := &fakeSessionAPI{err: errors.New("boom")}
		if _, err := sessionFulfillOutput(context.Background(), fake, "sess-1", 42); err == nil {
			t.Fatal("expected error passthrough")
		}
	})
}

func TestSessionPollOutput(t *testing.T) {
	t.Run("pending", func(t *testing.T) {
		fake := &fakeSessionAPI{poll: &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_PendingStatus{PendingStatus: "pending"},
		}}
		out, err := sessionPollOutput(context.Background(), fake, "sess-1", "")
		if err != nil {
			t.Fatalf("sessionPollOutput() unexpected error: %v", err)
		}
		if out["status"] != "pending" {
			t.Errorf("out = %v", out)
		}
	})

	t.Run("delivered inline", func(t *testing.T) {
		fake := &fakeSessionAPI{poll: &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_Delivered{
				Delivered: &platformv1.DeliveredConfig{ConfigJson: []byte(`{"a":1}`), Status: "ok"},
			},
		}}
		out, err := sessionPollOutput(context.Background(), fake, "sess-1", "")
		if err != nil {
			t.Fatalf("sessionPollOutput() unexpected error: %v", err)
		}
		if out["status"] != "ok" || out["config"] != `{"a":1}` {
			t.Errorf("out = %v", out)
		}
	})

	t.Run("delivered to file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		fake := &fakeSessionAPI{poll: &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_Delivered{
				Delivered: &platformv1.DeliveredConfig{ConfigJson: []byte(`{"a":1}`), Status: "ok"},
			},
		}}
		out, err := sessionPollOutput(context.Background(), fake, "sess-1", path)
		if err != nil {
			t.Fatalf("sessionPollOutput() unexpected error: %v", err)
		}
		if out["output"] != path {
			t.Errorf("out = %v", out)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil || string(data) != `{"a":1}` {
			t.Errorf("written config = %q err=%v", data, readErr)
		}
	})

	t.Run("write failure", func(t *testing.T) {
		fake := &fakeSessionAPI{poll: &platformv1.PollSessionResponse{
			Result: &platformv1.PollSessionResponse_Delivered{
				Delivered: &platformv1.DeliveredConfig{ConfigJson: []byte(`{}`), Status: "ok"},
			},
		}}
		badPath := filepath.Join(t.TempDir(), "missing-dir", "config.json")
		_, err := sessionPollOutput(context.Background(), fake, "sess-1", badPath)
		var typed ErrConfigWriteFailed
		if !errors.As(err, &typed) {
			t.Fatalf("expected ErrConfigWriteFailed, got %T: %v", err, err)
		}
	})

	t.Run("error", func(t *testing.T) {
		fake := &fakeSessionAPI{err: errors.New("boom")}
		if _, err := sessionPollOutput(context.Background(), fake, "sess-1", ""); err == nil {
			t.Fatal("expected error passthrough")
		}
	})
}
