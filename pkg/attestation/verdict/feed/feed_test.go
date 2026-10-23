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

package feed

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

// testDeadline bounds every wait a test makes on the feed.
const testDeadline = 10 * time.Second

func record(f *Feed, eventID, tenantID string) {
	f.OnDeviceVerdict(context.Background(), verdict.RecordedDeviceVerdict{
		Verdict: verdict.DeviceVerdict{TenantID: tenantID, Reason: "pcr mismatch"},
		EventID: eventID,
	})
}

func eventIDs(page Page) []string {
	ids := make([]string, 0, len(page.Verdicts))
	for _, v := range page.Verdicts {
		ids = append(ids, v.EventID)
	}
	return ids
}

func requireEvents(t *testing.T, page Page, want ...string) {
	t.Helper()
	got := eventIDs(page)
	if len(got) != len(want) {
		t.Fatalf("events = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events = %v, want %v", got, want)
		}
	}
}

func TestPollWithoutACursorFollowsFromNow(t *testing.T) {
	f := New()
	record(f, "before", "t1")

	start, err := f.Poll(context.Background(), EveryTenant(), Cursor{}, MaxWait)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(start.Verdicts) != 0 || start.Next.IsZero() {
		t.Fatalf("a poll without a cursor returns only the head: %+v", start)
	}

	record(f, "ev-1", "t1")
	record(f, "ev-2", "t2")
	page, err := f.Poll(context.Background(), EveryTenant(), start.Next, 0)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	requireEvents(t, page, "ev-1", "ev-2")

	again, err := f.Poll(context.Background(), EveryTenant(), page.Next, 0)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	requireEvents(t, again)
}

func TestPollAdmitsOnlyTheAudience(t *testing.T) {
	f := New()
	start, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	record(f, "ev-b", "tenant-b")
	record(f, "ev-platform", "")
	record(f, "ev-a", "tenant-a")

	tenant, err := f.Poll(context.Background(), Tenant("tenant-a"), start, 0)
	if err != nil {
		t.Fatalf("Poll(tenant-a): %v", err)
	}
	requireEvents(t, tenant, "ev-a")

	operator, err := f.Poll(context.Background(), Tenant(PlatformTenantID), start, 0)
	if err != nil {
		t.Fatalf("Poll(system): %v", err)
	}
	requireEvents(t, operator, "ev-b", "ev-platform", "ev-a")

	// Verdicts the audience may not see still move its cursor on.
	if tenant.Next != operator.Next {
		t.Fatalf("both cursors must reach the head: %v vs %v", tenant.Next, operator.Next)
	}
	blind, err := f.Poll(context.Background(), Tenant("tenant-c"), start, 0)
	if err != nil {
		t.Fatalf("Poll(tenant-c): %v", err)
	}
	requireEvents(t, blind)
	if blind.Next != operator.Next {
		t.Fatalf("an audience that sees nothing still advances: %v vs %v", blind.Next, operator.Next)
	}
}

func TestPollWaitsForAnAdmittedVerdict(t *testing.T) {
	f := New()
	start, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	type result struct {
		page Page
		err  error
	}
	done := make(chan result, 1)
	go func() {
		page, err := f.Poll(ctx, Tenant("tenant-a"), start, MaxWait)
		done <- result{page, err}
	}()

	// A verdict the audience may not see does not end the wait.
	record(f, "ev-b", "tenant-b")
	record(f, "ev-a", "tenant-a")

	got := <-done
	if got.err != nil {
		t.Fatalf("Poll: %v", got.err)
	}
	requireEvents(t, got.page, "ev-a")
}

func TestPollReturnsAnEmptyPageWhenTheWaitExpires(t *testing.T) {
	f := New()
	start, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	page, err := f.Poll(context.Background(), EveryTenant(), start, time.Millisecond)
	if err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if len(page.Verdicts) != 0 || page.Next != start {
		t.Fatalf("an expired wait returns no verdicts and the same cursor: %+v", page)
	}
}

func TestPollRefusesACursorThatMissedVerdicts(t *testing.T) {
	f := New(WithCapacity(2))
	start, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	record(f, "ev-1", "t1")
	record(f, "ev-2", "t1")
	if _, err := f.Poll(context.Background(), EveryTenant(), start, 0); err != nil {
		t.Fatalf("a cursor the feed still covers must poll: %v", err)
	}
	record(f, "ev-3", "t1")

	var missed ErrMissedVerdicts
	if _, err := f.Poll(context.Background(), EveryTenant(), start, 0); !errors.As(err, &missed) {
		t.Fatalf("err = %v, want ErrMissedVerdicts once ev-1 is gone", err)
	}

	// A cursor from another platformd run says nothing about this feed.
	other, err := New().Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	if _, err := f.Poll(context.Background(), EveryTenant(), other, 0); !errors.As(err, &missed) {
		t.Fatalf("err = %v, want ErrMissedVerdicts for another run's cursor", err)
	}
}

func TestPollRefusesACursorAheadOfTheFeed(t *testing.T) {
	f := New()
	head, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	ahead := Cursor{epoch: head.epoch, position: head.position + 1}
	var invalid ErrInvalidCursor
	if _, err := f.Poll(context.Background(), EveryTenant(), ahead, 0); !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want ErrInvalidCursor", err)
	}
}

func TestCloseEndsPollsAndRefusesNewOnes(t *testing.T) {
	f := New()
	start, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.Poll(context.Background(), EveryTenant(), start, MaxWait)
		done <- err
	}()
	f.Close()
	f.Close()

	var closed ErrClosed
	if err := <-done; !errors.As(err, &closed) {
		t.Fatalf("a waiting poll = %v, want ErrClosed", err)
	}
	if _, err := f.Follow(); !errors.As(err, &closed) {
		t.Fatalf("Follow after Close = %v, want ErrClosed", err)
	}
	if _, err := f.Poll(context.Background(), EveryTenant(), Cursor{}, 0); !errors.As(err, &closed) {
		t.Fatalf("Poll after Close = %v, want ErrClosed", err)
	}
}

func TestPollEndsWithItsContext(t *testing.T) {
	f := New()
	start, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.Poll(ctx, EveryTenant(), start, MaxWait); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestFollowRunsTheFollowHook(t *testing.T) {
	followed := 0
	f := New(WithOnFollow(func() { followed++ }))
	if _, err := f.Follow(); err != nil {
		t.Fatalf("Follow: %v", err)
	}
	if _, err := f.Poll(context.Background(), EveryTenant(), Cursor{}, 0); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if followed != 2 {
		t.Fatalf("hook ran %d times, want 2", followed)
	}
}

func TestCursorRoundTripsThroughItsString(t *testing.T) {
	f := New()
	record(f, "ev-1", "t1")
	head, err := f.Follow()
	if err != nil {
		t.Fatalf("Follow: %v", err)
	}
	parsed, err := ParseCursor(head.String())
	if err != nil {
		t.Fatalf("ParseCursor(%q): %v", head.String(), err)
	}
	if parsed != head {
		t.Fatalf("parsed %v, want %v", parsed, head)
	}
	empty, err := ParseCursor("")
	if err != nil || !empty.IsZero() || empty.String() != "" {
		t.Fatalf("the empty cursor follows from now: %v, %v", empty, err)
	}
}

func TestParseCursorRefusesMalformedCursors(t *testing.T) {
	for _, raw := range []string{"garbage", "1.", ".1", "x.1", "1.y", "1.2.3", "0.5"} {
		var invalid ErrInvalidCursor
		if _, err := ParseCursor(raw); !errors.As(err, &invalid) {
			t.Errorf("ParseCursor(%q) = %v, want ErrInvalidCursor", raw, err)
		}
	}
}

func TestAudience(t *testing.T) {
	tests := []struct {
		name     string
		audience Audience
		sees     []string
		blind    []string
	}{
		{name: "tenant", audience: Tenant("t1"), sees: []string{"t1"}, blind: []string{"t2", ""}},
		{name: "system tenant", audience: Tenant(PlatformTenantID), sees: []string{"t1", "t2", ""}},
		{name: "every tenant", audience: EveryTenant(), sees: []string{"t1", ""}},
		{name: "no tenant", audience: Tenant(""), blind: []string{"t1", ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, tenant := range tt.sees {
				if !tt.audience.Admits(tenant) {
					t.Errorf("must see tenant %q", tenant)
				}
			}
			for _, tenant := range tt.blind {
				if tt.audience.Admits(tenant) {
					t.Errorf("must not see tenant %q", tenant)
				}
			}
		})
	}
}

func TestClampWait(t *testing.T) {
	tests := []struct {
		in, want time.Duration
	}{
		{in: -time.Second, want: 0},
		{in: 0, want: 0},
		{in: time.Second, want: time.Second},
		{in: time.Hour, want: MaxWait},
	}
	for _, tt := range tests {
		if got := ClampWait(tt.in); got != tt.want {
			t.Errorf("ClampWait(%s) = %s, want %s", tt.in, got, tt.want)
		}
	}
}
