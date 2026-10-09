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

package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
)

func recordedFor(tenant, event string) verdict.RecordedDeviceVerdict {
	return verdict.RecordedDeviceVerdict{
		EventID: event,
		Verdict: verdict.DeviceVerdict{DeviceID: 1, TenantID: tenant},
	}
}

// TestResolveVerdictAudience pins the round-3 rules for every transport.
func TestResolveVerdictAudience(t *testing.T) {
	tests := []struct {
		name      string
		principal verdict.StreamPrincipal
		forbidden bool
		sees      []string
		blind     []string
	}{
		{name: "tenant", principal: verdict.StreamPrincipal{TenantID: "t1"}, sees: []string{"t1"}, blind: []string{"t2", ""}},
		{name: "certificate of a tenant", principal: verdict.StreamPrincipal{TenantID: "t1", HasCertificate: true}, sees: []string{"t1"}, blind: []string{"t2"}},
		{name: "system tenant sees every tenant", principal: verdict.StreamPrincipal{TenantID: "system"}, sees: []string{"t1", "t2", ""}},
		{name: "certificate without a tenant", principal: verdict.StreamPrincipal{HasCertificate: true}, forbidden: true},
		{name: "unix peer sees every tenant", principal: verdict.StreamPrincipal{UnixPeer: true}, sees: []string{"t1", ""}},
		{name: "no credential", principal: verdict.StreamPrincipal{}, forbidden: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			audience, err := resolveVerdictAudience(tt.principal)
			if tt.forbidden {
				var forbidden ErrVerdictStreamForbidden
				if !errors.As(err, &forbidden) {
					t.Fatalf("err = %v, want ErrVerdictStreamForbidden", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveVerdictAudience: %v", err)
			}
			for _, tenant := range tt.sees {
				if !audience.admits(tenant) {
					t.Errorf("must see tenant %q", tenant)
				}
			}
			for _, tenant := range tt.blind {
				if audience.admits(tenant) {
					t.Errorf("must not see tenant %q", tenant)
				}
			}
		})
	}
}

// TestOpenStreamDeliversOnlyTheAudience follows as one tenant and receives
// only that tenant's verdicts, in order.
func TestOpenStreamDeliversOnlyTheAudience(t *testing.T) {
	hub := newDeviceVerdictHub()
	defer hub.Close()
	subscription, err := hub.OpenVerdictStream(verdict.StreamPrincipal{TenantID: "t1"})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer subscription.Close()

	hub.OnDeviceVerdict(context.Background(), recordedFor("t2", "other"))
	hub.OnDeviceVerdict(context.Background(), recordedFor("t1", "mine"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 2)
	done := make(chan error, 1)
	go func() {
		done <- subscription.Serve(ctx, func(r verdict.RecordedDeviceVerdict) error {
			got <- r.EventID
			cancel()
			return nil
		}, verdict.StreamHeartbeat{})
	}()
	if event := <-got; event != "mine" {
		t.Fatalf("first verdict = %q, want mine", event)
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve = %v, want context.Canceled", err)
	}
}

func TestOpenStreamRefusesAnUnauthorisedPrincipal(t *testing.T) {
	hub := newDeviceVerdictHub()
	defer hub.Close()
	if _, err := hub.OpenVerdictStream(verdict.StreamPrincipal{HasCertificate: true}); !errors.As(err, new(ErrVerdictStreamForbidden)) {
		t.Fatalf("err = %v, want ErrVerdictStreamForbidden", err)
	}
	if len(hub.subs) != 0 {
		t.Fatal("a refused principal must not leave a subscription behind")
	}
}

func TestOpenStreamOnAClosedHub(t *testing.T) {
	hub := newDeviceVerdictHub()
	hub.Close()
	if _, err := hub.OpenVerdictStream(verdict.StreamPrincipal{UnixPeer: true}); !errors.As(err, new(ErrVerdictStreamClosed)) {
		t.Fatalf("err = %v, want ErrVerdictStreamClosed", err)
	}
}

func TestServeHeartbeatsWhileIdleAndStopsOnClose(t *testing.T) {
	hub := newDeviceVerdictHub()
	subscription, err := hub.OpenVerdictStream(verdict.StreamPrincipal{UnixPeer: true})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer subscription.Close()

	beats := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- subscription.Serve(context.Background(), func(verdict.RecordedDeviceVerdict) error { return nil },
			verdict.StreamHeartbeat{Every: time.Millisecond, Beat: func() error {
				select {
				case beats <- struct{}{}:
				default:
				}
				return nil
			}})
	}()
	<-beats
	hub.Close()
	if err := <-done; !errors.As(err, new(ErrVerdictStreamClosed)) {
		t.Fatalf("Serve = %v, want ErrVerdictStreamClosed", err)
	}
}

func TestServeStopsWhenAHeartbeatFails(t *testing.T) {
	hub := newDeviceVerdictHub()
	defer hub.Close()
	subscription, err := hub.OpenVerdictStream(verdict.StreamPrincipal{UnixPeer: true})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer subscription.Close()
	broken := errors.New("connection gone")
	err = subscription.Serve(context.Background(), func(verdict.RecordedDeviceVerdict) error { return nil },
		verdict.StreamHeartbeat{Every: time.Millisecond, Beat: func() error { return broken }})
	if !errors.Is(err, broken) {
		t.Fatalf("Serve = %v, want the heartbeat error", err)
	}
}

func TestServeEndsASubscriberThatFellBehind(t *testing.T) {
	hub := newDeviceVerdictHub()
	defer hub.Close()
	subscription, err := hub.OpenVerdictStream(verdict.StreamPrincipal{UnixPeer: true})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer subscription.Close()
	for i := 0; i <= verdictSubscriberBuffer; i++ {
		hub.OnDeviceVerdict(context.Background(), recordedFor("t1", "e"))
	}
	err = subscription.Serve(context.Background(), func(verdict.RecordedDeviceVerdict) error { return nil }, verdict.StreamHeartbeat{})
	if !errors.As(err, new(ErrVerdictSubscriberBehind)) {
		t.Fatalf("Serve = %v, want ErrVerdictSubscriberBehind", err)
	}
}

func TestOpenVerdictStreamWithoutAHub(t *testing.T) {
	var nilServer *AttestationServiceServer
	if _, err := nilServer.OpenVerdictStream(verdict.StreamPrincipal{UnixPeer: true}); !errors.As(err, new(ErrVerdictStreamUnavailable)) {
		t.Fatalf("nil server: err = %v", err)
	}
	server := NewAttestationServiceServer(&recordingHostQuoteService{}, discardLogger().Slog())
	if _, err := server.OpenVerdictStream(verdict.StreamPrincipal{UnixPeer: true}); !errors.As(err, new(ErrVerdictStreamUnavailable)) {
		t.Fatalf("no hub: err = %v", err)
	}
}
