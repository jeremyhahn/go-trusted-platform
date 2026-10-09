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
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/local"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdaemon "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/daemon"
)

// verdictRegistryService is an attestation service that hands its recorded
// verdicts to the registered verdict observers.
type verdictRegistryService struct {
	AttestationService
	observers []verdict.Observer
}

func (s *verdictRegistryService) RegisterDeviceVerdictObserver(obs verdict.Observer) {
	s.observers = append(s.observers, obs)
}

func (s *verdictRegistryService) record(recorded verdict.RecordedDeviceVerdict) {
	for _, obs := range s.observers {
		obs.OnDeviceVerdict(context.Background(), recorded)
	}
}

func subscribedVerdictDaemon(t *testing.T, attestation AttestationService) (*Daemon, chan *platformv1.Event) {
	t.Helper()
	service, err := NewService(nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	events := make(chan *platformv1.Event, 4)
	service.subMu.Lock()
	service.eventSubs["test"] = events
	service.subMu.Unlock()
	return &Daemon{service: service, config: &Config{AttestationService: attestation}, logger: discardLogger()}, events
}

func TestPublishDeviceVerdictsStreamsEveryVerdict(t *testing.T) {
	recordedAt := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		verdict  verdict.DeviceVerdict
		severity platformv1.EventSeverity
	}{
		{
			name:     "passed",
			verdict:  verdict.DeviceVerdict{DeviceID: 7, HostID: "node-7", Serial: "SN7", Passed: true},
			severity: platformv1.EventSeverity_EVENT_SEVERITY_INFO,
		},
		{
			name:     "absence of evidence",
			verdict:  verdict.DeviceVerdict{DeviceID: 7, HostID: "node-7", Serial: "SN7", Reason: "no attestation certificate enrolled"},
			severity: platformv1.EventSeverity_EVENT_SEVERITY_WARNING,
		},
		{
			name:     "cryptographic failure",
			verdict:  verdict.DeviceVerdict{DeviceID: 7, HostID: "node-7", Serial: "SN7", Cryptographic: true, Reason: "signature invalid"},
			severity: platformv1.EventSeverity_EVENT_SEVERITY_CRITICAL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestation := &verdictRegistryService{}
			daemon, events := subscribedVerdictDaemon(t, attestation)
			daemon.publishDeviceVerdicts()

			attestation.record(verdict.RecordedDeviceVerdict{Verdict: tt.verdict, EventID: "ev-1", RecordedAt: recordedAt})

			var event *platformv1.Event
			select {
			case event = <-events:
			default:
				t.Fatal("every recorded verdict must reach the event stream")
			}
			if event.Source != verdict.EventSource || event.Type != platformv1.EventType_EVENT_TYPE_ATTESTATION_VERIFIED {
				t.Fatalf("wrong source or type: %q %s", event.Source, event.Type)
			}
			if event.Severity != tt.severity {
				t.Fatalf("severity: got %s, want %s", event.Severity, tt.severity)
			}
			if event.Id != "ev-1" || !event.Timestamp.AsTime().Equal(recordedAt) {
				t.Fatalf("the event must carry the verdict's event ID and time: %q %s", event.Id, event.Timestamp.AsTime())
			}
			got, err := verdict.FromEventMetadata(event.Metadata)
			if err != nil {
				t.Fatalf("FromEventMetadata: %v", err)
			}
			if got != tt.verdict {
				t.Fatalf("round trip: got %+v, want %+v", got, tt.verdict)
			}
		})
	}
}

func TestPublishDeviceVerdictsWithoutWiring(t *testing.T) {
	// No event service, no attestation service, or one that cannot hand out
	// its verdicts: the subscription must be a no-op rather than a panic.
	(&Daemon{logger: discardLogger()}).publishDeviceVerdicts()
	(&Daemon{config: &Config{}, logger: discardLogger()}).publishDeviceVerdicts()

	attestation := &verdictRegistryService{}
	(&Daemon{config: &Config{AttestationService: attestation}, logger: discardLogger()}).publishDeviceVerdicts()
	if len(attestation.observers) != 0 {
		t.Fatal("a daemon without an event service must not subscribe")
	}

	daemon, events := subscribedVerdictDaemon(t, &recordingHostQuoteService{})
	daemon.publishDeviceVerdicts()
	select {
	case event := <-events:
		t.Fatalf("nothing may be published: %+v", event)
	default:
	}
}

// TestDeviceVerdictReachesAnSDKEventStream follows a failed verdict from the
// attestation service over gRPC to an SDK event stream, the path an overlay
// gateway follows verdicts on.
func TestDeviceVerdictReachesAnSDKEventStream(t *testing.T) {
	service, err := NewService(nil)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	subs := observeSubscriptions(service)
	attestation := &verdictRegistryService{}
	(&Daemon{service: service, config: &Config{AttestationService: attestation}, logger: discardLogger()}).publishDeviceVerdicts()

	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "d.sock"))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	server := grpc.NewServer(grpc.Creds(local.NewCredentials()))
	platformv1.RegisterPlatformDaemonServer(server, service)
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	conn, err := grpc.NewClient("unix://"+listener.Addr().String(),
		grpc.WithTransportCredentials(local.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), streamDeadline)
	defer cancel()
	stream, err := sdkdaemon.NewClientFromGRPC(platformv1.NewPlatformDaemonClient(conn)).StreamEvents(ctx, nil)
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	awaitSubscribed(t, subs, 1)

	failed := verdict.DeviceVerdict{DeviceID: 42, HostID: "node-42", Reason: "no attestation certificate enrolled"}
	attestation.record(verdict.RecordedDeviceVerdict{Verdict: failed, EventID: "ev-42", RecordedAt: time.Now()})

	event, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if event.GetSource() != verdict.EventSource || event.GetId() != "ev-42" {
		t.Fatalf("expected the device verdict event, got %q %q", event.GetSource(), event.GetId())
	}
	got, err := verdict.FromEventMetadata(event.GetMetadata())
	if err != nil {
		t.Fatalf("FromEventMetadata: %v", err)
	}
	if got != failed {
		t.Fatalf("over the wire: got %+v, want %+v", got, failed)
	}
}
