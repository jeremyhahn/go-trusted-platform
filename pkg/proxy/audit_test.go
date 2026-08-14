package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNoopSinkRecord(t *testing.T) {
	// The no-op sink must accept any event without side effects.
	noopSink{}.Record(context.Background(), AuditEvent{Decision: DecisionDeny})
	noopSink{}.Record(context.Background(), AuditEvent{})
}

func TestAuditEventFromRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "http://svc.example.com/api/x", nil)
	id := &ClientIdentity{ID: "c1", DeviceID: "d1", Zone: "z1", AuthMethod: "token"}
	ev := auditEvent(req, "route-1", DecisionAllow, "fine", id)
	if ev.RouteID != "route-1" || ev.Decision != DecisionAllow || ev.Reason != "fine" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Method != http.MethodPost || ev.Path != "/api/x" {
		t.Fatalf("request fields = %q %q", ev.Method, ev.Path)
	}
	if ev.RemoteAddr == "" {
		t.Error("RemoteAddr empty")
	}
	if ev.ClientID != "c1" || ev.DeviceID != "d1" || ev.Zone != "z1" || ev.AuthMethod != "token" {
		t.Fatalf("identity fields = %+v", ev)
	}
	if ev.Time.IsZero() {
		t.Error("Time not set")
	}
}

func TestAuditEventNilIdentity(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	ev := auditEvent(req, "r", DecisionDeny, "nope", nil)
	if ev.ClientID != "" || ev.DeviceID != "" || ev.Zone != "" || ev.AuthMethod != "" {
		t.Fatalf("identity fields must be empty for nil identity: %+v", ev)
	}
	if ev.Decision != DecisionDeny || ev.Reason != "nope" {
		t.Fatalf("event = %+v", ev)
	}
}
