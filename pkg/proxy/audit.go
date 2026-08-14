package proxy

import (
	"context"
	"net/http"
	"time"
)

// Audit decision values recorded in AuditEvent.Decision.
const (
	// DecisionAllow records a request that passed authentication.
	DecisionAllow = "allow"
	// DecisionDeny records a request denied by the auth chain.
	DecisionDeny = "deny"
	// DecisionError records an authentication or backend failure.
	DecisionError = "error"
	// DecisionNoRoute records a request that matched no route.
	DecisionNoRoute = "no-route"
)

// AuditEvent describes one routing/authentication decision.
type AuditEvent struct {
	Time       time.Time
	RouteID    string
	ClientID   string
	DeviceID   string
	Zone       string
	Decision   string
	Reason     string
	AuthMethod string
	RemoteAddr string
	Method     string
	Path       string
}

// noopSink discards audit events. It is installed when no AuditSink is
// injected.
type noopSink struct{}

// Record implements AuditSink by discarding the event.
func (noopSink) Record(context.Context, AuditEvent) {}

var _ AuditSink = noopSink{}

// auditEvent builds an AuditEvent for the request, filling identity fields
// when an authenticated identity is available.
func auditEvent(r *http.Request, routeID, decision, reason string, id *ClientIdentity) AuditEvent {
	ev := AuditEvent{
		Time:       time.Now(),
		RouteID:    routeID,
		Decision:   decision,
		Reason:     reason,
		RemoteAddr: r.RemoteAddr,
		Method:     r.Method,
		Path:       r.URL.Path,
	}
	if id != nil {
		ev.ClientID = id.ID
		ev.DeviceID = id.DeviceID
		ev.Zone = id.Zone
		ev.AuthMethod = id.AuthMethod
	}
	return ev
}
