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

package daemon

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ntp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NTPBackend is the time-synchronization capability the API layers consume.
// *ntp.Service implements it; the daemon holds the interface so the REST,
// gRPC, QUIC, MCP, and Unix transports all share one instance and therefore
// one view of the clock.
type NTPBackend interface {
	// Status returns the node's current synchronization state.
	Status(ctx context.Context) (*ntp.Status, error)

	// Sources returns the configured time sources and their live state.
	Sources(ctx context.Context) ([]ntp.Source, error)

	// Step forces an immediate clock correction and returns the resulting
	// state.
	Step(ctx context.Context) (*ntp.Status, error)
}

// Ensure the platform time service satisfies the backend contract.
var _ NTPBackend = (*ntp.Service)(nil)

// ErrNTPNotConfigured is returned by every transport when the node has no
// `ntp:` configuration section, which per the platform's explicit-config
// convention means platformd deliberately does not manage time here.
type ErrNTPNotConfigured struct{}

// Error implements the error interface.
func (ErrNTPNotConfigured) Error() string {
	return "ntp service is not configured on this node"
}

// ntpStatusToPb projects the domain status onto the platform.v1 message.
func ntpStatusToPb(s *ntp.Status) *platformv1.NTPStatus {
	if s == nil {
		return nil
	}
	var lastSync int64
	if !s.LastSync.IsZero() {
		lastSync = s.LastSync.Unix()
	}
	return &platformv1.NTPStatus{
		Synced:           s.Synced,
		Stratum:          s.Stratum,
		LeapStatus:       s.LeapStatus,
		OffsetSeconds:    s.OffsetSeconds,
		RootDispersion:   s.RootDispersion,
		RootDelay:        s.RootDelay,
		LastSyncUnix:     lastSync,
		Mode:             s.Mode,
		ReferenceId:      s.ReferenceID,
		ReferenceName:    s.ReferenceName,
		SourcesReachable: s.SourcesReachable,
		SourcesTotal:     s.SourcesTotal,
		Anomaly:          s.Anomaly,
		AnomalyReason:    s.AnomalyReason,
		// Carried on every transport, not just the health component: an
		// operator reading `platformctl ntp status` on a control plane
		// must see that it is advertising a time service it refuses,
		// without knowing to look at health first (#509).
		ServeNameFindings: ntpServeNameFindingsToPb(s.ServeNameFindings),
	}
}

// ntpServeNameFindingsToPb projects the advertised-name mismatches. An empty
// slice stays nil so the field is simply absent on a correctly configured
// node rather than an empty list a consumer has to interpret.
func ntpServeNameFindingsToPb(findings []ntp.ServeNameFinding) []*platformv1.NTSServeNameFinding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]*platformv1.NTSServeNameFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, &platformv1.NTSServeNameFinding{
			// Kind is the marker monitoring keys on, and the two kinds
			// are different claims: an address this node refuses, versus
			// a name that did not resolve here at all.
			Kind:           string(f.Kind),
			Name:           f.Name,
			Address:        f.Address,
			ListenNetworks: append([]string(nil), f.ListenNetworks...),
			Error:          f.Error,
		})
	}
	return out
}

// ntpSourcesToPb projects the domain sources onto platform.v1 messages.
func ntpSourcesToPb(sources []ntp.Source) []*platformv1.NTPSource {
	out := make([]*platformv1.NTPSource, 0, len(sources))
	for i := range sources {
		out = append(out, &platformv1.NTPSource{
			Address:       sources[i].Address,
			Mode:          string(sources[i].Mode),
			State:         string(sources[i].State),
			Stratum:       sources[i].Stratum,
			PollSeconds:   sources[i].PollSeconds,
			Reach:         sources[i].Reach,
			LastRxSeconds: sources[i].LastRxSeconds,
			OffsetSeconds: sources[i].OffsetSeconds,
			Reachable:     sources[i].Reachable,
		})
	}
	return out
}

// ntpErrToGRPC maps the domain's typed errors onto gRPC status codes. The
// same mapping backs the REST status codes and the QUIC wire statuses, so a
// caller sees the same class of failure on every transport.
func ntpErrToGRPC(err error) error {
	if err == nil {
		return nil
	}

	var (
		noSource    ntp.ErrNoReachableSource
		refused     ntp.ErrStepRefused
		unavailable ntp.ErrControlUnavailable
		malformed   ntp.ErrMalformedControlOutput
		timeout     ntp.ErrSyncTimeout
	)

	switch {
	case errors.Is(err, ntp.ErrDisabled{}), errors.Is(err, ErrNTPNotConfigured{}):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &noSource):
		// The operator asked for a step but there is nothing to step
		// towards. Aborted is the code protorest maps to 409 Conflict,
		// which is the documented REST contract for this condition.
		return status.Error(codes.Aborted, err.Error())
	case errors.As(err, &refused):
		// chronyd answered but does not control the clock, so the step
		// conflicts with how it runs: the same 409 as a step with no source.
		return status.Error(codes.Aborted, err.Error())
	case errors.As(err, &unavailable):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &malformed):
		return status.Error(codes.Internal, err.Error())
	case errors.As(err, &timeout):
		return status.Error(codes.DeadlineExceeded, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
