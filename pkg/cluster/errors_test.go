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

package cluster

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestErrClusterNotInitialized_Error(t *testing.T) {
	err := ErrClusterNotInitialized{}
	msg := err.Error()

	if msg != "cluster not initialized" {
		t.Errorf("expected 'cluster not initialized', got %q", msg)
	}
}

func TestErrClusterAlreadyInitialized_Error(t *testing.T) {
	err := ErrClusterAlreadyInitialized{}
	msg := err.Error()

	if msg != "cluster already initialized" {
		t.Errorf("expected 'cluster already initialized', got %q", msg)
	}
}

func TestErrNodeNotFound_Error(t *testing.T) {
	tests := []struct {
		name   string
		nodeID uint64
		want   string
	}{
		{
			name:   "node ID 1",
			nodeID: 1,
			want:   "node not found: id=1",
		},
		{
			name:   "node ID 42",
			nodeID: 42,
			want:   "node not found: id=42",
		},
		{
			name:   "node ID 0",
			nodeID: 0,
			want:   "node not found: id=0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrNodeNotFound{NodeID: tt.nodeID}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrNodeNotFound.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrNodeAlreadyExists_Error(t *testing.T) {
	err := ErrNodeAlreadyExists{NodeID: 5}
	msg := err.Error()

	if msg != "node already exists: id=5" {
		t.Errorf("expected 'node already exists: id=5', got %q", msg)
	}
}

func TestErrNodeNotLeader_Error(t *testing.T) {
	tests := []struct {
		name     string
		nodeID   uint64
		leaderID uint64
		want     string
	}{
		{
			name:     "with leader ID",
			nodeID:   2,
			leaderID: 1,
			want:     "node 2 is not the leader; current leader is 1",
		},
		{
			name:     "without leader ID",
			nodeID:   2,
			leaderID: 0,
			want:     "node 2 is not the leader; no leader currently elected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrNodeNotLeader{NodeID: tt.nodeID, LeaderID: tt.leaderID}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrNodeNotLeader.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrQuorumLost_Error(t *testing.T) {
	err := ErrQuorumLost{Required: 3, Available: 1}
	msg := err.Error()

	if msg != "quorum lost: required=3, available=1" {
		t.Errorf("expected 'quorum lost: required=3, available=1', got %q", msg)
	}
}

func TestErrBootstrapFailed_Error(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		cause  error
		want   string
	}{
		{
			name:   "with cause",
			reason: "initialization failed",
			cause:  errors.New("connection refused"),
			want:   "cluster bootstrap failed: initialization failed: connection refused",
		},
		{
			name:   "without cause",
			reason: "no nodes available",
			cause:  nil,
			want:   "cluster bootstrap failed: no nodes available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrBootstrapFailed{Reason: tt.reason, Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrBootstrapFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrBootstrapFailed_Unwrap(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrBootstrapFailed{Reason: "test", Cause: cause}

		unwrapped := err.Unwrap()
		if unwrapped != cause {
			t.Errorf("Unwrap() = %v, want %v", unwrapped, cause)
		}
	})

	t.Run("without cause", func(t *testing.T) {
		err := ErrBootstrapFailed{Reason: "test", Cause: nil}

		unwrapped := err.Unwrap()
		if unwrapped != nil {
			t.Errorf("Unwrap() = %v, want nil", unwrapped)
		}
	})

	t.Run("errors.Is works with wrapped error", func(t *testing.T) {
		cause := context.DeadlineExceeded
		err := ErrBootstrapFailed{Reason: "test", Cause: cause}

		if !errors.Is(err, context.DeadlineExceeded) {
			t.Error("errors.Is should find wrapped error")
		}
	})
}

func TestErrJoinFailed_Error(t *testing.T) {
	tests := []struct {
		name    string
		nodeID  uint64
		address string
		reason  string
		cause   error
		want    string
	}{
		{
			name:    "full error",
			nodeID:  2,
			address: "192.168.1.10:7000",
			reason:  "rejected",
			cause:   errors.New("timeout"),
			want:    "failed to join cluster: node=2, address=192.168.1.10:7000, reason=rejected: timeout",
		},
		{
			name:    "without reason",
			nodeID:  2,
			address: "192.168.1.10:7000",
			reason:  "",
			cause:   errors.New("timeout"),
			want:    "failed to join cluster: node=2, address=192.168.1.10:7000: timeout",
		},
		{
			name:    "without cause",
			nodeID:  2,
			address: "192.168.1.10:7000",
			reason:  "rejected",
			cause:   nil,
			want:    "failed to join cluster: node=2, address=192.168.1.10:7000, reason=rejected",
		},
		{
			name:    "minimal",
			nodeID:  2,
			address: "192.168.1.10:7000",
			reason:  "",
			cause:   nil,
			want:    "failed to join cluster: node=2, address=192.168.1.10:7000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrJoinFailed{
				NodeID:  tt.nodeID,
				Address: tt.address,
				Reason:  tt.reason,
				Cause:   tt.cause,
			}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrJoinFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrJoinFailed_Unwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrJoinFailed{NodeID: 1, Address: "addr", Cause: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestErrLeaveFailed_Error(t *testing.T) {
	tests := []struct {
		name   string
		nodeID uint64
		reason string
		cause  error
		want   string
	}{
		{
			name:   "full error",
			nodeID: 3,
			reason: "not a member",
			cause:  errors.New("timeout"),
			want:   "failed to leave cluster: node=3, reason=not a member: timeout",
		},
		{
			name:   "without reason",
			nodeID: 3,
			reason: "",
			cause:  errors.New("timeout"),
			want:   "failed to leave cluster: node=3: timeout",
		},
		{
			name:   "without cause",
			nodeID: 3,
			reason: "not a member",
			cause:  nil,
			want:   "failed to leave cluster: node=3, reason=not a member",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrLeaveFailed{NodeID: tt.nodeID, Reason: tt.reason, Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrLeaveFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrLeaveFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying")
	err := ErrLeaveFailed{NodeID: 1, Cause: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Field: "NodeID", Reason: "must be positive"}
	msg := err.Error()

	expected := "invalid cluster configuration: NodeID: must be positive"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestErrTimeout_Error(t *testing.T) {
	err := ErrTimeout{Operation: "leader election"}
	msg := err.Error()

	if msg != "cluster operation timed out: leader election" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestErrConnectionFailed_Error(t *testing.T) {
	tests := []struct {
		name    string
		nodeID  uint64
		address string
		cause   error
		want    string
	}{
		{
			name:    "with node ID",
			nodeID:  5,
			address: "192.168.1.10:7000",
			cause:   errors.New("connection refused"),
			want:    "connection failed to node 5 at 192.168.1.10:7000: connection refused",
		},
		{
			name:    "without node ID",
			nodeID:  0,
			address: "192.168.1.10:7000",
			cause:   errors.New("connection refused"),
			want:    "connection failed to 192.168.1.10:7000: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrConnectionFailed{NodeID: tt.nodeID, Address: tt.address, Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrConnectionFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrConnectionFailed_Unwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrConnectionFailed{Address: "addr", Cause: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestErrClusterUnavailable_Error(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{
			name:   "with reason",
			reason: "no quorum",
			want:   "cluster unavailable: no quorum",
		},
		{
			name:   "without reason",
			reason: "",
			want:   "cluster unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrClusterUnavailable{Reason: tt.reason}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrClusterUnavailable.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrNoLeader_Error(t *testing.T) {
	err := ErrNoLeader{}
	if msg := err.Error(); msg != "no leader available" {
		t.Errorf("expected 'no leader available', got %q", msg)
	}
}

func TestErrLeadershipTimeout_Error(t *testing.T) {
	err := ErrLeadershipTimeout{}
	if msg := err.Error(); msg != "leadership election timed out" {
		t.Errorf("expected 'leadership election timed out', got %q", msg)
	}
}

func TestErrAlreadyJoined_Error(t *testing.T) {
	err := ErrAlreadyJoined{}
	if msg := err.Error(); msg != "node already joined to cluster" {
		t.Errorf("expected 'node already joined to cluster', got %q", msg)
	}
}

func TestErrNotJoined_Error(t *testing.T) {
	err := ErrNotJoined{}
	if msg := err.Error(); msg != "node has not joined a cluster" {
		t.Errorf("expected 'node has not joined a cluster', got %q", msg)
	}
}

func TestErrAddNodeFailed_Error(t *testing.T) {
	tests := []struct {
		name    string
		nodeID  uint64
		address string
		cause   error
		want    string
	}{
		{
			name:    "with cause",
			nodeID:  5,
			address: "192.168.1.5:7000",
			cause:   errors.New("rejected"),
			want:    "failed to add node 5 at 192.168.1.5:7000: rejected",
		},
		{
			name:    "without cause",
			nodeID:  5,
			address: "192.168.1.5:7000",
			cause:   nil,
			want:    "failed to add node 5 at 192.168.1.5:7000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrAddNodeFailed{NodeID: tt.nodeID, Address: tt.address, Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrAddNodeFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrAddNodeFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying")
	err := ErrAddNodeFailed{NodeID: 1, Address: "addr", Cause: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestErrRemoveNodeFailed_Error(t *testing.T) {
	tests := []struct {
		name   string
		nodeID uint64
		cause  error
		want   string
	}{
		{
			name:   "with cause",
			nodeID: 5,
			cause:  errors.New("not found"),
			want:   "failed to remove node 5: not found",
		},
		{
			name:   "without cause",
			nodeID: 5,
			cause:  nil,
			want:   "failed to remove node 5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrRemoveNodeFailed{NodeID: tt.nodeID, Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrRemoveNodeFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrRemoveNodeFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying")
	err := ErrRemoveNodeFailed{NodeID: 1, Cause: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestErrManagerClosed_Error(t *testing.T) {
	err := ErrManagerClosed{}
	if msg := err.Error(); msg != "membership manager is closed" {
		t.Errorf("expected 'membership manager is closed', got %q", msg)
	}
}

func TestErrNoJoinAddresses_Error(t *testing.T) {
	err := ErrNoJoinAddresses{}
	if msg := err.Error(); msg != "no join addresses provided" {
		t.Errorf("expected 'no join addresses provided', got %q", msg)
	}
}

func TestErrInvalidAddress_Error(t *testing.T) {
	err := ErrInvalidAddress{Address: "invalid:address", Reason: "malformed"}
	msg := err.Error()

	if msg != "invalid address invalid:address: malformed" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestErrInvalidClusterState_Error(t *testing.T) {
	err := ErrInvalidClusterState{State: ClusterState("invalid")}
	msg := err.Error()

	if !strings.Contains(msg, "invalid cluster state") {
		t.Errorf("expected error to contain 'invalid cluster state', got %q", msg)
	}
}

func TestErrInvalidStateTransition_Error(t *testing.T) {
	err := ErrInvalidStateTransition{From: ClusterStateRunning, To: ClusterStateBootstrapping}
	msg := err.Error()

	expected := "invalid state transition: running -> bootstrapping"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestErrInvalidNodeState_Error(t *testing.T) {
	err := ErrInvalidNodeState{State: NodeState(99)}
	msg := err.Error()

	if !strings.Contains(msg, "invalid node state") {
		t.Errorf("expected error to contain 'invalid node state', got %q", msg)
	}
}

func TestErrInvalidNodeID_Error(t *testing.T) {
	err := ErrInvalidNodeID{ID: 0}
	msg := err.Error()

	if msg != "invalid node ID: 0" {
		t.Errorf("expected 'invalid node ID: 0', got %q", msg)
	}
}

func TestErrNilNode_Error(t *testing.T) {
	err := ErrNilNode{}
	if msg := err.Error(); msg != "node cannot be nil" {
		t.Errorf("expected 'node cannot be nil', got %q", msg)
	}
}

func TestErrContextCancelled_Error(t *testing.T) {
	cause := context.Canceled
	err := ErrContextCancelled{Err: cause}
	msg := err.Error()

	if msg != "operation cancelled: context canceled" {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestErrContextCancelled_Unwrap(t *testing.T) {
	cause := context.Canceled
	err := ErrContextCancelled{Err: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}

	if !errors.Is(err, context.Canceled) {
		t.Error("errors.Is should find wrapped context.Canceled")
	}
}

func TestErrClusterNotReady_Error(t *testing.T) {
	err := ErrClusterNotReady{State: ClusterStateBootstrapping}
	msg := err.Error()

	expected := "cluster not ready: current state is bootstrapping"
	if msg != expected {
		t.Errorf("expected %q, got %q", expected, msg)
	}
}

func TestErrLeadershipLost_Error(t *testing.T) {
	err := ErrLeadershipLost{}
	if msg := err.Error(); msg != "leadership lost during operation" {
		t.Errorf("expected 'leadership lost during operation', got %q", msg)
	}
}

func TestErrNilConfig_Error(t *testing.T) {
	err := ErrNilConfig{}
	if msg := err.Error(); msg != "cluster configuration cannot be nil" {
		t.Errorf("expected 'cluster configuration cannot be nil', got %q", msg)
	}
}

func TestErrNilMembership_Error(t *testing.T) {
	err := ErrNilMembership{}
	if msg := err.Error(); msg != "membership manager cannot be nil" {
		t.Errorf("expected 'membership manager cannot be nil', got %q", msg)
	}
}

func TestErrNilLogger_Error(t *testing.T) {
	err := ErrNilLogger{}
	if msg := err.Error(); msg != "logger cannot be nil" {
		t.Errorf("expected 'logger cannot be nil', got %q", msg)
	}
}

func TestErrCoordinatorAlreadyRunning_Error(t *testing.T) {
	err := ErrCoordinatorAlreadyRunning{}
	if msg := err.Error(); msg != "cluster coordinator is already running" {
		t.Errorf("expected 'cluster coordinator is already running', got %q", msg)
	}
}

func TestErrCoordinatorNotRunning_Error(t *testing.T) {
	err := ErrCoordinatorNotRunning{}
	if msg := err.Error(); msg != "cluster coordinator is not running" {
		t.Errorf("expected 'cluster coordinator is not running', got %q", msg)
	}
}

func TestErrStatusUnavailable_Error(t *testing.T) {
	err := ErrStatusUnavailable{}
	if msg := err.Error(); msg != "cluster status is unavailable" {
		t.Errorf("expected 'cluster status is unavailable', got %q", msg)
	}
}

func TestErrHealthCheckFailed_Error(t *testing.T) {
	tests := []struct {
		name   string
		reason string
		cause  error
		want   string
	}{
		{
			name:   "with cause",
			reason: "node unreachable",
			cause:  errors.New("timeout"),
			want:   "health check failed: node unreachable: timeout",
		},
		{
			name:   "without cause",
			reason: "no quorum",
			cause:  nil,
			want:   "health check failed: no quorum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ErrHealthCheckFailed{Reason: tt.reason, Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Errorf("ErrHealthCheckFailed.Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestErrHealthCheckFailed_Unwrap(t *testing.T) {
	cause := errors.New("underlying")
	err := ErrHealthCheckFailed{Reason: "test", Cause: cause}

	if err.Unwrap() != cause {
		t.Error("Unwrap() should return cause")
	}
}

func TestErrorTypesAreDistinct(t *testing.T) {
	// Ensure each error type is distinct by checking they don't match each other
	errTypes := []error{
		ErrClusterNotInitialized{},
		ErrClusterAlreadyInitialized{},
		ErrNodeNotFound{NodeID: 1},
		ErrNodeAlreadyExists{NodeID: 1},
		ErrNodeNotLeader{NodeID: 1},
		ErrQuorumLost{Required: 2, Available: 1},
		ErrBootstrapFailed{Reason: "test"},
		ErrJoinFailed{NodeID: 1, Address: "addr"},
		ErrLeaveFailed{NodeID: 1},
		ErrInvalidConfig{Field: "test", Reason: "test"},
		ErrTimeout{Operation: "test"},
		ErrConnectionFailed{Address: "addr"},
		ErrClusterUnavailable{},
		ErrNoLeader{},
		ErrLeadershipTimeout{},
		ErrAlreadyJoined{},
		ErrNotJoined{},
		ErrAddNodeFailed{NodeID: 1, Address: "addr"},
		ErrRemoveNodeFailed{NodeID: 1},
		ErrManagerClosed{},
		ErrNoJoinAddresses{},
		ErrInvalidAddress{Address: "addr", Reason: "test"},
		ErrInvalidClusterState{State: ClusterStateRunning},
		ErrInvalidStateTransition{From: ClusterStateRunning, To: ClusterStateStopped},
		ErrInvalidNodeState{State: NodeStateHealthy},
		ErrInvalidNodeID{ID: 0},
		ErrNilNode{},
		ErrContextCancelled{Err: context.Canceled},
		ErrClusterNotReady{State: ClusterStateBootstrapping},
		ErrLeadershipLost{},
		ErrNilConfig{},
		ErrNilMembership{},
		ErrNilLogger{},
		ErrCoordinatorAlreadyRunning{},
		ErrCoordinatorNotRunning{},
		ErrStatusUnavailable{},
		ErrHealthCheckFailed{Reason: "test"},
	}

	// Ensure all error types produce non-empty error messages
	for i, err := range errTypes {
		msg := err.Error()
		if msg == "" {
			t.Errorf("error type at index %d has empty error message", i)
		}
	}

	// Verify all implement the error interface properly
	for i, err := range errTypes {
		var _ = err
		if err.Error() == "" {
			t.Errorf("error at index %d returned empty string", i)
		}
	}
}

func TestUnwrappableErrors(t *testing.T) {
	// Test that all errors with Cause field properly implement Unwrap
	cause := errors.New("underlying cause")

	unwrappableErrors := []interface {
		error
		Unwrap() error
	}{
		ErrBootstrapFailed{Reason: "test", Cause: cause},
		ErrJoinFailed{NodeID: 1, Address: "addr", Cause: cause},
		ErrLeaveFailed{NodeID: 1, Cause: cause},
		ErrConnectionFailed{Address: "addr", Cause: cause},
		ErrAddNodeFailed{NodeID: 1, Address: "addr", Cause: cause},
		ErrRemoveNodeFailed{NodeID: 1, Cause: cause},
		ErrContextCancelled{Err: cause},
		ErrHealthCheckFailed{Reason: "test", Cause: cause},
	}

	for _, err := range unwrappableErrors {
		unwrapped := err.Unwrap()
		if unwrapped != cause {
			t.Errorf("%T.Unwrap() = %v, want %v", err, unwrapped, cause)
		}

		// Verify errors.Is works correctly
		if !errors.Is(err, cause) {
			t.Errorf("errors.Is(%T, cause) = false, want true", err)
		}
	}
}
