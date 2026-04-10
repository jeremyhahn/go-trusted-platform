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
	"errors"
	"testing"
)

func TestErrMissingNodeID_Error(t *testing.T) {
	err := ErrMissingNodeID{}
	expected := "node ID is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingListenAddr_Error(t *testing.T) {
	err := ErrMissingListenAddr{}
	expected := "listen address is required"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrMissingJoinAddrs_Error(t *testing.T) {
	err := ErrMissingJoinAddrs{}
	expected := "join addresses are required (comma-separated list)"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidListenAddr_Error(t *testing.T) {
	err := ErrInvalidListenAddr{Addr: "invalid", Reason: "missing port"}
	expected := `invalid listen address "invalid": missing port`
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidJoinAddr_Error(t *testing.T) {
	err := ErrInvalidJoinAddr{Addr: "badaddr", Reason: "invalid format"}
	expected := `invalid join address "badaddr": invalid format`
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterBootstrapFailed_Error(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrClusterBootstrapFailed{Err: cause}
	expected := "failed to bootstrap cluster: connection refused"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterBootstrapFailed_Unwrap(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrClusterBootstrapFailed{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return the underlying error")
	}
}

func TestErrClusterJoinFailed_Error(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrClusterJoinFailed{Err: cause}
	expected := "failed to join cluster: timeout"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterJoinFailed_Unwrap(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrClusterJoinFailed{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return the underlying error")
	}
}

func TestErrClusterLeaveFailed_Error(t *testing.T) {
	cause := errors.New("not in cluster")
	err := ErrClusterLeaveFailed{Err: cause}
	expected := "failed to leave cluster: not in cluster"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterLeaveFailed_Unwrap(t *testing.T) {
	cause := errors.New("not in cluster")
	err := ErrClusterLeaveFailed{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return the underlying error")
	}
}

func TestErrClusterStatusFailed_Error(t *testing.T) {
	cause := errors.New("unavailable")
	err := ErrClusterStatusFailed{Err: cause}
	expected := "failed to get cluster status: unavailable"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterStatusFailed_Unwrap(t *testing.T) {
	cause := errors.New("unavailable")
	err := ErrClusterStatusFailed{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return the underlying error")
	}
}

func TestErrClusterNodesFailed_Error(t *testing.T) {
	cause := errors.New("rpc error")
	err := ErrClusterNodesFailed{Err: cause}
	expected := "failed to list cluster nodes: rpc error"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterNodesFailed_Unwrap(t *testing.T) {
	cause := errors.New("rpc error")
	err := ErrClusterNodesFailed{Err: cause}
	if !errors.Is(err, cause) {
		t.Error("expected Unwrap to return the underlying error")
	}
}

func TestErrClusterNotBootstrapped_Error(t *testing.T) {
	err := ErrClusterNotBootstrapped{}
	expected := "cluster is not bootstrapped"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrNodeNotInCluster_Error(t *testing.T) {
	err := ErrNodeNotInCluster{}
	expected := "node is not part of a cluster"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrNodeAlreadyInCluster_Error(t *testing.T) {
	err := ErrNodeAlreadyInCluster{NodeID: "node-1"}
	expected := `node "node-1" is already part of a cluster`
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrClusterClientNotInitialized_Error(t *testing.T) {
	err := ErrClusterClientNotInitialized{}
	expected := "cluster client not initialized"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrInvalidDataDir_Error(t *testing.T) {
	err := ErrInvalidDataDir{Path: "/bad/path", Reason: "does not exist"}
	expected := `invalid data directory "/bad/path": does not exist`
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}
