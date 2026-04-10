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

//go:build !cluster

package daemon

import (
	"context"
	"testing"
)

func TestNewClusterService_Stub(t *testing.T) {
	t.Run("returns error when cluster not enabled", func(t *testing.T) {
		svc, err := NewClusterService(nil, nil)

		if err == nil {
			t.Fatal("expected error when cluster not enabled")
		}

		if svc != nil {
			t.Error("expected nil service when error returned")
		}

		// Verify error type
		errInvalid, ok := err.(ErrInvalidConfig)
		if !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}

		if errInvalid.Reason != "cluster service not enabled (build with -tags cluster)" {
			t.Errorf("unexpected error reason: %s", errInvalid.Reason)
		}
	})
}

func TestClusterService_StubMethods(t *testing.T) {
	// Create a nil service to test methods
	var svc *ClusterService

	ctx := context.Background()

	t.Run("RegisterServices returns error", func(t *testing.T) {
		if svc != nil {
			err := svc.RegisterGRPCServices(nil)
			if err == nil {
				t.Error("expected error from RegisterServices")
			}
		}
	})

	t.Run("Start returns nil", func(t *testing.T) {
		if svc != nil {
			err := svc.Start(ctx)
			if err != nil {
				t.Errorf("unexpected error from Start: %v", err)
			}
		}
	})

	t.Run("Stop returns nil", func(t *testing.T) {
		if svc != nil {
			err := svc.Stop(ctx)
			if err != nil {
				t.Errorf("unexpected error from Stop: %v", err)
			}
		}
	})

	t.Run("IsRunning returns false", func(t *testing.T) {
		if svc != nil {
			if svc.IsRunning() {
				t.Error("expected IsRunning to return false")
			}
		}
	})

	t.Run("Name returns cluster", func(t *testing.T) {
		if svc != nil {
			if svc.Name() != "cluster" {
				t.Errorf("expected name 'cluster', got %s", svc.Name())
			}
		}
	})

	t.Run("Bootstrap returns error", func(t *testing.T) {
		if svc != nil {
			err := svc.Bootstrap(ctx)
			if err == nil {
				t.Error("expected error from Bootstrap")
			}
		}
	})

	t.Run("Join returns error", func(t *testing.T) {
		if svc != nil {
			err := svc.Join(ctx, []string{"127.0.0.1:8080"})
			if err == nil {
				t.Error("expected error from Join")
			}
		}
	})

	t.Run("Leave returns error", func(t *testing.T) {
		if svc != nil {
			err := svc.Leave(ctx)
			if err == nil {
				t.Error("expected error from Leave")
			}
		}
	})

	t.Run("Status returns error", func(t *testing.T) {
		if svc != nil {
			_, err := svc.Status(ctx)
			if err == nil {
				t.Error("expected error from Status")
			}
		}
	})

	t.Run("Nodes returns error", func(t *testing.T) {
		if svc != nil {
			_, err := svc.Nodes(ctx)
			if err == nil {
				t.Error("expected error from Nodes")
			}
		}
	})

	t.Run("IsLeader returns false", func(t *testing.T) {
		if svc != nil {
			if svc.IsLeader() {
				t.Error("expected IsLeader to return false")
			}
		}
	})

	t.Run("GetLeader returns error", func(t *testing.T) {
		if svc != nil {
			_, err := svc.GetLeader(ctx)
			if err == nil {
				t.Error("expected error from GetLeader")
			}
		}
	})

	t.Run("WaitForLeader returns error", func(t *testing.T) {
		if svc != nil {
			_, err := svc.WaitForLeader(ctx)
			if err == nil {
				t.Error("expected error from WaitForLeader")
			}
		}
	})

	t.Run("IsHealthy returns false", func(t *testing.T) {
		if svc != nil {
			if svc.IsHealthy() {
				t.Error("expected IsHealthy to return false")
			}
		}
	})

	t.Run("HealthCheck returns error", func(t *testing.T) {
		if svc != nil {
			err := svc.HealthCheck(ctx)
			if err == nil {
				t.Error("expected error from HealthCheck")
			}
		}
	})

	t.Run("NodeID returns 0", func(t *testing.T) {
		if svc != nil {
			if svc.NodeID() != 0 {
				t.Errorf("expected NodeID 0, got %d", svc.NodeID())
			}
		}
	})

	t.Run("Config returns nil", func(t *testing.T) {
		if svc != nil {
			if svc.Config() != nil {
				t.Error("expected Config to return nil")
			}
		}
	})

	t.Run("Coordinator returns nil", func(t *testing.T) {
		if svc != nil {
			if svc.Coordinator() != nil {
				t.Error("expected Coordinator to return nil")
			}
		}
	})
}

func TestClusterServiceStub_AllMethods(t *testing.T) {
	// Test all stub methods with a zero-value struct
	svc := &ClusterService{}
	ctx := context.Background()

	t.Run("RegisterServices", func(t *testing.T) {
		err := svc.RegisterGRPCServices(nil)
		if err == nil {
			t.Error("expected error")
		}
		if _, ok := err.(ErrInvalidConfig); !ok {
			t.Errorf("expected ErrInvalidConfig, got %T", err)
		}
	})

	t.Run("Start", func(t *testing.T) {
		err := svc.Start(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("Stop", func(t *testing.T) {
		err := svc.Stop(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("IsRunning", func(t *testing.T) {
		if svc.IsRunning() {
			t.Error("expected false")
		}
	})

	t.Run("Name", func(t *testing.T) {
		name := svc.Name()
		if name != "cluster" {
			t.Errorf("expected 'cluster', got %s", name)
		}
	})

	t.Run("Bootstrap", func(t *testing.T) {
		err := svc.Bootstrap(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Join", func(t *testing.T) {
		err := svc.Join(ctx, []string{"addr1"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Leave", func(t *testing.T) {
		err := svc.Leave(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("Status", func(t *testing.T) {
		status, err := svc.Status(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if status != nil {
			t.Error("expected nil status")
		}
	})

	t.Run("Nodes", func(t *testing.T) {
		nodes, err := svc.Nodes(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if nodes != nil {
			t.Error("expected nil nodes")
		}
	})

	t.Run("IsLeader", func(t *testing.T) {
		if svc.IsLeader() {
			t.Error("expected false")
		}
	})

	t.Run("GetLeader", func(t *testing.T) {
		leader, err := svc.GetLeader(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if leader != nil {
			t.Error("expected nil leader")
		}
	})

	t.Run("WaitForLeader", func(t *testing.T) {
		leader, err := svc.WaitForLeader(ctx)
		if err == nil {
			t.Error("expected error")
		}
		if leader != nil {
			t.Error("expected nil leader")
		}
	})

	t.Run("IsHealthy", func(t *testing.T) {
		if svc.IsHealthy() {
			t.Error("expected false")
		}
	})

	t.Run("HealthCheck", func(t *testing.T) {
		err := svc.HealthCheck(ctx)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("NodeID", func(t *testing.T) {
		if svc.NodeID() != 0 {
			t.Errorf("expected 0, got %d", svc.NodeID())
		}
	})

	t.Run("Config", func(t *testing.T) {
		if svc.Config() != nil {
			t.Error("expected nil")
		}
	})

	t.Run("Coordinator", func(t *testing.T) {
		if svc.Coordinator() != nil {
			t.Error("expected nil")
		}
	})
}
