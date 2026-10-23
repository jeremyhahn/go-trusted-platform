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
	"sync"
	"testing"
	"time"
)

func TestDaemon_SDNService(t *testing.T) {
	// SDNService always returns a non-nil stub so that zone CRUD RPCs
	// (which have no OVS dependency) are served even without an OVS socket.
	// OVS-dependent operations check ovsClient != nil internally.
	t.Run("returns stub when OVS socket not configured", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-sdn.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		svc := d.SDNService()
		if svc == nil {
			t.Error("SDNService() must return a non-nil stub so zone RPCs are served")
		}
		// OVS client must be nil when no socket path was configured.
		if svc.OVSClient() != nil {
			t.Error("SDNService().OVSClient() must be nil when OVSSocketPath is empty")
		}
	})
}

func TestDaemon_KMSService(t *testing.T) {
	t.Run("returns nil when KMS not configured", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-kms.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		svc := d.KMSService()
		if svc != nil {
			t.Error("KMSService() should return nil when not configured")
		}
	})
}

func TestDaemon_IAMService(t *testing.T) {
	t.Run("returns nil when IAM not configured", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-iam.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		svc := d.IAMService()
		if svc != nil {
			t.Error("IAMService() should return nil when not configured")
		}
	})
}

func TestDaemon_TenantService(t *testing.T) {
	t.Run("returns nil when tenant not configured", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-tenant.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		svc := d.TenantService()
		if svc != nil {
			t.Error("TenantService() should return nil when not configured")
		}
	})
}

func TestDaemon_VTPMServiceServer(t *testing.T) {
	t.Run("returns nil when vTPM not configured", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-vtpm.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		svc := d.VTPMServiceServer()
		if svc != nil {
			t.Error("VTPMServiceServer() should return nil when not configured")
		}
	})
}

func TestDaemon_DeviceGRPCService(t *testing.T) {
	t.Run("returns nil when device not configured", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-device.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		svc := d.DeviceGRPCService()
		if svc != nil {
			t.Error("DeviceGRPCService() should return nil when not configured")
		}
	})
}

func TestDaemon_SetDeviceGRPCService(t *testing.T) {
	t.Run("sets device gRPC service", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-set-device.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		// Create a mock device service
		deviceSvc := &DeviceGRPCService{}

		d.SetDeviceGRPCService(deviceSvc)

		if d.DeviceGRPCService() != deviceSvc {
			t.Error("SetDeviceGRPCService() did not set the service correctly")
		}
	})

	t.Run("can set to nil", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-set-device-nil.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		d.SetDeviceGRPCService(nil)

		if d.DeviceGRPCService() != nil {
			t.Error("SetDeviceGRPCService(nil) should set to nil")
		}
	})
}

func TestDaemon_GRPCListenAddr(t *testing.T) {
	t.Run("returns configured address", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-grpc-addr.sock")
		config.GRPCListenAddr = "127.0.0.1:10443"

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		addr := d.GRPCListenAddr()
		if addr != "127.0.0.1:10443" {
			t.Errorf("GRPCListenAddr() = %q, want %q", addr, "127.0.0.1:10443")
		}
	})
}

func TestDaemon_GRPCServer(t *testing.T) {
	t.Run("returns nil when gRPC TCP disabled", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-grpc-server.sock")
		config.EnableGRPCTCP = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		server := d.GRPCServer()
		if server != nil {
			t.Error("GRPCServer() should return nil when gRPC TCP disabled")
		}
	})
}

func TestDaemon_IsGRPCTCPEnabled(t *testing.T) {
	t.Run("returns false when gRPC TCP disabled", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-grpc-enabled.sock")
		config.EnableGRPCTCP = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		if d.IsGRPCTCPEnabled() {
			t.Error("IsGRPCTCPEnabled() should return false when disabled")
		}
	})
}

func TestDaemon_registerHealthCheckers(t *testing.T) {
	t.Run("handles nil health registry", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-health-reg.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		// Set registry to nil
		d.healthRegistry = nil

		// This should not panic
		d.registerHealthCheckers()
	})
}

func TestDaemon_StartWithServiceStartErrors(t *testing.T) {
	t.Run("continues despite SDN service error", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-sdn-error.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		ctx := context.Background()

		// Start should succeed even without SDN
		err = d.Start(ctx)
		if err != nil {
			t.Errorf("Start() error: %v", err)
		}

		if !d.IsRunning() {
			t.Error("daemon should be running")
		}

		_ = d.Stop(ctx)
	})
}

func TestDaemon_StopWithNilServices(t *testing.T) {
	t.Run("handles nil services gracefully", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-stop-nil.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		// Ensure all optional services are nil
		d.sdnService = nil
		d.kmsService = nil
		d.iamService = nil
		d.tenantService = nil

		ctx := context.Background()

		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Stop should not panic with nil services
		err = d.Stop(ctx)
		if err != nil {
			t.Errorf("Stop() error: %v", err)
		}
	})
}

func TestDaemon_ForceStopWithNilServices(t *testing.T) {
	t.Run("handles nil services gracefully", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-force-nil.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		// Ensure all optional services are nil
		d.sdnService = nil
		d.kmsService = nil
		d.iamService = nil
		d.tenantService = nil

		ctx := context.Background()

		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// ForceStop should not panic with nil services
		err = d.ForceStop()
		if err != nil {
			t.Errorf("ForceStop() unexpected error: %v", err)
		}
	})
}

func TestDaemon_StopWithNilGRPCServer(t *testing.T) {
	t.Run("handles nil gRPC server gracefully", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-stop-grpc-nil.sock")
		config.EnableGRPCTCP = false

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		ctx := context.Background()

		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Verify gRPC server is nil
		if d.grpcServer != nil {
			t.Error("gRPC server should be nil when gRPC TCP is disabled")
		}

		// Stop should not panic with nil gRPC server
		err = d.Stop(ctx)
		if err != nil {
			t.Errorf("Stop() error: %v", err)
		}
	})
}

func TestDaemon_autoStartServicesWithDisabledService(t *testing.T) {
	t.Run("skips disabled services", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-autostart-disabled.sock")

		// Add a disabled service config
		config.Services["disabled-test"] = ServiceConfig{
			Enabled:    false,
			AutoStart:  true,
			Timeout:    5 * time.Second,
			MaxRetries: 3,
		}

		// autoStarted closes once the auto-start pass has completed, which is
		// what makes the zero-count assertion below meaningful.
		autoStarted := make(chan struct{})
		var autoStartOnce sync.Once
		d, err := New(config, withAutoStartObserver(func() {
			autoStartOnce.Do(func() { close(autoStarted) })
		}))
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		// Register the service
		svc := newMockService("disabled-test")
		_ = d.RegisterService(svc)

		ctx := context.Background()
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("Start() error: %v", err)
		}

		// Wait for a COMPLETED auto-start pass before asserting the negative.
		// Sleeping and finding the count still zero cannot distinguish
		// "auto-start correctly skipped this disabled service" from
		// "auto-start has not run yet" — both look identical.
		<-autoStarted

		// Service should NOT have been started because it's disabled
		if svc.startCount.Load() > 0 {
			t.Error("disabled service should not have been started")
		}

		_ = d.Stop(ctx)
	})
}

func TestDaemon_NewWithNilLogger(t *testing.T) {
	t.Run("uses default logger when nil", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-nil-logger.sock")
		config.Logger = nil

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}

		if d.logger == nil {
			t.Error("logger should not be nil when default is used")
		}
	})
}

func TestDaemon_StartTwiceWithStop(t *testing.T) {
	t.Run("can start again after stop", func(t *testing.T) {
		config := testConfig("/tmp/test-daemon-restart.sock")

		d, err := New(config)
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		defer d.ForceStop()

		ctx := context.Background()

		// First start
		err = d.Start(ctx)
		if err != nil {
			t.Fatalf("first Start() error: %v", err)
		}

		// Stop
		err = d.Stop(ctx)
		if err != nil {
			t.Fatalf("Stop() error: %v", err)
		}

		// Recreate the daemon (socket already closed)
		d2, err := New(config)
		if err != nil {
			t.Fatalf("New() after stop error: %v", err)
		}
		defer d2.ForceStop()

		// Second start with new daemon
		err = d2.Start(ctx)
		if err != nil {
			t.Fatalf("second Start() error: %v", err)
		}

		if !d2.IsRunning() {
			t.Error("daemon should be running after second start")
		}

		_ = d2.Stop(ctx)
	})
}
