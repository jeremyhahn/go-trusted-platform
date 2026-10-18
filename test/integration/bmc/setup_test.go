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

//go:build integration

// Package bmc_integration provides multi-protocol integration tests for the
// platformd BMC service. The daemon is started externally by the integration
// test shell script and endpoints are provided via environment variables.
package bmc_integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

func TestMain(m *testing.M) {
	if err := seedTestProfile(); err != nil {
		fmt.Printf("FATAL: failed to seed test device profile: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// seedTestProfile connects to platformd via gRPC, creates a device profile
// pointing at the vBMC IPMI+HTTPS endpoint, and stores the returned ID in
// DefaultTestProfileID so all protocol adapters target the same profile.
func seedTestProfile() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	endpoint := getEnvOrDefault(EnvPlatformGRPCEndpoint, DefaultPlatformGRPCEndpoint)
	conn, err := grpc.NewClient(endpoint, helpers.GRPCTransportCredentials())
	if err != nil {
		return fmt.Errorf("gRPC dial %s: %w", endpoint, err)
	}
	defer conn.Close()

	ipmiHost, ipmiPort := IPMIEndpoint(VBMCFlavorDell)

	client := device.NewClientFromGRPC(pb.NewDeviceServiceClient(conn))
	profile, err := client.CreateProfile(ctx, &pb.DeviceProfile{
		Name: "vbmc-supermicro-integration",
		Bmc: &pb.BMCConfig{
			Address:  ipmiHost,
			Port:     int32(ipmiPort),
			Username: getEnvOrDefault("VBMC_IPMI_USER", "ADMIN"),
			Password: getEnvOrDefault("VBMC_IPMI_PASSWORD", "ADMIN"),
			Protocol: "ipmi",
		},
	})
	if err != nil {
		return fmt.Errorf("CreateProfile: %w", err)
	}

	DefaultTestProfileID = profile.Id
	fmt.Printf("Test profile created: ID=%d, address=%s:%d\n", profile.Id, ipmiHost, ipmiPort)

	// The BMC enrollment ceremony stamps a Device entity (the "device-stamp"
	// step) using the same identifier passed to EnrollBMC — the profile ID.
	// Seed a Device with that ID so the ceremony can load and persist the
	// resulting BMCEnrollment record and complete successfully.
	if _, err := client.Create(ctx, &pb.Device{
		Id:     profile.Id,
		Model:  "vbmc-supermicro-integration",
		Serial: fmt.Sprintf("VBMC-%d", profile.Id),
	}); err != nil {
		return fmt.Errorf("CreateDevice: %w", err)
	}
	fmt.Printf("Test device created: ID=%d\n", profile.Id)
	return nil
}
