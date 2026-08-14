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

package podman

import (
	"log/slog"
	"testing"
)

// hasTPMDevice reports whether an OCI configuration hands the container the
// host TPM character device.
func hasTPMDevice(oci *ociConfig) bool {
	if oci == nil || oci.Linux == nil {
		return false
	}
	for _, device := range oci.Linux.Devices {
		if device.Path == TPMDevicePath {
			return true
		}
	}
	return false
}

// TestRuntime_TPMDeviceComesOnlyFromTheContainerConfiguration is the security
// regression test for the host-knob TPM grant.
//
// The runtime used to grant /dev/tpm0 to EVERY container it started whenever
// its own configuration had the TPM default enabled, regardless of the
// container's configuration. The platform mirrors that default into the
// container specification before measuring it, so the platform's own path was
// covered — but any other caller of the runtime (or of the manager) received a
// host TPM device that appeared in no container configuration and therefore in
// no configuration digest.
//
// The grant now has exactly one source: the container's own configuration,
// which is the value the measurement is taken over.
func TestRuntime_TPMDeviceComesOnlyFromTheContainerConfiguration(t *testing.T) {
	t.Parallel()

	// A host configuration with the TPM default turned on, built exactly as
	// PodmanConfig builds the runtime's configuration.
	hostDefault := (&PodmanConfig{EnableTPMAccess: true}).ToRuntimeConfig()
	runtime := &Runtime{config: hostDefault, logger: slog.Default()}

	t.Run("a container that did not ask for the TPM does not receive it", func(t *testing.T) {
		t.Parallel()

		oci := runtime.generateOCIConfig(&ContainerConfig{
			Name:  "unprivileged",
			Image: "alpine:latest",
		}, "/tmp/rootfs")

		if hasTPMDevice(oci) {
			t.Fatal("the container was handed the host TPM device without asking " +
				"for it: the grant is outside its configuration and therefore " +
				"outside its measurement")
		}
	})

	t.Run("a container whose configuration grants the TPM receives it", func(t *testing.T) {
		t.Parallel()

		oci := runtime.generateOCIConfig(&ContainerConfig{
			Name:      "tpm-user",
			Image:     "alpine:latest",
			TPMAccess: true,
		}, "/tmp/rootfs")

		if !hasTPMDevice(oci) {
			t.Fatal("a container whose measured configuration grants the host TPM " +
				"must receive the device")
		}
	})

	t.Run("the host default does not reach the manager's runtime", func(t *testing.T) {
		t.Parallel()

		// ToManagerConfig is the other path the default used to travel:
		// NewPodmanManager copied it onto the runtime configuration.
		managerConfig := (&PodmanConfig{
			StorageRoot:     "/tmp/storage",
			RunRoot:         "/tmp/run",
			MaxContainers:   1,
			Timeout:         1,
			EnableTPMAccess: true,
		}).ToManagerConfig()

		if _, err := NewPodmanManager(managerConfig); err != nil {
			t.Fatalf("NewPodmanManager: %v", err)
		}

		manager := &Runtime{config: managerConfig.Runtime, logger: slog.Default()}
		oci := manager.generateOCIConfig(&ContainerConfig{
			Name:  "via-manager",
			Image: "alpine:latest",
		}, "/tmp/rootfs")

		if hasTPMDevice(oci) {
			t.Fatal("the manager propagated a host-level TPM default onto the " +
				"runtime, granting the device to a container that never " +
				"declared it")
		}
	})
}

// TestRuntime_ResourceLimitsReachTheContainer covers the cgroup limits the
// runtime applies. They are part of what a caller declared, so a container must
// receive them; the embedded path used to receive none, because the layer above
// never filled ContainerConfig.Resources.
func TestRuntime_ResourceLimitsReachTheContainer(t *testing.T) {
	t.Parallel()

	runtime := &Runtime{config: DefaultRuntimeConfig(), logger: slog.Default()}

	t.Run("declared limits become OCI resources", func(t *testing.T) {
		t.Parallel()

		oci := runtime.generateOCIConfig(&ContainerConfig{
			Name:  "limited",
			Image: "alpine:latest",
			Resources: &ResourceLimits{
				MemoryLimit:       512 * 1024 * 1024,
				MemoryReservation: 256 * 1024 * 1024,
				MemorySwap:        1024 * 1024 * 1024,
				CPUQuota:          150000,
				CPUPeriod:         100000,
				CPUShares:         512,
				PidsLimit:         100,
			},
		}, "/tmp/rootfs")

		resources := oci.Linux.Resources
		if resources == nil {
			t.Fatal("a container that declared limits received none")
		}
		if resources.Memory == nil || resources.Memory.Limit == nil ||
			*resources.Memory.Limit != 512*1024*1024 {
			t.Errorf("memory limit = %v, want 536870912", resources.Memory)
		}
		if resources.Memory.Reservation == nil || *resources.Memory.Reservation != 256*1024*1024 {
			t.Error("the memory reservation was dropped")
		}
		if resources.Memory.Swap == nil || *resources.Memory.Swap != 1024*1024*1024 {
			t.Error("the combined memory and swap limit was dropped")
		}
		if resources.CPU == nil || resources.CPU.Quota == nil || *resources.CPU.Quota != 150000 {
			t.Error("the CPU quota was dropped")
		}
		if resources.CPU.Period == nil || *resources.CPU.Period != 100000 {
			t.Error("the CPU period was dropped")
		}
		if resources.CPU.Shares == nil || *resources.CPU.Shares != 512 {
			t.Error("the CPU shares were dropped")
		}
		if resources.Pids == nil || resources.Pids.Limit != 100 {
			t.Error("the process limit was dropped")
		}
	})

	t.Run("a container that declared no limits gets none", func(t *testing.T) {
		t.Parallel()

		oci := runtime.generateOCIConfig(&ContainerConfig{
			Name:  "unlimited",
			Image: "alpine:latest",
		}, "/tmp/rootfs")

		if oci.Linux.Resources != nil {
			t.Errorf("Resources = %+v, want nil for a container with no limits",
				oci.Linux.Resources)
		}
	})
}

// TestResourceLimits_ValidateMemoryFields covers the negative-quantity guards
// on the memory limits, which the OCI runtime would otherwise reject far later.
func TestResourceLimits_ValidateMemoryFields(t *testing.T) {
	t.Parallel()

	valid := &ResourceLimits{
		MemoryLimit:       1024,
		MemoryReservation: 512,
		MemorySwap:        2048,
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() on valid limits = %v, want nil", err)
	}

	invalid := map[string]*ResourceLimits{
		"memory limit":       {MemoryLimit: -1},
		"memory reservation": {MemoryReservation: -1},
		"memory swap":        {MemorySwap: -1},
	}
	for name, limits := range invalid {
		if err := limits.Validate(); err == nil {
			t.Errorf("a negative %s must be rejected", name)
		}
	}
}
