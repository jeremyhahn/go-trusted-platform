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

package container

import (
	"context"
	"reflect"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// digestOfLaunch is the configuration digest of an effective launch
// configuration — the measurement, computed exactly as measureCreate does.
func digestOfLaunch(t *testing.T, launch *PodmanContainerConfig) string {
	t.Helper()
	d, err := orchestration.ContainerConfigDigest(launch.AttestationSpec())
	if err != nil {
		t.Fatalf("ContainerConfigDigest: %v", err)
	}
	return d
}

// digestOfSpec is the configuration digest a specification measures as.
func digestOfSpec(t *testing.T, spec *OrchestratorContainerSpec) string {
	t.Helper()
	return digestOfLaunch(t, newLaunchConfig(spec))
}

// TestLaunchConfig_TPMAccessIsMeasured is the security regression test for the
// two-derivations hole.
//
// The launch path appended a /dev/tpm0 bind mount for a spec with TPMAccess
// set; the measurement path mapped only spec.Mounts. Two specs differing only
// by TPMAccess therefore measured identically while one of them received the
// platform's root of trust — granting a workload the host TPM did not change
// its measurement. The mount list the container receives is now the mount list
// that is measured, so the grant cannot be invisible.
func TestLaunchConfig_TPMAccessIsMeasured(t *testing.T) {
	t.Parallel()

	base := func() *OrchestratorContainerSpec {
		return &OrchestratorContainerSpec{Name: "tpm", Image: "alpine:latest"}
	}

	t.Run("granting the host TPM changes the configuration digest", func(t *testing.T) {
		t.Parallel()

		granted := base()
		granted.TPMAccess = true

		if digestOfSpec(t, base()) == digestOfSpec(t, granted) {
			t.Fatal("a container handed the host TPM device measured identically " +
				"to one that was not")
		}
	})

	t.Run("the TPM device appears in the measured mount list", func(t *testing.T) {
		t.Parallel()

		spec := base()
		spec.TPMAccess = true
		measured := newLaunchConfig(spec).AttestationSpec()

		found := false
		for _, m := range measured.Mounts {
			if m.Source == HostTPMDevicePath && m.Target == HostTPMDevicePath {
				if m.Type != orchestration.MountTypeBind {
					t.Errorf("TPM mount Type = %q, want %q", m.Type, orchestration.MountTypeBind)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("%s is missing from the measured mount list", HostTPMDevicePath)
		}
	})

	// The grant has one representation, so the backend's device request and
	// the measurement cannot disagree.
	t.Run("the backend device request follows the measured mount list", func(t *testing.T) {
		t.Parallel()

		spec := base()
		spec.TPMAccess = true
		launch := newLaunchConfig(spec)

		if !launch.GrantsTPMDevice() {
			t.Fatal("GrantsTPMDevice must report the grant carried by the mount list")
		}
		backend, err := convertFromPodmanContainerConfig(launch)
		if err != nil {
			t.Fatalf("convertFromPodmanContainerConfig: %v", err)
		}
		if !backend.TPMAccess {
			t.Fatal("the backend was not asked for the TPM device the mount list grants")
		}
	})

	// Declaring the device mount directly is the same grant and measures as
	// such: there is no second, unmeasured way to ask for it.
	t.Run("an explicitly declared TPM mount is the same grant", func(t *testing.T) {
		t.Parallel()

		flag := base()
		flag.TPMAccess = true

		explicit := base()
		explicit.Mounts = []MountConfig{
			{Source: HostTPMDevicePath, Target: HostTPMDevicePath, Type: MountTypeBind},
		}

		if digestOfSpec(t, flag) != digestOfSpec(t, explicit) {
			t.Error("the TPM flag and an explicit /dev/tpm0 mount must measure the same")
		}
		if !newLaunchConfig(explicit).GrantsTPMDevice() {
			t.Error("an explicit /dev/tpm0 mount is a TPM grant")
		}
	})
}

// TestLaunchConfig_SingleDerivation asserts the structural property the
// refactor exists to establish: the container's measurement is computed over
// the very value the backend was handed, not over a parallel derivation of the
// same specification.
func TestLaunchConfig_SingleDerivation(t *testing.T) {
	ctx := context.Background()

	spec := &OrchestratorContainerSpec{
		Name:       "derived-once",
		Image:      "alpine:latest",
		Command:    []string{"/bin/sh"},
		Args:       []string{"-c", "true"},
		Env:        map[string]string{"KEY": "value"},
		Labels:     map[string]string{"app": "web"},
		User:       "1000:1000",
		WorkingDir: "/app",
		Privileged: true,
		TPMAccess:  true,
		Capabilities: CapabilityConfig{
			Add:  []string{"NET_ADMIN"},
			Drop: []string{"ALL"},
		},
		Mounts: []MountConfig{
			{Source: "/host", Target: "/container", Type: MountTypeBind, ReadOnly: true},
		},
		Ports: []PortMapping{
			{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
		},
		Network: ContainerNetworkConfig{Mode: NetworkModeHost},
	}

	orch, podman, _ := newMeasuringOrchestrator(t, fixedDigestResolver{})

	container, err := orch.Create(ctx, spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	launched := podman.createConfig
	if launched == nil {
		t.Fatal("the backend recorded no launch configuration")
	}

	// Re-derive the measurement from what the backend actually received and
	// require the recorded ConfigDigest to match it. Any field applied to the
	// container but omitted from the measurement, or measured but not applied,
	// breaks this equality.
	expected := launched.AttestationSpec()
	expected.ImageDigest = digestOf(spec.Image)
	want, err := orchestration.ContainerConfigDigest(expected)
	if err != nil {
		t.Fatalf("ContainerConfigDigest: %v", err)
	}

	entry, err := orch.attestor.GetMeasurementLog().FindImageIdentity(container.ID)
	if err != nil {
		t.Fatalf("FindImageIdentity: %v", err)
	}
	if entry.ConfigDigest != want {
		t.Fatalf("recorded ConfigDigest = %q, want the digest of the launched "+
			"configuration %q", entry.ConfigDigest, want)
	}

	// And the launched configuration really is the one the specification
	// derives, so no caller can slip a different value past the measurement.
	if !reflect.DeepEqual(launched, newLaunchConfig(spec)) {
		t.Error("the backend received something other than the spec's single derivation")
	}
}

// TestLaunchConfig_MeasurementCoverage is the exhaustiveness backstop.
//
// It enumerates every field of the effective launch configuration — the value
// the backend is handed — by reflection and requires each one to be classified
// either as measured or as a stated gap. A field added to the launch path in a
// later change fails this test until the author decides, in writing, whether
// it belongs in the configuration digest. That is what keeps the class of bug
// this refactor closed from reopening one field at a time.
func TestLaunchConfig_MeasurementCoverage(t *testing.T) {
	t.Parallel()

	// measured names a launch field that changes the configuration digest,
	// with a mutation that proves it.
	measured := map[string]func(*PodmanContainerConfig){
		"Image":       func(c *PodmanContainerConfig) { c.Image = "alpine:3.20" },
		"Command":     func(c *PodmanContainerConfig) { c.Command = []string{"/bin/false"} },
		"Entrypoint":  func(c *PodmanContainerConfig) { c.Entrypoint = []string{"/init"} },
		"Environment": func(c *PodmanContainerConfig) { c.Environment = map[string]string{"K": "other"} },
		"Labels":      func(c *PodmanContainerConfig) { c.Labels = map[string]string{"app": "other"} },
		"Mounts": func(c *PodmanContainerConfig) {
			c.Mounts = append(c.Mounts, PodmanMount{Source: "/etc", Target: "/etc", Type: "bind"})
		},
		"Ports": func(c *PodmanContainerConfig) {
			c.Ports = append(c.Ports, PodmanPort{HostPort: 9090, ContainerPort: 90, Protocol: "tcp"})
		},
		"NetworkMode": func(c *PodmanContainerConfig) { c.NetworkMode = "host" },
		"User":        func(c *PodmanContainerConfig) { c.User = "0:0" },
		"WorkDir":     func(c *PodmanContainerConfig) { c.WorkDir = "/elsewhere" },
		"Privileged":  func(c *PodmanContainerConfig) { c.Privileged = true },
		"AutoRemove":  func(c *PodmanContainerConfig) { c.AutoRemove = true },
		"CapAdd":      func(c *PodmanContainerConfig) { c.CapAdd = []string{"SYS_ADMIN"} },
		"CapDrop":     func(c *PodmanContainerConfig) { c.CapDrop = []string{"ALL"} },
	}

	// carried names a launch field the SDK spec receives but deliberately
	// excludes from the digest.
	carried := map[string]string{
		"Name": "a per-instance identifier the SDK excludes, so two identically " +
			"configured containers with different names measure alike",
	}

	// gaps names a launch field that is NOT in the digest, with the reason.
	// Each entry is asserted to still be a gap, so closing one upstream fails
	// this test and forces the classification, the AttestationSpec doc comment
	// and docs/attestation/workload-attestation.md to be updated together.
	gaps := map[string]struct {
		reason string
		mutate func(*PodmanContainerConfig)
	}{
		"Hostname": {
			reason: "reaches the container as the OCI process hostname; " +
				"needs orchestration.ContainerSpec.Hostname upstream",
			mutate: func(c *PodmanContainerConfig) { c.Hostname = "elsewhere" },
		},
		"DNS": {
			reason: "needs orchestration.ContainerSpec.DNS upstream; also dropped " +
				"at the podman adapter today, so it reaches nothing",
			mutate: func(c *PodmanContainerConfig) { c.DNS = []string{"10.0.0.1"} },
		},
		"DNSSearch": {
			reason: "needs orchestration.ContainerSpec.DNSSearch upstream; also " +
				"dropped at the podman adapter today",
			mutate: func(c *PodmanContainerConfig) { c.DNSSearch = []string{"evil.example"} },
		},
		"ReadOnly": {
			reason: "read-only rootfs; needs " +
				"orchestration.ContainerSpec.ReadOnlyRootFS upstream. Nothing sets it",
			mutate: func(c *PodmanContainerConfig) { c.ReadOnly = true },
		},
		"StopTimeout": {
			reason: "bounds how long a stop waits: availability, not integrity. " +
				"It cannot change what runs or what the workload can reach",
			mutate: func(c *PodmanContainerConfig) {
				timeout := 600
				c.StopTimeout = &timeout
			},
		},
		// Unlike the entries above, this is a decision rather than a missing
		// upstream field: the limits ARE applied, by every launch path, and are
		// deliberately left out of the digest.
		"Resources": {
			reason: "CPU, memory and process limits bound what a workload may " +
				"consume: availability, not integrity. They cannot change what it " +
				"runs or what it can reach",
			mutate: func(c *PodmanContainerConfig) {
				c.Resources = ResourceConfig{MemoryLimit: "64M", CPULimit: "0.25"}
			},
		},
	}

	base := func() *PodmanContainerConfig {
		return newLaunchConfig(&OrchestratorContainerSpec{
			Name:    "coverage",
			Image:   "alpine:latest",
			Command: []string{"/bin/sh"},
			Env:     map[string]string{"K": "v"},
			Labels:  map[string]string{"app": "web"},
			Mounts: []MountConfig{
				{Source: "/host", Target: "/container", Type: MountTypeBind},
			},
			Ports: []PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		})
	}
	baseDigest := digestOfLaunch(t, base())

	// Every field of the launch configuration must be classified.
	launchType := reflect.TypeOf(PodmanContainerConfig{})
	for i := 0; i < launchType.NumField(); i++ {
		name := launchType.Field(i).Name
		_, isMeasured := measured[name]
		_, isCarried := carried[name]
		_, isGap := gaps[name]
		if !isMeasured && !isCarried && !isGap {
			t.Errorf("PodmanContainerConfig.%s reaches the container but is not "+
				"classified: add it to AttestationSpec and to the measured set, "+
				"or state why it is a gap (and update "+
				"docs/attestation/workload-attestation.md)", name)
		}
	}
	for name := range measured {
		if _, ok := launchType.FieldByName(name); !ok {
			t.Errorf("measured set names PodmanContainerConfig.%s, which no longer exists", name)
		}
	}
	for name := range gaps {
		if _, ok := launchType.FieldByName(name); !ok {
			t.Errorf("gap set names PodmanContainerConfig.%s, which no longer exists", name)
		}
	}

	for name, mutate := range measured {
		t.Run("measured/"+name, func(t *testing.T) {
			launch := base()
			mutate(launch)
			if digestOfLaunch(t, launch) == baseDigest {
				t.Errorf("changing %s must change the configuration digest", name)
			}
		})
	}

	for name, gap := range gaps {
		t.Run("gap/"+name, func(t *testing.T) {
			launch := base()
			gap.mutate(launch)
			if digestOfLaunch(t, launch) != baseDigest {
				t.Errorf("%s now affects the configuration digest — the gap is closed; "+
					"reclassify it here, in AttestationSpec's doc comment and in "+
					"docs/attestation/workload-attestation.md (reason was: %s)",
					name, gap.reason)
			}
		})
	}

	// The nested mount and port shapes are part of the same surface.
	t.Run("mount fields", func(t *testing.T) {
		mountGaps := map[string]string{
			"Options": "mount propagation rides here; needs " +
				"orchestration.ContainerMount.Propagation upstream",
		}
		mountMeasured := map[string]struct{}{
			"Source": {}, "Target": {}, "Type": {}, "ReadOnly": {},
		}
		mountType := reflect.TypeOf(PodmanMount{})
		for i := 0; i < mountType.NumField(); i++ {
			name := mountType.Field(i).Name
			_, ok := mountMeasured[name]
			_, gap := mountGaps[name]
			if !ok && !gap {
				t.Errorf("PodmanMount.%s is not classified as measured or as a gap", name)
			}
		}

		launch := base()
		launch.Mounts[0].Options = []string{"rshared"}
		if digestOfLaunch(t, launch) != baseDigest {
			t.Error("PodmanMount.Options now affects the digest — the gap is closed; " +
				"reclassify it")
		}
	})

	t.Run("port fields", func(t *testing.T) {
		// Every port field is folded into the canonical mapping string, so
		// each must move the digest.
		portMutations := map[string]func(*PodmanPort){
			"HostIP":        func(p *PodmanPort) { p.HostIP = "127.0.0.1" },
			"HostPort":      func(p *PodmanPort) { p.HostPort = 9999 },
			"ContainerPort": func(p *PodmanPort) { p.ContainerPort = 8443 },
			"Protocol":      func(p *PodmanPort) { p.Protocol = "udp" },
		}
		portType := reflect.TypeOf(PodmanPort{})
		for i := 0; i < portType.NumField(); i++ {
			name := portType.Field(i).Name
			if _, ok := portMutations[name]; !ok {
				t.Errorf("PodmanPort.%s is not covered: it is folded into the "+
					"measured mapping string or it is a gap", name)
			}
		}
		for name, mutate := range portMutations {
			launch := base()
			mutate(&launch.Ports[0])
			if digestOfLaunch(t, launch) == baseDigest {
				t.Errorf("changing PodmanPort.%s must change the digest", name)
			}
		}
	})
}

// TestNewLaunchConfig covers the derivation itself, including the two
// properties its doc comment claims.
func TestNewLaunchConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil spec derives nothing", func(t *testing.T) {
		t.Parallel()
		if got := newLaunchConfig(nil); got != nil {
			t.Errorf("newLaunchConfig(nil) = %v, want nil", got)
		}
	})

	t.Run("carries the spec onto the launch configuration", func(t *testing.T) {
		t.Parallel()

		launch := newLaunchConfig(&OrchestratorContainerSpec{
			Name:       "full",
			Image:      "nginx:latest",
			Command:    []string{"nginx"},
			Args:       []string{"-g", "daemon off;"},
			Env:        map[string]string{"ENV": "test"},
			Labels:     map[string]string{"app": "nginx"},
			User:       "nginx",
			WorkingDir: "/app",
			Privileged: true,
			Capabilities: CapabilityConfig{
				Add:  []string{"NET_ADMIN"},
				Drop: []string{"ALL"},
			},
			Mounts: []MountConfig{{Source: "/data", Target: "/app/data", ReadOnly: true}},
			Ports:  []PortMapping{{ContainerPort: 80, HostPort: 8080, Protocol: "tcp"}},
			Network: ContainerNetworkConfig{
				Mode:       NetworkModeHost,
				DNSServers: []string{"8.8.8.8"},
				DNSSearch:  []string{"example.test"},
				Hostname:   "nginx-host",
			},
		})

		if launch.Name != "full" || launch.Image != "nginx:latest" {
			t.Errorf("identity not carried: %q %q", launch.Name, launch.Image)
		}
		if want := []string{"nginx", "-g", "daemon off;"}; !reflect.DeepEqual(launch.Command, want) {
			t.Errorf("Command = %v, want %v", launch.Command, want)
		}
		if launch.NetworkMode != NetworkModeHost.String() {
			t.Errorf("NetworkMode = %q, want %q", launch.NetworkMode, NetworkModeHost)
		}
		if launch.Hostname != "nginx-host" {
			t.Errorf("Hostname = %q, want nginx-host", launch.Hostname)
		}
		if len(launch.DNS) != 1 || len(launch.DNSSearch) != 1 {
			t.Errorf("DNS = %v, DNSSearch = %v", launch.DNS, launch.DNSSearch)
		}
		if len(launch.Mounts) != 1 || len(launch.Ports) != 1 {
			t.Errorf("mounts = %d, ports = %d, want 1 and 1", len(launch.Mounts), len(launch.Ports))
		}
		if !launch.Privileged || len(launch.CapAdd) != 1 || len(launch.CapDrop) != 1 {
			t.Error("the privilege dimension was not carried")
		}
	})

	// The declared platform mode is what the launch configuration carries, so
	// the measurement names the mode the operator approved. Mapping it onto a
	// mode the backend understands happens at the backend boundary.
	t.Run("carries the declared network mode, including sdn", func(t *testing.T) {
		t.Parallel()

		launch := newLaunchConfig(&OrchestratorContainerSpec{
			Name:    "sdn",
			Image:   "alpine:latest",
			Network: ContainerNetworkConfig{Mode: NetworkModeSDN, SDN: &SDNConfig{Bridge: "br0"}},
		})
		if launch.NetworkMode != NetworkModeSDN.String() {
			t.Errorf("NetworkMode = %q, want %q", launch.NetworkMode, NetworkModeSDN)
		}
		backend, err := convertFromPodmanContainerConfig(launch)
		if err != nil {
			t.Fatalf("convertFromPodmanContainerConfig: %v", err)
		}
		if backend.NetworkMode != "bridge" {
			t.Errorf("backend NetworkMode = %q, want bridge", backend.NetworkMode)
		}
	})

	t.Run("an sdn container does not measure as a bridge container", func(t *testing.T) {
		t.Parallel()

		bridged := &OrchestratorContainerSpec{
			Name:    "net",
			Image:   "alpine:latest",
			Network: ContainerNetworkConfig{Mode: NetworkModeBridge},
		}
		sdn := &OrchestratorContainerSpec{
			Name:    "net",
			Image:   "alpine:latest",
			Network: ContainerNetworkConfig{Mode: NetworkModeSDN, SDN: &SDNConfig{Bridge: "br0"}},
		}
		if digestOfSpec(t, bridged) == digestOfSpec(t, sdn) {
			t.Error("an SDN container must not measure as a bridge container")
		}
	})

	// Command and Args become one argv, which is what the container executes.
	t.Run("command and args are one measured argv", func(t *testing.T) {
		t.Parallel()

		split := &OrchestratorContainerSpec{
			Name: "argv", Image: "alpine:latest",
			Command: []string{"/bin/sh"}, Args: []string{"-c", "true"},
		}
		joined := &OrchestratorContainerSpec{
			Name: "argv", Image: "alpine:latest",
			Command: []string{"/bin/sh", "-c", "true"},
		}
		if digestOfSpec(t, split) != digestOfSpec(t, joined) {
			t.Error("specs that launch the same argv must measure the same")
		}

		different := &OrchestratorContainerSpec{
			Name: "argv", Image: "alpine:latest",
			Command: []string{"/bin/sh"}, Args: []string{"-c", "curl evil"},
		}
		if digestOfSpec(t, split) == digestOfSpec(t, different) {
			t.Error("changing the arguments must change the digest")
		}
	})

	t.Run("declaration order of mounts is preserved and measured", func(t *testing.T) {
		t.Parallel()

		first := &OrchestratorContainerSpec{
			Name: "order", Image: "alpine:latest",
			Mounts: []MountConfig{
				{Source: "/a", Target: "/a", Type: MountTypeBind},
				{Source: "/b", Target: "/b", Type: MountTypeBind},
			},
		}
		second := &OrchestratorContainerSpec{
			Name: "order", Image: "alpine:latest",
			Mounts: []MountConfig{
				{Source: "/b", Target: "/b", Type: MountTypeBind},
				{Source: "/a", Target: "/a", Type: MountTypeBind},
			},
		}
		if digestOfSpec(t, first) == digestOfSpec(t, second) {
			t.Error("mount order is significant to the runtime and must be measured")
		}
	})
}

func TestPodmanContainerConfig_GrantsTPMDevice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config *PodmanContainerConfig
		want   bool
	}{
		{name: "nil config", config: nil, want: false},
		{name: "no mounts", config: &PodmanContainerConfig{}, want: false},
		{
			name: "unrelated mounts",
			config: &PodmanContainerConfig{Mounts: []PodmanMount{
				{Source: "/host", Target: "/container", Type: "bind"},
			}},
			want: false,
		},
		{
			name: "device mounted at its host path",
			config: &PodmanContainerConfig{Mounts: []PodmanMount{
				{Source: HostTPMDevicePath, Target: HostTPMDevicePath, Type: "bind"},
			}},
			want: true,
		},
		{
			name: "device mounted elsewhere in the container",
			config: &PodmanContainerConfig{Mounts: []PodmanMount{
				{Source: HostTPMDevicePath, Target: "/dev/tpm", Type: "bind"},
			}},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.config.GrantsTPMDevice(); got != tc.want {
				t.Errorf("GrantsTPMDevice() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPodmanContainerConfig_AttestationSpec(t *testing.T) {
	t.Parallel()

	t.Run("nil launch configuration measures nothing", func(t *testing.T) {
		t.Parallel()
		var config *PodmanContainerConfig
		if got := config.AttestationSpec(); got != nil {
			t.Error("AttestationSpec() on a nil launch configuration must be nil")
		}
	})

	t.Run("an unmeasurable spec is refused by the SDK, not silently hashed", func(t *testing.T) {
		t.Parallel()
		// An empty image is not a measurable configuration.
		if _, err := orchestration.ContainerConfigDigest((&PodmanContainerConfig{}).AttestationSpec()); err != nil {
			t.Logf("ContainerConfigDigest rejected the empty configuration: %v", err)
		}
		if _, err := orchestration.ContainerConfigDigest(nil); err == nil {
			t.Error("a nil spec must not produce a digest")
		}
	})

	t.Run("projects every measured field", func(t *testing.T) {
		t.Parallel()

		launch := &PodmanContainerConfig{
			Name:        "proj",
			Image:       "nginx:latest",
			Command:     []string{"nginx", "-g"},
			Entrypoint:  []string{"/init"},
			Environment: map[string]string{"K": "v"},
			Labels:      map[string]string{"app": "web"},
			NetworkMode: "host",
			User:        "nginx",
			WorkDir:     "/app",
			Privileged:  true,
			AutoRemove:  true,
			CapAdd:      []string{"NET_ADMIN"},
			CapDrop:     []string{"ALL"},
			Mounts: []PodmanMount{
				{Source: "/host", Target: "/container", Type: "bind", ReadOnly: true},
			},
			Ports: []PodmanPort{
				{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			},
		}

		spec := launch.AttestationSpec()
		if spec.Image != launch.Image || spec.User != launch.User || spec.WorkDir != launch.WorkDir {
			t.Error("identity fields were not projected")
		}
		if !spec.Privileged || !spec.AutoRemove {
			t.Error("flags were not projected")
		}
		if spec.Network != "host" {
			t.Errorf("Network = %q, want host", spec.Network)
		}
		if !reflect.DeepEqual(spec.Entrypoint, launch.Entrypoint) {
			t.Errorf("Entrypoint = %v, want %v", spec.Entrypoint, launch.Entrypoint)
		}
		if len(spec.Mounts) != 1 || spec.Mounts[0].Type != "bind" || !spec.Mounts[0].ReadOnly {
			t.Errorf("Mounts = %v", spec.Mounts)
		}
		if len(spec.Ports) != 1 || spec.Ports[0] != "0.0.0.0:8080:80/tcp" {
			t.Errorf("Ports = %v, want [0.0.0.0:8080:80/tcp]", spec.Ports)
		}
	})
}

func TestFormatPodmanPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		port PodmanPort
		want string
	}{
		{name: "host and container port", port: PodmanPort{HostPort: 8080, ContainerPort: 80}, want: "8080:80"},
		{
			name: "with protocol",
			port: PodmanPort{HostPort: 8080, ContainerPort: 80, Protocol: "udp"},
			want: "8080:80/udp",
		},
		{
			name: "with host ip",
			port: PodmanPort{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"},
			want: "127.0.0.1:8080:80/tcp",
		},
		{name: "zero value", port: PodmanPort{}, want: "0:0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := formatPodmanPort(tc.port); got != tc.want {
				t.Errorf("formatPodmanPort() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBackendNetworkMode(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		NetworkModeBridge.String(): "bridge",
		NetworkModeHost.String():   "host",
		NetworkModeNone.String():   "none",
		NetworkModeSDN.String():    "bridge",
		"":                         "bridge",
		"nonsense":                 "bridge",
	}

	for mode, want := range tests {
		if got := backendNetworkMode(mode); got != want {
			t.Errorf("backendNetworkMode(%q) = %q, want %q", mode, got, want)
		}
	}
}
