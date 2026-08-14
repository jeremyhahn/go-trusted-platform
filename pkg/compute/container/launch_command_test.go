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
	"reflect"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/podman"
)

// standaloneSpec is a specification that exercises every dimension of the
// launch configuration a standalone service must reproduce.
func standaloneSpec() *OrchestratorContainerSpec {
	return &OrchestratorContainerSpec{
		Name:       "standalone",
		Image:      "myregistry.io/app:v1",
		Command:    []string{"/app/start.sh"},
		Args:       []string{"--flag", "value"},
		User:       "1000:1000",
		WorkingDir: "/app",
		Privileged: true,
		TPMAccess:  true,
		Capabilities: CapabilityConfig{
			Add:  []string{"NET_ADMIN"},
			Drop: []string{"ALL"},
		},
		Env:    map[string]string{"APP_ENV": "production"},
		Labels: map[string]string{"app": "myapp"},
		Mounts: []MountConfig{
			{Source: "/host/data", Target: "/data"},
		},
		Ports: []PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		Network: ContainerNetworkConfig{
			Mode:     NetworkModeHost,
			Hostname: "app-host",
		},
		Resources: ResourceConfig{MemoryLimit: "2G", CPULimit: "2"},
		Service: ServiceConfig{
			Mode:       ServiceModeStandalone,
			Standalone: &StandaloneConfig{Restart: "always"},
		},
	}
}

// TestStandaloneServiceLaunchesTheMeasuredConfiguration is the security
// regression test for the standalone-mode attestation bypass.
//
// The generators built their own podman run command line from the
// specification, independently of newLaunchConfig. They omitted capabilities,
// user, working directory, arguments, the hostname and the TPM device grant, so
// with Service.Mode: standalone the container systemd or OpenRC actually
// started was not the container that had been measured: the measurement
// attested a configuration that never ran.
//
// Every flag asserted here is part of the effective launch configuration the
// measurement is taken over. A generator that re-walks the specification cannot
// satisfy this test by accident.
func TestStandaloneServiceLaunchesTheMeasuredConfiguration(t *testing.T) {
	t.Parallel()

	// Each entry is a dimension of the measured launch configuration that the
	// standalone launch must apply too.
	wanted := map[string]string{
		"user":               "--user 1000:1000",
		"working directory":  "--workdir /app",
		"added capability":   "--cap-add NET_ADMIN",
		"dropped capability": "--cap-drop ALL",
		"host TPM device":    "--device /dev/tpm0:/dev/tpm0",
		"command arguments":  "--flag value",
		"hostname":           "--hostname app-host",
		"privileged":         "--privileged",
	}

	t.Run("systemd", func(t *testing.T) {
		t.Parallel()
		unit := NewSystemdGenerator().Generate(standaloneSpec())
		for dimension, flag := range wanted {
			if !strings.Contains(unit, flag) {
				t.Errorf("the systemd unit does not apply the measured %s (%q): "+
					"the container systemd starts is not the container that was "+
					"measured", dimension, flag)
			}
		}
	})

	t.Run("openrc", func(t *testing.T) {
		t.Parallel()
		script := NewRCGenerator().Generate(standaloneSpec())
		for dimension, flag := range wanted {
			if !strings.Contains(script, flag) {
				t.Errorf("the rc script does not apply the measured %s (%q): "+
					"the container OpenRC starts is not the container that was "+
					"measured", dimension, flag)
			}
		}
	})
}

// containsSequence reports whether want appears as a contiguous run of args.
func containsSequence(args, want []string) bool {
	if len(want) == 0 || len(want) > len(args) {
		return false
	}
	for i := 0; i+len(want) <= len(args); i++ {
		matched := true
		for j, value := range want {
			if args[i+j] != value {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// coverageLaunchConfig is an effective launch configuration with every field
// set to a value the rendered command line must be able to show.
func coverageLaunchConfig() *PodmanContainerConfig {
	stopTimeout := 30
	return &PodmanContainerConfig{
		Name:        "coverage",
		Image:       "myregistry.io/app:v1",
		Command:     []string{"/app/start.sh", "--flag", "value"},
		Entrypoint:  []string{"/init"},
		Environment: map[string]string{"APP_ENV": "production"},
		Labels:      map[string]string{"app": "myapp"},
		Mounts: []PodmanMount{
			{Source: "/host/data", Target: "/data"},
			{Source: "/host/config", Target: "/config", ReadOnly: true},
			{Source: "/host/typed", Target: "/typed", Type: "bind"},
			{Source: HostTPMDevicePath, Target: HostTPMDevicePath, Type: "bind"},
		},
		Ports:       []PodmanPort{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
		NetworkMode: "host",
		User:        "1000:1000",
		WorkDir:     "/app",
		Hostname:    "app-host",
		Privileged:  true,
		ReadOnly:    true,
		AutoRemove:  true,
		StopTimeout: &stopTimeout,
		CapAdd:      []string{"NET_ADMIN"},
		CapDrop:     []string{"ALL"},
		DNS:         []string{"10.0.0.1"},
		DNSSearch:   []string{"example.test"},
		Resources: ResourceConfig{
			MemoryLimit:       "512M",
			MemoryReservation: "256M",
			MemorySwap:        "1G",
			CPULimit:          "1.5",
			CPUShares:         512,
			PidsLimit:         100,
		},
	}
}

// TestPodmanRunArgs_LaunchCoverage is the drift backstop for the three launch
// paths, and the counterpart of TestLaunchConfig_MeasurementCoverage.
//
// It enumerates every field of the effective launch configuration by reflection
// and requires each one to be classified: either the rendered command line shows
// it, or the field is inert — dropped by convertFromPodmanContainerConfig too,
// so it reaches no container by any path. An inert field must PROVE it is inert
// against the backend projection, so wiring a field into the backend without
// rendering it into a generated unit fails this test rather than silently
// making standalone containers differ from measured ones.
func TestPodmanRunArgs_LaunchCoverage(t *testing.T) {
	t.Parallel()

	launch := coverageLaunchConfig()
	args := podmanRunArgs(launch)

	backend, err := convertFromPodmanContainerConfig(launch)
	if err != nil {
		t.Fatalf("convertFromPodmanContainerConfig: %v", err)
	}

	// rendered names a launch field the command line must show, with the exact
	// contiguous argument runs that show it.
	rendered := map[string][][]string{
		"Name":        {{"--name", "coverage"}},
		"Image":       {{"myregistry.io/app:v1"}},
		"Command":     {{"/app/start.sh", "--flag", "value"}},
		"Environment": {{"-e", "APP_ENV=production"}},
		"Labels":      {{"--label", "app=myapp"}},
		"Mounts": {
			{"-v", "/host/data:/data"},
			{"-v", "/host/config:/config:ro"},
			{"--mount", "type=bind,source=/host/typed,destination=/typed"},
			// The host TPM grant is a device, exactly as the backend requests it.
			{"--device", HostTPMDevicePath + ":" + HostTPMDevicePath},
		},
		"Ports":       {{"-p", "8080:80/tcp"}},
		"NetworkMode": {{"--network", "host"}},
		"User":        {{"--user", "1000:1000"}},
		"WorkDir":     {{"--workdir", "/app"}},
		"Hostname":    {{"--hostname", "app-host"}},
		"Privileged":  {{"--privileged"}},
		"ReadOnly":    {{"--read-only"}},
		"StopTimeout": {{"--stop-timeout", "30"}},
		"CapAdd":      {{"--cap-add", "NET_ADMIN"}},
		"CapDrop":     {{"--cap-drop", "ALL"}},
		"Resources": {
			{"--memory", "512M"},
			{"--memory-reservation", "256M"},
			{"--memory-swap", "1G"},
			{"--cpus", "1.5"},
			{"--cpu-shares", "512"},
			{"--pids-limit", "100"},
		},
	}

	// inert names a launch field the command line does NOT render, together with
	// the proof that the backend does not receive it either.
	inert := map[string]struct {
		reason string
		absent func(*podman.ContainerConfig) bool
	}{
		"Entrypoint": {
			reason: "the podman adapter drops it and the embedded runtime never " +
				"reads it, so rendering --entrypoint would make a standalone " +
				"container differ from the measured one",
			absent: func(c *podman.ContainerConfig) bool { return c.Entrypoint == nil },
		},
		"AutoRemove": {
			reason: "the podman adapter drops it; the generated unit and script " +
				"remove the container explicitly instead",
			absent: func(c *podman.ContainerConfig) bool { return !c.AutoRemove },
		},
		"DNS": {
			reason: "the podman adapter drops it, so no launch path resolves names " +
				"differently; it is also an upstream measurement gap " +
				"(orchestration.ContainerSpec.DNS)",
			absent: func(c *podman.ContainerConfig) bool { return len(c.DNS) == 0 },
		},
		"DNSSearch": {
			reason: "the podman adapter drops it, exactly as it drops DNS servers",
			absent: func(c *podman.ContainerConfig) bool { return len(c.DNSSearch) == 0 },
		},
	}

	launchType := reflect.TypeOf(PodmanContainerConfig{})
	for i := 0; i < launchType.NumField(); i++ {
		name := launchType.Field(i).Name
		_, isRendered := rendered[name]
		_, isInert := inert[name]
		if !isRendered && !isInert {
			t.Errorf("PodmanContainerConfig.%s is not classified for the launch "+
				"command line: render it in podmanRunArgs, or state why it is "+
				"inert and prove the backend drops it too", name)
		}
		if isRendered && isInert {
			t.Errorf("PodmanContainerConfig.%s cannot be both rendered and inert", name)
		}
	}
	for name := range rendered {
		if _, ok := launchType.FieldByName(name); !ok {
			t.Errorf("rendered set names PodmanContainerConfig.%s, which no longer exists", name)
		}
	}
	for name := range inert {
		if _, ok := launchType.FieldByName(name); !ok {
			t.Errorf("inert set names PodmanContainerConfig.%s, which no longer exists", name)
		}
	}

	for name, sequences := range rendered {
		for _, want := range sequences {
			if !containsSequence(args, want) {
				t.Errorf("the launch command line does not apply %s as %v; a "+
					"standalone container would not be the container that was "+
					"measured.\nargs: %v", name, want, args)
			}
		}
	}

	for name, classification := range inert {
		if !classification.absent(backend) {
			t.Errorf("PodmanContainerConfig.%s now reaches the backend, so the "+
				"generated unit and script must render it too — it is no longer "+
				"inert (reason was: %s)", name, classification.reason)
		}
	}
}

// TestPodmanRunArgs_MirrorsTheBackendProjection asserts the two projections of
// one launch configuration agree on the values a container actually gets, so
// neither supervisor can start something the other would not.
func TestPodmanRunArgs_MirrorsTheBackendProjection(t *testing.T) {
	t.Parallel()

	launch := newLaunchConfig(standaloneSpec())
	args := podmanRunArgs(launch)
	backend, err := convertFromPodmanContainerConfig(launch)
	if err != nil {
		t.Fatalf("convertFromPodmanContainerConfig: %v", err)
	}

	if !containsSequence(args, []string{"--network", backend.NetworkMode}) {
		t.Errorf("the command line does not use the backend's network mode %q: %v",
			backend.NetworkMode, args)
	}
	if !containsSequence(args, []string{"--user", backend.User}) {
		t.Errorf("the command line does not apply the backend's user %q", backend.User)
	}
	if !containsSequence(args, []string{"--workdir", backend.WorkDir}) {
		t.Errorf("the command line does not apply the backend's workdir %q", backend.WorkDir)
	}
	if !containsSequence(args, []string{"--hostname", backend.Hostname}) {
		t.Errorf("the command line does not apply the backend's hostname %q", backend.Hostname)
	}
	if backend.Privileged != containsSequence(args, []string{"--privileged"}) {
		t.Error("privilege differs between the backend request and the command line")
	}
	if backend.TPMAccess != containsSequence(args,
		[]string{"--device", HostTPMDevicePath + ":" + HostTPMDevicePath}) {
		t.Error("the host TPM grant differs between the backend request and the " +
			"command line")
	}
	if *backend.StopTimeout != effectiveStopTimeout(launch) {
		t.Error("the stop timeout differs between the backend request and the " +
			"generated service")
	}

	// Both projections carry the declared limits: the backend as the quantities
	// the runtime applies, the command line as the values podman parses.
	if backend.Resources == nil {
		t.Fatal("the backend received no resource limits for a spec that declared them")
	}
	if !containsSequence(args, []string{"--memory", launch.Resources.MemoryLimit}) {
		t.Error("the command line does not apply the declared memory limit")
	}
	if !containsSequence(args, []string{"--cpus", launch.Resources.CPULimit}) {
		t.Error("the command line does not apply the declared CPU limit")
	}

	// Ports and mounts are rendered from the same values the backend receives.
	for _, port := range backend.Ports {
		want := formatPodmanPort(PodmanPort{
			HostIP:        port.HostIP,
			HostPort:      port.HostPort,
			ContainerPort: port.ContainerPort,
			Protocol:      port.Protocol,
		})
		if !containsSequence(args, []string{"-p", want}) {
			t.Errorf("the command line does not publish the backend's port %q", want)
		}
	}
	for _, capability := range backend.CapAdd {
		if !containsSequence(args, []string{"--cap-add", capability}) {
			t.Errorf("the command line does not grant the backend's capability %q", capability)
		}
	}
	for _, capability := range backend.CapDrop {
		if !containsSequence(args, []string{"--cap-drop", capability}) {
			t.Errorf("the command line does not drop the backend's capability %q", capability)
		}
	}
}

// TestGeneratorsRenderTheSameLaunchCommand pins both generators to the single
// rendering of the launch artifact. A generator that walked the specification
// again — which is how the standalone paths diverged — cannot produce these
// strings.
func TestGeneratorsRenderTheSameLaunchCommand(t *testing.T) {
	t.Parallel()

	spec := standaloneSpec()
	launch := newLaunchConfig(spec)
	args := podmanRunArgs(launch)

	t.Run("the systemd unit runs the launch arguments verbatim", func(t *testing.T) {
		t.Parallel()

		unit := NewSystemdGenerator().Generate(spec)
		want := "ExecStart=" + systemdExecCommand("/usr/bin/podman",
			append([]string{"run"}, args...)) + "\n"
		if !strings.Contains(unit, want) {
			t.Errorf("the unit's ExecStart is not the launch configuration's "+
				"command line.\nwant: %s\nunit:\n%s", want, unit)
		}
	})

	t.Run("the rc script runs the launch arguments verbatim", func(t *testing.T) {
		t.Parallel()

		script := NewRCGenerator().Generate(spec)
		want := "${podman} run -d " + shellCommand(args) + "\n"
		if !strings.Contains(script, want) {
			t.Errorf("the rc script's run command is not the launch "+
				"configuration's command line.\nwant: %s\nscript:\n%s", want, script)
		}
	})

	// Both supervisors are handed the same argument vector, so the only
	// difference between them is supervision.
	// A device profile's ContainerConfig reaches the same derivation through
	// ToOrchestratorContainerSpec, so both entry points launch one value.
	// ContainerConfig carries no User or WorkingDir field, so a profile-defined
	// container simply has neither — measured and launched alike.
	t.Run("a device profile's container config runs the same derivation", func(t *testing.T) {
		t.Parallel()

		profileConfig := &ContainerConfig{
			Name:         spec.Name,
			Image:        spec.Image,
			Command:      spec.Command,
			Args:         spec.Args,
			Env:          spec.Env,
			Mounts:       spec.Mounts,
			Resources:    spec.Resources,
			Network:      spec.Network,
			Service:      spec.Service,
			Labels:       spec.Labels,
			Privileged:   spec.Privileged,
			Capabilities: spec.Capabilities,
			Ports:        spec.Ports,
			TPMAccess:    spec.TPMAccess,
		}
		derived := profileConfig.ToOrchestratorContainerSpec()

		want := podmanRunArgs(newLaunchConfig(derived))
		unit := NewSystemdGenerator().GenerateFromContainerConfig(profileConfig)
		if !strings.Contains(unit, systemdExecCommand("/usr/bin/podman", append([]string{"run"}, want...))) {
			t.Errorf("the unit generated from a device profile is not the profile's "+
				"single derivation.\nwant: %v\nunit:\n%s", want, unit)
		}

		script := NewRCGenerator().GenerateFromContainerConfig(profileConfig)
		if !strings.Contains(script, "${podman} run -d "+shellCommand(want)) {
			t.Errorf("the rc script generated from a device profile is not the "+
				"profile's single derivation.\nwant: %v\nscript:\n%s", want, script)
		}

		// The container the profile describes is the container it measures.
		if !reflect.DeepEqual(newLaunchConfig(derived), newLaunchConfig(derived)) {
			t.Error("the derivation is not a function of the specification")
		}
	})
}

// TestPodmanRunArgs_Determinism covers the two properties a generated file
// needs: a nil configuration renders nothing, and equal configurations render
// byte-identical command lines however their maps are ordered.
func TestPodmanRunArgs_Determinism(t *testing.T) {
	t.Parallel()

	t.Run("no launch configuration renders no command", func(t *testing.T) {
		t.Parallel()
		if args := podmanRunArgs(nil); args != nil {
			t.Errorf("podmanRunArgs(nil) = %v, want nil", args)
		}
	})

	t.Run("maps are rendered in a stable order", func(t *testing.T) {
		t.Parallel()

		spec := &OrchestratorContainerSpec{
			Name:  "stable",
			Image: "alpine:latest",
			Env: map[string]string{
				"ZULU": "z", "ALPHA": "a", "MIKE": "m", "BRAVO": "b",
			},
			Labels: map[string]string{
				"zone": "z", "app": "a", "tier": "t",
			},
			Capabilities: CapabilityConfig{Add: []string{"SYS_TIME", "NET_ADMIN"}},
		}

		first := strings.Join(podmanRunArgs(newLaunchConfig(spec)), " ")
		for i := 0; i < 16; i++ {
			if got := strings.Join(podmanRunArgs(newLaunchConfig(spec)), " "); got != first {
				t.Fatalf("rendering is not deterministic:\n%s\n%s", first, got)
			}
		}
		if !strings.Contains(first, "-e ALPHA=a -e BRAVO=b -e MIKE=m -e ZULU=z") {
			t.Errorf("environment is not rendered in sorted key order: %s", first)
		}
		if !strings.Contains(first, "--label app=a --label tier=t --label zone=z") {
			t.Errorf("labels are not rendered in sorted key order: %s", first)
		}
		if !strings.Contains(first, "--cap-add NET_ADMIN --cap-add SYS_TIME") {
			t.Errorf("capabilities are not rendered in sorted order: %s", first)
		}
	})
}

// TestSystemdExecArg covers the escaping a systemd Exec* directive needs, in
// both the ordinary and the hostile case: systemd splits the directive on
// whitespace and expands "%" specifiers and "$" variables, so an argument
// carrying any of them must survive as the value that was measured.
func TestSystemdExecArg(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"plain":            "plain",
		"APP_ENV=prod":     "APP_ENV=prod",
		"/host/data:/data": "/host/data:/data",
		"with space":       `"with space"`,
		`with"quote`:       `"with\"quote"`,
		`with\backslash`:   `"with\\backslash"`,
		"with'quote":       `"with'quote"`,
		"100%":             "100%%",
		"$HOME":            "$$HOME",
		"a b%c$d":          `"a b%%c$$d"`,
		"":                 `""`,
	}

	for input, want := range tests {
		if got := systemdExecArg(input); got != want {
			t.Errorf("systemdExecArg(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestShellArg covers the quoting a POSIX shell command word needs. The old
// scheme placed backslash-escaped double quotes inside a variable the script
// then expanded unquoted; word splitting does not remove quotes, so podman
// received arguments containing literal quote characters.
func TestShellArg(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"plain":            "plain",
		"APP_ENV=prod":     "APP_ENV=prod",
		"/host/data:/data": "/host/data:/data",
		"8080:80/tcp":      "8080:80/tcp",
		"with space":       `'with space'`,
		"$HOME":            `'$HOME'`,
		"`id`":             "'`id`'",
		`"quoted"`:         `'"quoted"'`,
		"it's":             `'it'\''s'`,
		";rm -rf /":        `';rm -rf /'`,
		"":                 "''",
	}

	for input, want := range tests {
		if got := shellArg(input); got != want {
			t.Errorf("shellArg(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestStandaloneCommandCarriesHostileValues proves a value that would break
// out of the generated file cannot: the container receives it verbatim.
func TestStandaloneCommandCarriesHostileValues(t *testing.T) {
	t.Parallel()

	spec := &OrchestratorContainerSpec{
		Name:  "hostile",
		Image: "alpine:latest",
		Env: map[string]string{
			"MESSAGE": "a b; rm -rf / $(id) `id` 100%",
		},
	}

	value := "MESSAGE=a b; rm -rf / $(id) `id` 100%"

	unit := NewSystemdGenerator().Generate(spec)
	if !strings.Contains(unit, systemdExecArg(value)) {
		t.Errorf("the unit does not carry the environment value safely:\n%s", unit)
	}
	if strings.Contains(unit, "ExecStart=/usr/bin/podman run -e MESSAGE=a b;") {
		t.Error("the unit would hand podman a truncated environment value")
	}

	script := NewRCGenerator().Generate(spec)
	if !strings.Contains(script, shellArg(value)) {
		t.Errorf("the rc script does not carry the environment value safely:\n%s", script)
	}
}

// TestGenerators_NoSpecification covers the invalid input both generators must
// survive: with nothing to derive a launch configuration from there is no
// service to write, and neither generator may dereference its way to a panic.
func TestGenerators_NoSpecification(t *testing.T) {
	t.Parallel()

	if unit := NewSystemdGenerator().Generate(nil); unit != "" {
		t.Errorf("Generate(nil) = %q, want an empty unit", unit)
	}
	if unit := NewSystemdGenerator().GenerateFromContainerConfig(nil); unit != "" {
		t.Errorf("GenerateFromContainerConfig(nil) = %q, want an empty unit", unit)
	}
	if script := NewRCGenerator().Generate(nil); script != "" {
		t.Errorf("Generate(nil) = %q, want an empty script", script)
	}
	if script := NewRCGenerator().GenerateFromContainerConfig(nil); script != "" {
		t.Errorf("GenerateFromContainerConfig(nil) = %q, want an empty script", script)
	}
}
