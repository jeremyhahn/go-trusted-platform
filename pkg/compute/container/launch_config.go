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

package container

import (
	"strconv"
	"strings"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
)

// The launched configuration and the measured configuration are ONE value.
//
// A container's effective launch configuration — every mount, every device,
// every flag — is derived exactly once, by newLaunchConfig, into a
// *PodmanContainerConfig. That single value is what the backend receives and
// it is the only input to the measurement: AttestationSpec projects it onto
// the go-quicbaas SDK container spec that orchestration.ContainerConfigDigest
// hashes. Orchestrator.measureCreate is handed the launch configuration and
// never sees the OrchestratorContainerSpec, so the measurement path cannot
// reach a field the launch path did not derive.
//
// This replaces two independent derivations of the same thing. Previously the
// launch path appended a /dev/tpm0 bind mount for a spec with TPMAccess set
// while the measurement path mapped only spec.Mounts, so two specs differing
// only by TPMAccess measured identically and one of them received the host
// root of trust. That was one instance of a class: any field wired into the
// launch derivation but not the measurement derivation escaped measurement
// silently. There is now nothing to keep in step.
//
// The remaining risk is not divergence but omission: a field added to
// PodmanContainerConfig and used by the backend, yet dropped by
// AttestationSpec. That is what TestLaunchConfig_MeasurementCoverage pins —
// it enumerates every field of the launch configuration by reflection and
// fails until the new one is classified as measured or as a stated,
// justified gap.

// newLaunchConfig derives a container's effective launch configuration from
// its specification.
//
// It is the single derivation: the only function that reads an
// OrchestratorContainerSpec in order to run a container, and therefore the
// only place a field can enter the launched configuration. Whatever it puts
// on the returned value is measured by AttestationSpec, and whatever it
// leaves off cannot reach the container.
//
// Two derived properties are worth naming:
//
// Command and Args are concatenated into the single argv the container
// executes, because that is what the backend receives. Two specs that differ
// only in where the command stops and the arguments start launch the same
// process and therefore measure identically — which is correct, in the same
// way the container name is excluded as a per-instance identifier.
//
// TPMAccess is expressed as a /dev/tpm0 bind mount and nowhere else. The
// mount list is measured, so the host TPM cannot be handed to a container
// without changing its configuration digest. There is deliberately no
// separate TPM flag on the launch configuration to forget to measure: the
// backend recognizes the grant from the mount itself
// (PodmanContainerConfig.GrantsTPMDevice).
func newLaunchConfig(spec *OrchestratorContainerSpec) *PodmanContainerConfig {
	if spec == nil {
		return nil
	}

	config := &PodmanContainerConfig{
		Name:        spec.Name,
		Image:       spec.Image,
		Environment: spec.Env,
		Labels:      spec.Labels,
		User:        spec.User,
		WorkDir:     spec.WorkingDir,
		Privileged:  spec.Privileged,
		CapAdd:      spec.Capabilities.Add,
		CapDrop:     spec.Capabilities.Drop,
		DNS:         spec.Network.DNSServers,
		DNSSearch:   spec.Network.DNSSearch,
		Hostname:    spec.Network.Hostname,
		NetworkMode: spec.Network.GetNetworkMode().String(),
		Resources:   spec.Resources,
	}

	// The container's argv is the command followed by its arguments.
	if len(spec.Command) > 0 || len(spec.Args) > 0 {
		config.Command = make([]string, 0, len(spec.Command)+len(spec.Args))
		config.Command = append(config.Command, spec.Command...)
		config.Command = append(config.Command, spec.Args...)
	}

	// Mounts keep declaration order, which is significant to the runtime and
	// to the digest. Device passthrough is appended last so the effective
	// mount list ends with what the spec's flags imply.
	config.Mounts = make([]PodmanMount, 0, len(spec.Mounts)+1)
	for _, m := range spec.Mounts {
		config.Mounts = append(config.Mounts, PodmanMount{
			Source:   m.Source,
			Target:   m.Target,
			Type:     string(m.Type),
			ReadOnly: m.ReadOnly,
		})
	}
	if spec.TPMAccess {
		config.Mounts = append(config.Mounts, PodmanMount{
			Source: HostTPMDevicePath,
			Target: HostTPMDevicePath,
			Type:   string(MountTypeBind),
		})
	}

	config.Ports = make([]PodmanPort, 0, len(spec.Ports))
	for _, p := range spec.Ports {
		config.Ports = append(config.Ports, PodmanPort{
			HostIP:        p.HostIP,
			HostPort:      p.HostPort,
			ContainerPort: p.ContainerPort,
			Protocol:      p.Protocol,
		})
	}

	return config
}

// GrantsTPMDevice reports whether the effective launch configuration exposes
// the host TPM character device to the container.
//
// The grant has exactly one representation — a mount of HostTPMDevicePath —
// and that representation is measured. Deriving the backend's device-node
// request from it, rather than carrying a parallel boolean, is what makes it
// impossible to grant the platform's root of trust without changing the
// container's configuration digest.
func (c *PodmanContainerConfig) GrantsTPMDevice() bool {
	if c == nil {
		return false
	}
	for _, m := range c.Mounts {
		if m.grantsTPMDevice() {
			return true
		}
	}
	return false
}

// grantsTPMDevice reports whether this single mount is the host TPM grant.
//
// It is the one predicate that recognizes the grant, shared by the backend
// request (GrantsTPMDevice) and by the command line a generated service runs
// (PodmanMount.runArgs), so no launch path can disagree with the measurement
// about which mount is the platform's root of trust.
func (m PodmanMount) grantsTPMDevice() bool {
	return m.Source == HostTPMDevicePath || m.Target == HostTPMDevicePath
}

// AttestationSpec projects the effective launch configuration onto the
// go-quicbaas SDK container spec that orchestration.ContainerConfigDigest
// measures. The returned spec is for measurement only; it is never launched.
//
// Its input is the value handed to the backend, so every field the launcher
// derived is in scope here. Each one either maps to a real SDK field and is
// hashed, or is a stated measurement gap:
//
//   - Hostname is a gap. The container really receives it (it becomes the
//     OCI process hostname), but the SDK spec has no field for it. Closing
//     the gap needs orchestration.ContainerSpec.Hostname upstream.
//   - DNS and DNSSearch are gaps for the same reason: no
//     orchestration.ContainerSpec.DNS / .DNSSearch upstream. They are also
//     dropped at the podman adapter today, so they reach nothing.
//   - PodmanMount.Options is a gap; mount propagation rides in it and there
//     is no orchestration.ContainerMount.Propagation upstream.
//   - ReadOnly (read-only rootfs) is a gap; no
//     orchestration.ContainerSpec.ReadOnlyRootFS upstream. Nothing sets it.
//   - StopTimeout is deliberately unmeasured: it bounds how long a stop
//     waits, which is availability, not what runs or what it can reach.
//   - Resources is deliberately unmeasured for the same reason: CPU, memory and
//     process limits bound what a workload may consume, and cannot change what
//     it runs or what it can reach. Unlike the gaps above this is a decision
//     rather than a missing upstream field, so it is not closed by adding one.
//     The limits ARE applied by every launch path, so no supervisor runs a
//     differently constrained container than another.
//
// Name is carried for diagnostics but excluded from the digest by the SDK, as
// a per-instance identifier: two identically configured containers with
// different names measure identically.
//
// A gap is closed by adding the field to orchestration.ContainerSpec and its
// ContainerConfigDigest upstream — never by smuggling it through a label.
func (c *PodmanContainerConfig) AttestationSpec() *orchestration.ContainerSpec {
	if c == nil {
		return nil
	}

	mounts := make([]orchestration.ContainerMount, 0, len(c.Mounts))
	for _, m := range c.Mounts {
		mounts = append(mounts, orchestration.ContainerMount{
			Source:   m.Source,
			Target:   m.Target,
			ReadOnly: m.ReadOnly,
			Type:     m.Type,
		})
	}

	ports := make([]string, 0, len(c.Ports))
	for _, p := range c.Ports {
		ports = append(ports, formatPodmanPort(p))
	}

	return &orchestration.ContainerSpec{
		Name:       c.Name,
		Image:      c.Image,
		Env:        c.Environment,
		Mounts:     mounts,
		Ports:      ports,
		WorkDir:    c.WorkDir,
		Entrypoint: c.Entrypoint,
		Command:    c.Command,
		Labels:     c.Labels,
		AutoRemove: c.AutoRemove,
		Network:    c.NetworkMode,
		User:       c.User,
		Privileged: c.Privileged,
		CapAdd:     c.CapAdd,
		CapDrop:    c.CapDrop,
	}
}

// formatPodmanPort renders a port mapping in the canonical
// "[hostIP:]hostPort:containerPort[/protocol]" form the SDK spec carries, so
// the mapping is measured exactly as the backend receives it.
func formatPodmanPort(p PodmanPort) string {
	var b strings.Builder
	if p.HostIP != "" {
		b.WriteString(p.HostIP)
		b.WriteByte(':')
	}
	b.WriteString(strconv.FormatUint(uint64(p.HostPort), 10))
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(p.ContainerPort), 10))
	if p.Protocol != "" {
		b.WriteByte('/')
		b.WriteString(p.Protocol)
	}
	return b.String()
}
