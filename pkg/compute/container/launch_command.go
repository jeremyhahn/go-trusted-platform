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
	"sort"
	"strconv"
	"strings"
)

// The launched configuration and the measured configuration are ONE value, and
// a standalone service launches that value too.
//
// A container reaches a runtime by one of two supervisors: platformd itself,
// through the podman backend (see convertFromPodmanContainerConfig), or an init
// service, through a generated systemd unit or OpenRC script. Both start from
// the same *PodmanContainerConfig that newLaunchConfig derived and that
// AttestationSpec measured. podmanRunArgs is the only rendering of that value
// as a command line, so the two supervisors cannot disagree about what runs.
//
// This replaces a third derivation. Each generator used to walk the
// OrchestratorContainerSpec itself and build its own `podman run` line, which
// omitted capabilities, the user, the working directory, the argv tail, the
// hostname and the TPM device grant, and applied resource limits the backend
// never received. With Service.Mode: standalone the container systemd started
// was therefore not the container that had been measured — the measurement
// attested a configuration that never ran.
//
// The remaining risk is the same one the measurement side has: a field added to
// PodmanContainerConfig, passed to the backend, but not rendered here. That is
// what TestPodmanRunArgs_LaunchCoverage pins. It classifies every field as
// rendered or as inert, and an inert field must be proven inert by
// convertFromPodmanContainerConfig dropping it too — so wiring a field into the
// backend without rendering it into the unit fails the test.

// defaultStopTimeoutSeconds is the stop timeout every launch path applies when
// the launch configuration does not name one. It is shared so the backend, the
// systemd unit and the rc script cannot wait for different lengths of time.
const defaultStopTimeoutSeconds = 10

// cpuQuotaPeriodMicroseconds is the CFS scheduling period a fractional CPU
// limit is expressed against, which is both the kernel default and the period
// podman's --cpus uses.
const cpuQuotaPeriodMicroseconds = 100000

// podmanRunArgs renders a container's effective launch configuration as the
// argument vector that follows `podman run`.
//
// Every field of the launch configuration is either rendered here or is inert
// on every path — dropped by convertFromPodmanContainerConfig as well, so it
// reaches no container:
//
//   - Entrypoint is inert. The backend's ContainerConfig carries the field but
//     the embedded runtime never reads it, and no specification sets it, so
//     rendering --entrypoint would make a standalone container differ from the
//     embedded one. It is measured, which is harmless: measuring more than is
//     applied cannot let an unapproved container run.
//   - AutoRemove is inert for the same reason. The generated unit and script
//     remove the container explicitly around start and stop, so no container
//     is left behind by not rendering --rm.
//   - DNS and DNSSearch are inert: the podman adapter drops both.
//
// Resource limits ARE rendered, and the backend now applies them too. They are
// deliberately not measured (see AttestationSpec): a limit bounds what a
// workload may consume, which is availability, and cannot change what it runs
// or what it can reach. Rendering them on one path only, as the generators did,
// made two supervisors run measurably different containers from one digest.
func podmanRunArgs(c *PodmanContainerConfig) []string {
	if c == nil {
		return nil
	}

	args := make([]string, 0, 32)

	if c.Name != "" {
		args = append(args, "--name", c.Name)
	}

	// The init service invokes the same podman the platform's backend does, so
	// it is given the mode the backend resolves: an SDN container runs on the
	// runtime's bridge here exactly as it does under platformd, and the OVS
	// attachment remains the network manager's job.
	args = append(args, "--network", backendNetworkMode(c.NetworkMode))

	if c.User != "" {
		args = append(args, "--user", c.User)
	}
	if c.WorkDir != "" {
		args = append(args, "--workdir", c.WorkDir)
	}
	if c.Hostname != "" {
		args = append(args, "--hostname", c.Hostname)
	}
	if c.Privileged {
		args = append(args, "--privileged")
	}
	if c.ReadOnly {
		args = append(args, "--read-only")
	}

	args = append(args, "--stop-timeout", strconv.Itoa(effectiveStopTimeout(c)))

	// Capabilities are sorted, as both the configuration digest and the SDK's
	// own runtime sort them: if the orderings could differ, a container could
	// measure one way and launch another.
	for _, capability := range sortedCopy(c.CapAdd) {
		args = append(args, "--cap-add", capability)
	}
	for _, capability := range sortedCopy(c.CapDrop) {
		args = append(args, "--cap-drop", capability)
	}

	// Maps are rendered in sorted key order so the same launch configuration
	// always produces byte-identical unit content.
	for _, key := range sortedKeys(c.Environment) {
		args = append(args, "-e", key+"="+c.Environment[key])
	}
	for _, key := range sortedKeys(c.Labels) {
		args = append(args, "--label", key+"="+c.Labels[key])
	}

	// Mounts keep declaration order, which is significant to the runtime and to
	// the digest.
	for _, mount := range c.Mounts {
		args = append(args, mount.runArgs()...)
	}

	// Ports are rendered by the same formatter the measurement uses, so the
	// mapping that runs is the mapping that was hashed.
	for _, port := range c.Ports {
		args = append(args, "-p", formatPodmanPort(port))
	}

	args = append(args, resourceArgs(c.Resources)...)

	args = append(args, c.Image)
	args = append(args, c.Command...)

	return args
}

// effectiveStopTimeout returns the stop timeout in seconds the launch
// configuration resolves to. The backend applies the same default, so a
// generated service stops a container on the same schedule platformd does.
func effectiveStopTimeout(c *PodmanContainerConfig) int {
	if c != nil && c.StopTimeout != nil {
		return *c.StopTimeout
	}
	return defaultStopTimeoutSeconds
}

// runArgs renders one mount as the flags that materialize it.
//
// The host TPM grant becomes --device rather than a plain volume: podman's
// --device creates the character device in the container and permits access to
// it, which is what the embedded backend asks the OCI runtime for when
// GrantsTPMDevice reports the grant. A bind mount of the device node alone
// would appear in the container without the cgroup permission to use it, so the
// two supervisors would not be running the same container.
func (m PodmanMount) runArgs() []string {
	if m.grantsTPMDevice() {
		return []string{"--device", m.Source + ":" + m.Target}
	}

	// A mount that names its kind can only be expressed by --mount; the
	// untyped short form keeps -v, exactly as the go-quicbaas SDK renders the
	// same two shapes.
	if m.Type != "" {
		fields := make([]string, 0, 5)
		fields = append(fields, "type="+m.Type)
		if m.Source != "" {
			fields = append(fields, "source="+m.Source)
		}
		fields = append(fields, "destination="+m.Target)
		if m.ReadOnly {
			fields = append(fields, "readonly")
		}
		fields = append(fields, m.Options...)
		return []string{"--mount", strings.Join(fields, ",")}
	}

	spec := m.Source + ":" + m.Target
	if options := m.shortFormOptions(); len(options) > 0 {
		spec += ":" + strings.Join(options, ",")
	}
	return []string{"-v", spec}
}

// shortFormOptions returns the mount options in the order the embedded backend
// hands them to the OCI runtime: the declared options followed by the read-only
// marker.
func (m PodmanMount) shortFormOptions() []string {
	if !m.ReadOnly {
		return m.Options
	}
	options := make([]string, 0, len(m.Options)+1)
	options = append(options, m.Options...)
	return append(options, "ro")
}

// resourceArgs renders the declared resource limits as podman flags.
//
// The zero ResourceConfig renders nothing, so a container that declared no
// limits is launched without any — which is what the backend receives for it.
func resourceArgs(r ResourceConfig) []string {
	args := make([]string, 0, 12)
	if r.MemoryLimit != "" {
		args = append(args, "--memory", r.MemoryLimit)
	}
	if r.MemoryReservation != "" {
		args = append(args, "--memory-reservation", r.MemoryReservation)
	}
	if r.MemorySwap != "" {
		args = append(args, "--memory-swap", r.MemorySwap)
	}
	if r.CPULimit != "" {
		args = append(args, "--cpus", r.CPULimit)
	}
	if r.CPUShares > 0 {
		args = append(args, "--cpu-shares", strconv.FormatInt(r.CPUShares, 10))
	}
	if r.PidsLimit > 0 {
		args = append(args, "--pids-limit", strconv.FormatInt(r.PidsLimit, 10))
	}
	return args
}

// sortedCopy returns the values in sorted order without disturbing the caller's
// slice, which the launch configuration and the measurement share.
func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sorted := make([]string, len(values))
	copy(sorted, values)
	sort.Strings(sorted)
	return sorted
}

// sortedKeys returns a map's keys in sorted order.
func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// systemdExecCommand renders a podman invocation as the value of a systemd
// Exec* directive.
//
// systemd splits the directive on whitespace and interprets "%" as a specifier
// and "$" as a variable reference, so an argument carrying any of those must be
// quoted or escaped or the container would receive something other than the
// measured value.
func systemdExecCommand(podmanPath string, args []string) string {
	rendered := make([]string, 0, len(args)+1)
	rendered = append(rendered, systemdExecArg(podmanPath))
	for _, arg := range args {
		rendered = append(rendered, systemdExecArg(arg))
	}
	return strings.Join(rendered, " ")
}

// systemdExecArg renders one argument for a systemd Exec* directive.
func systemdExecArg(arg string) string {
	rendered := arg
	if arg == "" || strings.ContainsAny(arg, " \t\n\"'\\") {
		var b strings.Builder
		b.Grow(len(arg) + 2)
		b.WriteByte('"')
		for _, r := range arg {
			if r == '"' || r == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(r)
		}
		b.WriteByte('"')
		rendered = b.String()
	}

	// Both replacements apply inside quotes as well: systemd resolves
	// specifiers and variables after unquoting.
	rendered = strings.ReplaceAll(rendered, "%", "%%")
	return strings.ReplaceAll(rendered, "$", "$$")
}

// shellCommand renders a podman invocation as a POSIX shell command word list.
func shellCommand(args []string) string {
	rendered := make([]string, 0, len(args))
	for _, arg := range args {
		rendered = append(rendered, shellArg(arg))
	}
	return strings.Join(rendered, " ")
}

// shellArg renders one argument as a single POSIX shell word.
//
// An argument made only of characters no shell treats specially is emitted
// verbatim, which keeps generated scripts readable; anything else is
// single-quoted, the one quoting form that suppresses every expansion. This
// replaces an escaping scheme that placed backslash-escaped double quotes in a
// variable which the script then expanded unquoted: word splitting does not
// remove quotes, so podman received arguments with literal quote characters in
// them.
func shellArg(arg string) string {
	if arg == "" {
		return "''"
	}
	if isShellSafe(arg) {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// isShellSafe reports whether every character of s is one that no POSIX shell
// treats specially in an unquoted word.
func isShellSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("@%+=:,./-_", r):
		default:
			return false
		}
	}
	return true
}
