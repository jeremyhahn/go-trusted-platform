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
	"time"

	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// formatContainerState formats a ContainerState to a human-readable string
func formatContainerState(state computesvc.ContainerState) string {
	return string(state)
}

// formatTimestamp formats a time.Time for display
func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return "N/A"
	}
	return ts.UTC().Format(time.RFC3339)
}

// formatDuration formats a duration for display
func formatDuration(seconds uint32) string {
	d := time.Duration(seconds) * time.Second
	if d < time.Minute {
		return d.String()
	}
	if d < time.Hour {
		return d.Round(time.Second).String()
	}
	hours := d / time.Hour
	minutes := (d % time.Hour) / time.Minute
	return strconv.FormatInt(int64(hours), 10) + "h" + strconv.FormatInt(int64(minutes), 10) + "m"
}

// formatBytes formats byte count for human-readable display
func formatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/TB, 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/GB, 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/MB, 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/KB, 'f', 2, 64) + " KB"
	default:
		return strconv.FormatUint(bytes, 10) + " B"
	}
}

// formatBool formats a boolean for display
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// parseEnvVar parses an environment variable specification (KEY=value)
func parseEnvVar(spec string) (*computesvc.EnvVar, error) {
	parts := strings.SplitN(spec, "=", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidEnvVar{Spec: spec}
	}
	return &computesvc.EnvVar{
		Name:  parts[0],
		Value: parts[1],
	}, nil
}

// parseEnvVars parses multiple environment variable specifications
func parseEnvVars(specs []string) ([]*computesvc.EnvVar, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	envVars := make([]*computesvc.EnvVar, 0, len(specs))
	for _, spec := range specs {
		envVar, err := parseEnvVar(spec)
		if err != nil {
			return nil, err
		}
		envVars = append(envVars, envVar)
	}
	return envVars, nil
}

// parseLabel parses a label specification (key=value)
func parseLabel(spec string) (string, string, error) {
	parts := strings.SplitN(spec, "=", 2)
	if len(parts) != 2 {
		return "", "", ErrInvalidLabel{Spec: spec}
	}
	return parts[0], parts[1], nil
}

// parseLabels parses multiple label specifications
func parseLabels(specs []string) (map[string]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	labels := make(map[string]string, len(specs))
	for _, spec := range specs {
		key, value, err := parseLabel(spec)
		if err != nil {
			return nil, err
		}
		labels[key] = value
	}
	return labels, nil
}

// parsePortMapping parses a port mapping specification (hostPort:containerPort[/protocol])
func parsePortMapping(spec string) (*computesvc.PortMapping, error) {
	// Parse protocol if specified
	protocol := "tcp"
	protocolParts := strings.SplitN(spec, "/", 2)
	if len(protocolParts) == 2 {
		spec = protocolParts[0]
		protocol = strings.ToLower(protocolParts[1])
	}

	// Parse ports
	parts := strings.SplitN(spec, ":", 2)
	if len(parts) != 2 {
		return nil, ErrInvalidPortMapping{Mapping: spec}
	}

	hostPort, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, ErrInvalidPortMapping{Mapping: spec}
	}

	containerPort, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, ErrInvalidPortMapping{Mapping: spec}
	}

	return &computesvc.PortMapping{
		HostPort:      uint32(hostPort),
		ContainerPort: uint32(containerPort),
		Protocol:      protocol,
	}, nil
}

// parsePortMappings parses multiple port mapping specifications
func parsePortMappings(specs []string) ([]*computesvc.PortMapping, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	mappings := make([]*computesvc.PortMapping, 0, len(specs))
	for _, spec := range specs {
		mapping, err := parsePortMapping(spec)
		if err != nil {
			return nil, err
		}
		mappings = append(mappings, mapping)
	}
	return mappings, nil
}

// parseMountSpec parses a mount specification (hostPath:containerPath[:ro])
func parseMountSpec(spec string) (*computesvc.VolumeMount, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, ErrInvalidMountSpec{Spec: spec}
	}

	mount := &computesvc.VolumeMount{
		Source:      parts[0],
		Destination: parts[1],
		Readonly:    false,
	}

	if len(parts) == 3 {
		if parts[2] == "ro" || parts[2] == "readonly" {
			mount.Readonly = true
		}
	}

	return mount, nil
}

// parseMountSpecs parses multiple mount specifications
func parseMountSpecs(specs []string) ([]*computesvc.VolumeMount, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	mounts := make([]*computesvc.VolumeMount, 0, len(specs))
	for _, spec := range specs {
		mount, err := parseMountSpec(spec)
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, mount)
	}
	return mounts, nil
}

// parseMemory parses a memory specification (e.g., 512m, 1g)
func parseMemory(spec string) (uint64, error) {
	if spec == "" {
		return 0, nil
	}

	spec = strings.ToLower(strings.TrimSpace(spec))
	if len(spec) < 2 {
		return 0, ErrInvalidMemorySpec{Spec: spec}
	}

	suffix := spec[len(spec)-1:]
	valueStr := spec[:len(spec)-1]

	value, err := strconv.ParseUint(valueStr, 10, 64)
	if err != nil {
		return 0, ErrInvalidMemorySpec{Spec: spec}
	}

	switch suffix {
	case "b":
		return value / (1024 * 1024), nil // Convert to MB
	case "k":
		return value / 1024, nil // Convert KB to MB
	case "m":
		return value, nil // Already in MB
	case "g":
		return value * 1024, nil // Convert GB to MB
	case "t":
		return value * 1024 * 1024, nil // Convert TB to MB
	default:
		return 0, ErrInvalidMemorySpec{Spec: spec}
	}
}

// parseCPU parses a CPU specification (e.g., 0.5, 1, 2)
func parseCPU(spec string) (float64, error) {
	if spec == "" {
		return 0, nil
	}

	value, err := strconv.ParseFloat(strings.TrimSpace(spec), 64)
	if err != nil {
		return 0, ErrInvalidCPUSpec{Spec: spec}
	}

	if value < 0 {
		return 0, ErrInvalidCPUSpec{Spec: spec}
	}

	return value, nil
}

// parseContainerState parses a container state string to a domain ContainerState
func parseContainerState(state string) (computesvc.ContainerState, bool) {
	return computesvc.ParseContainerState(state)
}

// truncateID truncates a container ID for display
func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
