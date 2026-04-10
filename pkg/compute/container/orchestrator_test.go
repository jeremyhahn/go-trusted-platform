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
	"testing"
	"time"
)

func TestContainerState_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state    ContainerState
		expected string
	}{
		{StateCreated, "created"},
		{StateRunning, "running"},
		{StateStopped, "stopped"},
		{StateRemoving, "removing"},
		{StatePaused, "paused"},
		{StateRestarting, "restarting"},
		{StateExited, "exited"},
		{StateDead, "dead"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("ContainerState.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestContainerState_IsValid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state ContainerState
		valid bool
	}{
		{"created", StateCreated, true},
		{"running", StateRunning, true},
		{"stopped", StateStopped, true},
		{"removing", StateRemoving, true},
		{"paused", StatePaused, true},
		{"restarting", StateRestarting, true},
		{"exited", StateExited, true},
		{"dead", StateDead, true},
		{"empty", ContainerState(""), false},
		{"invalid", ContainerState("invalid"), false},
		{"unknown", ContainerState("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.state.IsValid(); got != tt.valid {
				t.Errorf("ContainerState.IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestContainerState_IsRunning(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state     ContainerState
		isRunning bool
	}{
		{StateCreated, false},
		{StateRunning, true},
		{StateStopped, false},
		{StateRemoving, false},
		{StatePaused, false},
		{StateRestarting, false},
		{StateExited, false},
		{StateDead, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			if got := tt.state.IsRunning(); got != tt.isRunning {
				t.Errorf("ContainerState.IsRunning() = %v, want %v", got, tt.isRunning)
			}
		})
	}
}

func TestContainerState_IsStopped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state     ContainerState
		isStopped bool
	}{
		{StateCreated, false},
		{StateRunning, false},
		{StateStopped, true},
		{StateRemoving, false},
		{StatePaused, false},
		{StateRestarting, false},
		{StateExited, true},
		{StateDead, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			t.Parallel()
			if got := tt.state.IsStopped(); got != tt.isStopped {
				t.Errorf("ContainerState.IsStopped() = %v, want %v", got, tt.isStopped)
			}
		})
	}
}

func TestContainer_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	container := &Container{
		ID:      "abc123",
		Name:    "test-container",
		Image:   "nginx:latest",
		ImageID: "sha256:abc123",
		State:   StateRunning,
		Spec: &OrchestratorContainerSpec{
			Name:  "test-container",
			Image: "nginx:latest",
		},
		CreatedAt:  now,
		StartedAt:  now,
		FinishedAt: time.Time{},
		ExitCode:   0,
		Pid:        12345,
		Labels:     map[string]string{"app": "test"},
		NetworkSettings: &NetworkSettings{
			IPAddress:  "172.17.0.2",
			Gateway:    "172.17.0.1",
			MACAddress: "02:42:ac:11:00:02",
		},
		Mounts: []MountInfo{
			{
				Source:      "/host/data",
				Destination: "/data",
				Mode:        "ro",
				RW:          false,
			},
		},
		Platform: "linux/amd64",
		Health: &HealthStatus{
			Status:        "healthy",
			FailingStreak: 0,
		},
	}

	if container.ID != "abc123" {
		t.Errorf("ID = %q, want %q", container.ID, "abc123")
	}
	if container.Name != "test-container" {
		t.Errorf("Name = %q, want %q", container.Name, "test-container")
	}
	if container.State != StateRunning {
		t.Errorf("State = %q, want %q", container.State, StateRunning)
	}
	if container.NetworkSettings.IPAddress != "172.17.0.2" {
		t.Errorf("IPAddress = %q, want %q", container.NetworkSettings.IPAddress, "172.17.0.2")
	}
}

func TestListOptions_Defaults(t *testing.T) {
	t.Parallel()

	opts := ListOptions{}

	if opts.All {
		t.Error("Default All should be false")
	}
	if opts.Filters != nil {
		t.Error("Default Filters should be nil")
	}
	if opts.Limit != 0 {
		t.Error("Default Limit should be 0")
	}
}

func TestLogOptions_Defaults(t *testing.T) {
	t.Parallel()

	opts := LogOptions{}

	if opts.Follow {
		t.Error("Default Follow should be false")
	}
	if opts.Stdout {
		t.Error("Default Stdout should be false")
	}
	if opts.Stderr {
		t.Error("Default Stderr should be false")
	}
	if opts.Timestamps {
		t.Error("Default Timestamps should be false")
	}
}

func TestPullOptions_Defaults(t *testing.T) {
	t.Parallel()

	opts := PullOptions{}

	if opts.VerifySignature {
		t.Error("Default VerifySignature should be false")
	}
	if opts.RegistryAuth != "" {
		t.Error("Default RegistryAuth should be empty")
	}
	if opts.Platform != "" {
		t.Error("Default Platform should be empty")
	}
}

func TestAttestationReport_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	report := &AttestationReport{
		ContainerID:   "abc123",
		ContainerName: "test",
		Timestamp:     now,
		Quote:         []byte{0x01, 0x02, 0x03},
		Signature:     []byte{0x04, 0x05, 0x06},
		Log: &MeasurementLog{
			Entries: []MeasurementEntry{
				{
					ContainerID:    "abc123",
					Timestamp:      now,
					EventType:      EventContainerCreate,
					ImageDigest:    []byte{0x07, 0x08},
					ConfigDigest:   []byte{0x09, 0x0a},
					CumulativeHash: []byte{0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a},
				},
			},
		},
		ImageDigest:    []byte{0x07, 0x08},
		ConfigDigest:   []byte{0x09, 0x0a},
		PCRValues:      map[int][]byte{14: {0x0d, 0x0e}},
		AIKCertificate: []byte{0x0f, 0x10},
		Verified:       true,
	}

	if report.ContainerID != "abc123" {
		t.Errorf("ContainerID = %q, want %q", report.ContainerID, "abc123")
	}
	if !report.Verified {
		t.Error("Verified should be true")
	}
	if len(report.Log.Entries) != 1 {
		t.Errorf("MeasurementLog.Len() = %d, want 1", len(report.Log.Entries))
	}
}

func TestPolicyDecision_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	decision := &PolicyDecision{
		Allowed:    false,
		Reasons:    []string{"image not signed", "privileged not allowed"},
		Warnings:   []string{"using deprecated API"},
		PolicyName: "container.security",
		Timestamp:  now,
		Input:      map[string]interface{}{"container": "test"},
	}

	if decision.Allowed {
		t.Error("Allowed should be false")
	}
	if len(decision.Reasons) != 2 {
		t.Errorf("Reasons length = %d, want 2", len(decision.Reasons))
	}
	if len(decision.Warnings) != 1 {
		t.Errorf("Warnings length = %d, want 1", len(decision.Warnings))
	}
}

func TestImageVerification_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	verification := &ImageVerification{
		ImageRef:         "registry.example.com/app:v1",
		Digest:           "sha256:abc123",
		Verified:         true,
		Signer:           "platform-ca",
		SignatureType:    "cosign",
		Timestamp:        now,
		Certificate:      []byte{0x01, 0x02},
		SignaturePayload: []byte{0x03, 0x04},
		Annotations:      map[string]string{"signed-by": "ci"},
	}

	if verification.ImageRef != "registry.example.com/app:v1" {
		t.Errorf("ImageRef = %q, want %q", verification.ImageRef, "registry.example.com/app:v1")
	}
	if !verification.Verified {
		t.Error("Verified should be true")
	}
	if verification.SignatureType != "cosign" {
		t.Errorf("SignatureType = %q, want %q", verification.SignatureType, "cosign")
	}
}

func TestPolicyInput_Fields(t *testing.T) {
	t.Parallel()

	input := &PolicyInput{
		Container: &OrchestratorContainerSpec{
			Name:  "test",
			Image: "nginx:latest",
		},
		Image: &ImageInfo{
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "latest",
		},
		Signature: &SignatureInfo{
			Verified: true,
			Signer:   "platform-ca",
		},
		Network: &ContainerNetworkConfig{
			Mode: NetworkModeBridge,
		},
		Attestation: &AttestationState{
			Attested: true,
		},
		User:      "admin",
		Groups:    []string{"admins", "developers"},
		Namespace: "production",
	}

	if input.Container.Name != "test" {
		t.Errorf("Container.Name = %q, want %q", input.Container.Name, "test")
	}
	if input.Image.Registry != "docker.io" {
		t.Errorf("Image.Registry = %q, want %q", input.Image.Registry, "docker.io")
	}
	if !input.Signature.Verified {
		t.Error("Signature.Verified should be true")
	}
	if len(input.Groups) != 2 {
		t.Errorf("Groups length = %d, want 2", len(input.Groups))
	}
}

func TestNetworkSettings_Fields(t *testing.T) {
	t.Parallel()

	settings := &NetworkSettings{
		IPAddress:  "172.17.0.2",
		Gateway:    "172.17.0.1",
		MACAddress: "02:42:ac:11:00:02",
		Ports: map[string][]PortBinding{
			"80/tcp": {
				{HostIP: "0.0.0.0", HostPort: "8080"},
			},
		},
		Networks: map[string]*NetworkInfo{
			"bridge": {
				NetworkID: "abc123",
				IPAddress: "172.17.0.2",
				Gateway:   "172.17.0.1",
			},
		},
	}

	if settings.IPAddress != "172.17.0.2" {
		t.Errorf("IPAddress = %q, want %q", settings.IPAddress, "172.17.0.2")
	}
	if len(settings.Ports["80/tcp"]) != 1 {
		t.Errorf("Ports[80/tcp] length = %d, want 1", len(settings.Ports["80/tcp"]))
	}
	if settings.Networks["bridge"].IPAddress != "172.17.0.2" {
		t.Errorf("Networks[bridge].IPAddress = %q, want %q",
			settings.Networks["bridge"].IPAddress, "172.17.0.2")
	}
}

func TestHealthStatus_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	health := &HealthStatus{
		Status:        "healthy",
		FailingStreak: 0,
		Log: []HealthLog{
			{
				Start:    now.Add(-time.Minute),
				End:      now,
				ExitCode: 0,
				Output:   "OK",
			},
		},
	}

	if health.Status != "healthy" {
		t.Errorf("Status = %q, want %q", health.Status, "healthy")
	}
	if health.FailingStreak != 0 {
		t.Errorf("FailingStreak = %d, want 0", health.FailingStreak)
	}
	if len(health.Log) != 1 {
		t.Errorf("Log length = %d, want 1", len(health.Log))
	}
}

func TestMountInfo_Fields(t *testing.T) {
	t.Parallel()

	mount := MountInfo{
		Source:      "/host/data",
		Destination: "/data",
		Mode:        "ro",
		RW:          false,
		Propagation: "rprivate",
	}

	if mount.Source != "/host/data" {
		t.Errorf("Source = %q, want %q", mount.Source, "/host/data")
	}
	if mount.Destination != "/data" {
		t.Errorf("Destination = %q, want %q", mount.Destination, "/data")
	}
	if mount.RW {
		t.Error("RW should be false")
	}
}

func TestImageInfo_Fields(t *testing.T) {
	t.Parallel()

	info := &ImageInfo{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "latest",
		Digest:     "sha256:abc123",
		Labels: map[string]string{
			"maintainer": "NGINX Team",
		},
	}

	if info.Registry != "docker.io" {
		t.Errorf("Registry = %q, want %q", info.Registry, "docker.io")
	}
	if info.Repository != "library/nginx" {
		t.Errorf("Repository = %q, want %q", info.Repository, "library/nginx")
	}
	if info.Tag != "latest" {
		t.Errorf("Tag = %q, want %q", info.Tag, "latest")
	}
}

func TestSignatureInfo_Fields(t *testing.T) {
	t.Parallel()

	info := &SignatureInfo{
		Verified: true,
		Signer:   "platform-ca",
		Issuer:   "Trusted Platform CA",
	}

	if !info.Verified {
		t.Error("Verified should be true")
	}
	if info.Signer != "platform-ca" {
		t.Errorf("Signer = %q, want %q", info.Signer, "platform-ca")
	}
}

func TestAttestationState_Fields(t *testing.T) {
	t.Parallel()

	now := time.Now()
	state := &AttestationState{
		Attested:     true,
		LastAttested: now,
		PCRValues: map[int][]byte{
			14: {0x01, 0x02},
		},
	}

	if !state.Attested {
		t.Error("Attested should be true")
	}
	if len(state.PCRValues) != 1 {
		t.Errorf("PCRValues length = %d, want 1", len(state.PCRValues))
	}
}
