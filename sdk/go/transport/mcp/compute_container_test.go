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

package mcp

import (
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// CreateContainer calls container_create with the flat arguments the tool
// documents: the name and image at the top level, never under "config".
func TestCreateContainerCallsContainerCreateWithFlatArguments(t *testing.T) {
	tests := []struct {
		name   string
		config *platformv1.ContainerConfig
		args   map[string]interface{}
	}{
		{"basic",
			&platformv1.ContainerConfig{Name: "web", Image: "alpine:latest"},
			map[string]interface{}{"name": "web", "image": "alpine:latest"}},
		{"environment",
			&platformv1.ContainerConfig{Name: "web", Image: "alpine:latest",
				Env: []*platformv1.EnvVar{{Name: "MODE", Value: "test"}, {Name: "LEVEL", Value: "debug"}}},
			map[string]interface{}{"name": "web", "image": "alpine:latest",
				"env": map[string]interface{}{"MODE": "test", "LEVEL": "debug"}}},
		{"command",
			&platformv1.ContainerConfig{Name: "web", Image: "alpine:latest",
				Command: []string{"sh", "-c"}, Args: []string{"sleep 60"}},
			map[string]interface{}{"name": "web", "image": "alpine:latest",
				"command": []interface{}{"sh", "-c"}, "args": []interface{}{"sleep 60"}}},
		{"every documented field",
			&platformv1.ContainerConfig{Name: "web", Image: "alpine:latest",
				Labels: map[string]string{"tier": "edge"}, WorkingDir: "/srv", User: "nobody", Privileged: true,
				Volumes:   []*platformv1.VolumeMount{{Source: "/data", Destination: "/mnt", Readonly: true, Type: "bind"}},
				Ports:     []*platformv1.PortMapping{{ContainerPort: 80, HostPort: 8080, HostIp: "127.0.0.1", Protocol: "tcp"}},
				Resources: &platformv1.ResourceLimits{MaxCpus: 2, MaxMemoryMb: 512}},
			map[string]interface{}{"name": "web", "image": "alpine:latest",
				"labels": map[string]interface{}{"tier": "edge"}, "working_dir": "/srv", "user": "nobody",
				"privileged": true,
				"mounts": []interface{}{map[string]interface{}{
					"source": "/data", "target": "/mnt", "read_only": true, "type": "bind"}},
				"ports": []interface{}{map[string]interface{}{
					"container_port": float64(80), "host_port": float64(8080), "host_ip": "127.0.0.1", "protocol": "tcp"}},
				"resources": map[string]interface{}{"cpu_limit": "2", "memory_limit": "512M"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results := map[string]interface{}{
				"container_create": map[string]interface{}{"container": map[string]interface{}{"id": "c-1"}},
			}
			calls, err := invokePhase35(t, results, platformv1.ComputeService_CreateContainer_FullMethodName,
				&platformv1.CreateContainerRequest{Config: tt.config}, &platformv1.CreateContainerResponse{})
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if len(calls) != 1 || calls[0].Name != "container_create" {
				t.Fatalf("calls = %+v, want one container_create call", calls)
			}
			if !reflect.DeepEqual(calls[0].Arguments, tt.args) {
				t.Errorf("arguments = %v, want %v", calls[0].Arguments, tt.args)
			}
		})
	}
}

func TestContainerCreateArgsRejectsANonCreateRequest(t *testing.T) {
	const method = platformv1.ComputeService_CreateContainer_FullMethodName
	for _, args := range []interface{}{"web", &platformv1.StartContainerRequest{Id: "web"}, (*platformv1.CreateContainerRequest)(nil)} {
		if _, err := containerCreateArgs(args); err != (ErrUnexpectedArgsType{Method: method}) {
			t.Errorf("containerCreateArgs(%T) err = %v, want ErrUnexpectedArgsType", args, err)
		}
	}
}
