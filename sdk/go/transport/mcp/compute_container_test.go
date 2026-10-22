package mcp

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestCreateContainer_FlatToolArguments(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"container_create": daemonContainerResult("c-1", "web", "creating", map[string]interface{}{
			"success": true, "message": "Container created successfully",
		}),
	}, &calls)

	request := &platformv1.CreateContainerRequest{AttestOnCreate: true, Config: &platformv1.ContainerConfig{
		Name:       "web",
		Image:      "docker.io/library/nginx:1.27",
		Command:    []string{"nginx"},
		Args:       []string{"-g", "daemon off;"},
		Env:        []*platformv1.EnvVar{{Name: "MODE", Value: "prod"}},
		Labels:     map[string]string{"tier": "front"},
		WorkingDir: "/srv",
		User:       "nginx",
		Privileged: true,
		Volumes:    []*platformv1.VolumeMount{{Source: "/data", Destination: "/srv/data", Readonly: true, Type: "bind"}},
		Ports:      []*platformv1.PortMapping{{ContainerPort: 80, HostPort: 8080, HostIp: "127.0.0.1", Protocol: "tcp"}},
		Resources:  &platformv1.ResourceLimits{MaxCpus: 2, MaxMemoryMb: 512},
	}}
	response := &platformv1.CreateContainerResponse{}
	if err := a.Connection().Invoke(context.Background(), createContainerMethod, request, response); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "container_create" {
		t.Fatalf("calls = %+v, want single container_create", calls)
	}
	want := map[string]interface{}{
		"name":        "web",
		"image":       "docker.io/library/nginx:1.27",
		"command":     []interface{}{"nginx"},
		"args":        []interface{}{"-g", "daemon off;"},
		"env":         map[string]interface{}{"MODE": "prod"},
		"labels":      map[string]interface{}{"tier": "front"},
		"working_dir": "/srv",
		"user":        "nginx",
		"privileged":  true,
		"mounts": []interface{}{map[string]interface{}{
			"source": "/data", "target": "/srv/data", "read_only": true, "type": "bind",
		}},
		"ports": []interface{}{map[string]interface{}{
			"container_port": float64(80), "host_port": float64(8080), "host_ip": "127.0.0.1", "protocol": "tcp",
		}},
		"resources":        map[string]interface{}{"cpu_limit": "2", "memory_limit": "512M"},
		"attest_on_create": true,
	}
	if !reflect.DeepEqual(calls[0].Arguments, want) {
		t.Errorf("tool arguments = %v, want %v", calls[0].Arguments, want)
	}
	container := response.GetContainer()
	if container.GetId() != "c-1" || container.GetConfig().GetName() != "web" ||
		container.GetState() != platformv1.ContainerState_CONTAINER_STATE_CREATED {
		t.Errorf("container = %+v, want id c-1, name web, state CREATED", container)
	}
	if !container.GetCreatedAt().AsTime().Equal(daemonContainerCreatedAt) {
		t.Errorf("created_at = %v, want %v", container.GetCreatedAt().AsTime(), daemonContainerCreatedAt)
	}
	if !response.GetStatus().GetSuccess() || response.GetStatus().GetMessage() != "Container created successfully" {
		t.Errorf("status = %+v, want the daemon's success status", response.GetStatus())
	}
}

// daemonContainerCreatedAt is the creation time daemonContainerResult answers.
var daemonContainerCreatedAt = time.Date(2026, 10, 22, 9, 30, 0, 0, time.UTC)

// daemonContainerResult is a container tool result in the shape the daemon
// answers it, copied from MCPServiceProvider.instanceToContainerResponse
// (pkg/api/daemon/mcp_service.go), which this module cannot import; status,
// when not nil, is the create status container_create adds beside it.
func daemonContainerResult(id, name, state string, status map[string]interface{}) map[string]interface{} {
	result := map[string]interface{}{
		"id":         id,
		"name":       name,
		"state":      state,
		"created_at": daemonContainerCreatedAt.Format(time.RFC3339),
		"updated_at": daemonContainerCreatedAt.Format(time.RFC3339),
		"memory":     512,
		"cpus":       2,
		"metadata":   map[string]interface{}{"image": "alpine"},
	}
	if status != nil {
		result["status"] = status
	}
	return result
}

func TestCreateContainer_AttestationFailureReachesStatus(t *testing.T) {
	a := provisioningTestServer(t, map[string]interface{}{
		"container_create": daemonContainerResult("c-2", "web", "creating", map[string]interface{}{
			"success": false, "message": "Container created but attestation failed: no TPM",
		}),
	}, new([]toolCall))

	response := &platformv1.CreateContainerResponse{}
	request := &platformv1.CreateContainerRequest{AttestOnCreate: true, Config: &platformv1.ContainerConfig{Name: "web", Image: "alpine"}}
	if err := a.Connection().Invoke(context.Background(), createContainerMethod, request, response); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if response.GetStatus().GetSuccess() {
		t.Errorf("status = %+v, want the attestation failure", response.GetStatus())
	}
	if response.GetStatus().GetMessage() != "Container created but attestation failed: no TPM" {
		t.Errorf("status message = %q", response.GetStatus().GetMessage())
	}
	if response.GetContainer().GetId() != "c-2" {
		t.Errorf("container = %+v, want the created container beside the failure", response.GetContainer())
	}
}

func TestGetContainer_DecodesDaemonResult(t *testing.T) {
	a := provisioningTestServer(t, map[string]interface{}{
		"container_get": daemonContainerResult("c-3", "db", "running", nil),
	}, new([]toolCall))

	response := &platformv1.GetContainerResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.ComputeService_GetContainer_FullMethodName,
		&platformv1.GetContainerRequest{Id: "c-3"}, response); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	container := response.GetContainer()
	if container.GetId() != "c-3" || container.GetConfig().GetName() != "db" ||
		container.GetState() != platformv1.ContainerState_CONTAINER_STATE_RUNNING {
		t.Errorf("container = %+v, want id c-3, name db, state RUNNING", container)
	}
}

func TestListContainers_DecodesDaemonResult(t *testing.T) {
	a := provisioningTestServer(t, map[string]interface{}{
		"container_list": map[string]interface{}{"containers": []interface{}{
			daemonContainerResult("c-4", "a", "stopped", nil),
			daemonContainerResult("c-5", "b", "suspended", nil),
		}},
	}, new([]toolCall))

	response := &platformv1.ListContainersResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.ComputeService_ListContainers_FullMethodName,
		&platformv1.ListContainersRequest{}, response); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	containers := response.GetContainers()
	if len(containers) != 2 {
		t.Fatalf("containers = %+v, want 2", containers)
	}
	if containers[0].GetId() != "c-4" || containers[0].GetState() != platformv1.ContainerState_CONTAINER_STATE_EXITED {
		t.Errorf("containers[0] = %+v, want c-4 EXITED", containers[0])
	}
	if containers[1].GetConfig().GetName() != "b" || containers[1].GetState() != platformv1.ContainerState_CONTAINER_STATE_PAUSED {
		t.Errorf("containers[1] = %+v, want b PAUSED", containers[1])
	}
}

func TestContainerDecoders_RefuseMalformedResults(t *testing.T) {
	unknownState := daemonContainerResult("c-6", "x", "hibernating", nil)
	badTime := daemonContainerResult("c-7", "y", "running", nil)
	badTime["created_at"] = "yesterday"

	tests := []struct {
		name   string
		decode mcpReplyDecoder
		result interface{}
		reply  interface{}
		check  func(error) bool
	}{
		{"create unknown state", decodeContainerCreateResult, unknownState, &platformv1.CreateContainerResponse{},
			func(err error) bool { return errors.As(err, new(ErrUnknownContainerState)) }},
		{"get bad created_at", decodeContainerGetResult, badTime, &platformv1.GetContainerResponse{},
			func(err error) bool { return errors.As(err, new(ErrUnmarshalFailed)) }},
		{"list unknown state", decodeContainerListResult, map[string]interface{}{"containers": []interface{}{unknownState}},
			&platformv1.ListContainersResponse{}, func(err error) bool { return errors.As(err, new(ErrUnknownContainerState)) }},
		{"create not an object", decodeContainerCreateResult, "not an object", &platformv1.CreateContainerResponse{},
			func(err error) bool { return err != nil }},
		{"create wrong reply", decodeContainerCreateResult, badTime, &platformv1.GetContainerResponse{},
			func(err error) bool { return errors.As(err, new(ErrUnexpectedReplyType)) }},
		{"get wrong reply", decodeContainerGetResult, badTime, &platformv1.CreateContainerResponse{},
			func(err error) bool { return errors.As(err, new(ErrUnexpectedReplyType)) }},
		{"list wrong reply", decodeContainerListResult, badTime, &platformv1.GetContainerResponse{},
			func(err error) bool { return errors.As(err, new(ErrUnexpectedReplyType)) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.decode(tt.result, tt.reply); !tt.check(err) {
				t.Errorf("decode error = %v", err)
			}
		})
	}
}

func TestCreateContainer_MinimalRequestSendsNameAndImageOnly(t *testing.T) {
	arguments, err := buildContainerCreateArgs(&platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{Name: "web", Image: "alpine"},
	})
	if err != nil {
		t.Fatalf("buildContainerCreateArgs: %v", err)
	}
	want := map[string]interface{}{"name": "web", "image": "alpine"}
	if !reflect.DeepEqual(arguments, want) {
		t.Errorf("arguments = %v, want %v", arguments, want)
	}
}

func TestBuildContainerCreateArgs_WrongType(t *testing.T) {
	for _, args := range []interface{}{&platformv1.GetContainerRequest{}, (*platformv1.CreateContainerRequest)(nil)} {
		_, err := buildContainerCreateArgs(args)
		if _, ok := err.(ErrUnexpectedArgsType); !ok {
			t.Errorf("buildContainerCreateArgs(%T) error = %v, want ErrUnexpectedArgsType", args, err)
		}
	}
}
