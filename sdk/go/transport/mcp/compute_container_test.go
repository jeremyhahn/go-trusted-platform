package mcp

import (
	"context"
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestCreateContainer_FlatToolArguments(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"container_create": map[string]interface{}{
			"container": map[string]interface{}{"id": "c-1"},
		},
	}, &calls)

	request := &platformv1.CreateContainerRequest{Config: &platformv1.ContainerConfig{
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
		"resources": map[string]interface{}{"cpu_limit": "2", "memory_limit": "512M"},
	}
	if !reflect.DeepEqual(calls[0].Arguments, want) {
		t.Errorf("tool arguments = %v, want %v", calls[0].Arguments, want)
	}
	if response.GetContainer().GetId() != "c-1" {
		t.Errorf("container = %+v, want id c-1", response.GetContainer())
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
