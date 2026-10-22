package mcp

import (
	"strconv"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// createContainerMethod is the gRPC method the container_create tool serves.
const createContainerMethod = "/platform.v1.ComputeService/CreateContainer"

func init() {
	mcpArgBuilders[createContainerMethod] = buildContainerCreateArgs
	mcpReplyDecoders[createContainerMethod] = decodeContainerCreateResult
	mcpReplyDecoders[platformv1.ComputeService_GetContainer_FullMethodName] = decodeContainerGetResult
	mcpReplyDecoders[platformv1.ComputeService_ListContainers_FullMethodName] = decodeContainerListResult
}

// containerStates maps the daemon's instance state names to the container
// states the gRPC service answers for them (compute_grpc_service.go,
// instanceStateToContainerProtoState); "unknown" and "deleting" have no
// container state there either.
var containerStates = map[string]platformv1.ContainerState{
	"":          platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED,
	"unknown":   platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED,
	"deleting":  platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED,
	"creating":  platformv1.ContainerState_CONTAINER_STATE_CREATED,
	"starting":  platformv1.ContainerState_CONTAINER_STATE_STARTING,
	"running":   platformv1.ContainerState_CONTAINER_STATE_RUNNING,
	"suspended": platformv1.ContainerState_CONTAINER_STATE_PAUSED,
	"stopping":  platformv1.ContainerState_CONTAINER_STATE_STOPPING,
	"stopped":   platformv1.ContainerState_CONTAINER_STATE_EXITED,
	"error":     platformv1.ContainerState_CONTAINER_STATE_ERROR,
}

// containerWire is one container as the container tools answer it: the
// instance's fields at the top level, not a platform.v1.Container message.
type containerWire struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	State     string `json:"state"`
	CreatedAt string `json:"created_at"`
}

// containerStatusWire is the create status container_create answers beside
// the container's fields.
type containerStatusWire struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// containerCreateWire is the container_create tool's result.
type containerCreateWire struct {
	containerWire
	Status *containerStatusWire `json:"status"`
}

// containerListWire is the container_list tool's result.
type containerListWire struct {
	Containers []containerWire `json:"containers"`
}

// toPb converts the tool's container to the message the gRPC service answers.
func (w containerWire) toPb() (*platformv1.Container, error) {
	state, known := containerStates[w.State]
	if !known {
		return nil, ErrUnknownContainerState{Value: w.State}
	}
	container := &platformv1.Container{Id: w.ID, State: state}
	if w.CreatedAt != "" {
		createdAt, err := time.Parse(time.RFC3339, w.CreatedAt)
		if err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		container.CreatedAt = timestamppb.New(createdAt)
	}
	if w.Name != "" {
		container.Config = &platformv1.ContainerConfig{Name: w.Name}
	}
	return container, nil
}

// decodeContainerCreateResult fills a CreateContainerResponse from the
// container_create tool's result: the container and the create status.
func decodeContainerCreateResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.CreateContainerResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: createContainerMethod}
	}
	var wire containerCreateWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	container, err := wire.toPb()
	if err != nil {
		return err
	}
	out.Container = container
	if wire.Status != nil {
		out.Status = &platformv1.Status{Success: wire.Status.Success, Message: wire.Status.Message}
	}
	return nil
}

// decodeContainerGetResult fills a GetContainerResponse from the
// container_get tool's result.
func decodeContainerGetResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.GetContainerResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.ComputeService_GetContainer_FullMethodName}
	}
	var wire containerWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	container, err := wire.toPb()
	if err != nil {
		return err
	}
	out.Container = container
	return nil
}

// decodeContainerListResult fills a ListContainersResponse from the
// container_list tool's result.
func decodeContainerListResult(result interface{}, reply interface{}) error {
	out, ok := reply.(*platformv1.ListContainersResponse)
	if !ok {
		return ErrUnexpectedReplyType{Method: platformv1.ComputeService_ListContainers_FullMethodName}
	}
	var wire containerListWire
	if err := decodeToolResult(result, &wire); err != nil {
		return err
	}
	out.Containers = make([]*platformv1.Container, 0, len(wire.Containers))
	for _, item := range wire.Containers {
		container, err := item.toPb()
		if err != nil {
			return err
		}
		out.Containers = append(out.Containers, container)
	}
	return nil
}

// buildContainerCreateArgs flattens a CreateContainerRequest into the
// container_create tool's arguments. The tool takes the container's fields at
// the top level (docs/compute/api-reference-mcp.md, "Container tools"); the
// generic JSON round-trip would nest them under "config" and the daemon would
// refuse every create with CONTAINER_NAME_REQUIRED.
func buildContainerCreateArgs(args interface{}) (map[string]interface{}, error) {
	request, ok := args.(*platformv1.CreateContainerRequest)
	if !ok || request == nil {
		return nil, ErrUnexpectedArgsType{Method: createContainerMethod}
	}
	config := request.GetConfig()
	arguments := map[string]interface{}{
		"name":  config.GetName(),
		"image": config.GetImage(),
	}
	if len(config.GetCommand()) > 0 {
		arguments["command"] = config.GetCommand()
	}
	if len(config.GetArgs()) > 0 {
		arguments["args"] = config.GetArgs()
	}
	if len(config.GetEnv()) > 0 {
		env := make(map[string]interface{}, len(config.GetEnv()))
		for _, variable := range config.GetEnv() {
			env[variable.GetName()] = variable.GetValue()
		}
		arguments["env"] = env
	}
	if len(config.GetLabels()) > 0 {
		labels := make(map[string]interface{}, len(config.GetLabels()))
		for key, value := range config.GetLabels() {
			labels[key] = value
		}
		arguments["labels"] = labels
	}
	if config.GetWorkingDir() != "" {
		arguments["working_dir"] = config.GetWorkingDir()
	}
	if config.GetUser() != "" {
		arguments["user"] = config.GetUser()
	}
	if config.GetPrivileged() {
		arguments["privileged"] = true
	}
	if len(config.GetVolumes()) > 0 {
		arguments["mounts"] = containerMountArgs(config.GetVolumes())
	}
	if len(config.GetPorts()) > 0 {
		arguments["ports"] = containerPortArgs(config.GetPorts())
	}
	if resources := containerResourceArgs(config.GetResources()); len(resources) > 0 {
		arguments["resources"] = resources
	}
	if request.GetAttestOnCreate() {
		arguments["attest_on_create"] = true
	}
	return arguments, nil
}

// containerMountArgs maps volume mounts to the tool's mount objects.
func containerMountArgs(volumes []*platformv1.VolumeMount) []interface{} {
	mounts := make([]interface{}, 0, len(volumes))
	for _, volume := range volumes {
		mounts = append(mounts, map[string]interface{}{
			"source":    volume.GetSource(),
			"target":    volume.GetDestination(),
			"read_only": volume.GetReadonly(),
			"type":      volume.GetType(),
		})
	}
	return mounts
}

// containerPortArgs maps port mappings to the tool's port objects.
func containerPortArgs(mappings []*platformv1.PortMapping) []interface{} {
	ports := make([]interface{}, 0, len(mappings))
	for _, mapping := range mappings {
		ports = append(ports, map[string]interface{}{
			"container_port": mapping.GetContainerPort(),
			"host_port":      mapping.GetHostPort(),
			"host_ip":        mapping.GetHostIp(),
			"protocol":       mapping.GetProtocol(),
		})
	}
	return ports
}

// containerResourceArgs maps resource limits to the tool's resources object:
// a CPU count and a memory size in mebibytes ("512M").
func containerResourceArgs(limits *platformv1.ResourceLimits) map[string]interface{} {
	resources := make(map[string]interface{}, 2)
	if limits.GetMaxCpus() > 0 {
		resources["cpu_limit"] = strconv.FormatUint(uint64(limits.GetMaxCpus()), 10)
	}
	if limits.GetMaxMemoryMb() > 0 {
		resources["memory_limit"] = strconv.FormatUint(limits.GetMaxMemoryMb(), 10) + "M"
	}
	return resources
}
