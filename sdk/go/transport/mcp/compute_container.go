package mcp

import (
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// createContainerMethod is the gRPC method the container_create tool serves.
const createContainerMethod = "/platform.v1.ComputeService/CreateContainer"

func init() {
	mcpArgBuilders[createContainerMethod] = buildContainerCreateArgs
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
