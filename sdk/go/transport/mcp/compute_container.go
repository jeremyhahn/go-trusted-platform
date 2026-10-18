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
	"fmt"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// containerCreateArgs flattens a CreateContainerRequest into the arguments
// the container_create tool documents (docs/compute/api-reference-mcp.md).
// The generic JSON round-trip would nest them under "config", where the tool
// never looks, so every create would lose its name.
func containerCreateArgs(args interface{}) (map[string]interface{}, error) {
	const method = platformv1.ComputeService_CreateContainer_FullMethodName
	request, ok := args.(*platformv1.CreateContainerRequest)
	if !ok || request == nil {
		return nil, ErrUnexpectedArgsType{Method: method}
	}
	config := request.GetConfig()
	arguments := map[string]interface{}{
		"name":  config.GetName(),
		"image": config.GetImage(),
	}
	if command := config.GetCommand(); len(command) > 0 {
		arguments["command"] = command
	}
	if commandArgs := config.GetArgs(); len(commandArgs) > 0 {
		arguments["args"] = commandArgs
	}
	if envVars := config.GetEnv(); len(envVars) > 0 {
		env := make(map[string]interface{}, len(envVars))
		for _, envVar := range envVars {
			env[envVar.GetName()] = envVar.GetValue()
		}
		arguments["env"] = env
	}
	if labels := config.GetLabels(); len(labels) > 0 {
		arguments["labels"] = labels
	}
	if workingDir := config.GetWorkingDir(); workingDir != "" {
		arguments["working_dir"] = workingDir
	}
	if user := config.GetUser(); user != "" {
		arguments["user"] = user
	}
	if config.GetPrivileged() {
		arguments["privileged"] = true
	}
	if volumes := config.GetVolumes(); len(volumes) > 0 {
		mounts := make([]interface{}, 0, len(volumes))
		for _, volume := range volumes {
			mounts = append(mounts, map[string]interface{}{
				"source":    volume.GetSource(),
				"target":    volume.GetDestination(),
				"read_only": volume.GetReadonly(),
				"type":      volume.GetType(),
			})
		}
		arguments["mounts"] = mounts
	}
	if portMappings := config.GetPorts(); len(portMappings) > 0 {
		ports := make([]interface{}, 0, len(portMappings))
		for _, port := range portMappings {
			ports = append(ports, map[string]interface{}{
				"container_port": port.GetContainerPort(),
				"host_port":      port.GetHostPort(),
				"host_ip":        port.GetHostIp(),
				"protocol":       port.GetProtocol(),
			})
		}
		arguments["ports"] = ports
	}
	if limits := config.GetResources(); limits != nil {
		resources := make(map[string]interface{})
		if cpus := limits.GetMaxCpus(); cpus > 0 {
			resources["cpu_limit"] = strconv.FormatUint(uint64(cpus), 10)
		}
		if memoryMB := limits.GetMaxMemoryMb(); memoryMB > 0 {
			resources["memory_limit"] = fmt.Sprintf("%dM", memoryMB)
		}
		if len(resources) > 0 {
			arguments["resources"] = resources
		}
	}
	return arguments, nil
}

func init() {
	mcpArgBuilders[platformv1.ComputeService_CreateContainer_FullMethodName] = containerCreateArgs
}
