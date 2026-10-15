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
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// vmLifecycleToolMap maps the ComputeService VM lifecycle methods to the
// platformd vm_* tools (pkg/api/mcp/vm_tools.go). Each tool takes only the
// VM id.
var vmLifecycleToolMap = map[string]string{
	platformv1.ComputeService_StartVM_FullMethodName:   "vm_start",
	platformv1.ComputeService_StopVM_FullMethodName:    "vm_stop",
	platformv1.ComputeService_RebootVM_FullMethodName:  "vm_reboot",
	platformv1.ComputeService_SuspendVM_FullMethodName: "vm_suspend",
	platformv1.ComputeService_ResumeVM_FullMethodName:  "vm_resume",
	platformv1.ComputeService_DeleteVM_FullMethodName:  "vm_delete",
}

// vmByIDArgs renders a VM lifecycle request as the tool's id argument. The
// tools carry no force, timeout_seconds or delete_disks, so a request that
// sets one is refused rather than run with the field silently dropped.
func vmByIDArgs(method string) mcpArgBuilder {
	render := protoJSONArgs(method)
	return func(args interface{}) (map[string]interface{}, error) {
		request, ok := args.(proto.Message)
		if !ok || !request.ProtoReflect().IsValid() {
			return nil, ErrUnexpectedArgsType{Method: method}
		}
		if err := refuseUncarried(method, "", request, "id"); err != nil {
			return nil, err
		}
		return render(request)
	}
}

func init() {
	for method, tool := range vmLifecycleToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = vmByIDArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
