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
	"encoding/base64"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// mcpReplyWindows routes the methods whose reply may outlast the client's
// timeout to the window the daemon holds that reply open for: a graceful
// stop or reboot answers only once the guest has powered down
// (docs/compute/api.md §2). Methods absent from this map use the client's
// timeout.
var mcpReplyWindows = map[string]func(args interface{}) time.Duration{
	platformv1.ComputeService_StopVM_FullMethodName:   stopVMReplyWindow,
	platformv1.ComputeService_RebootVM_FullMethodName: rebootVMReplyWindow,
}

// replyWindow is how long method's reply may take, or zero for the client's
// timeout.
func replyWindow(method string, args interface{}) time.Duration {
	window, ok := mcpReplyWindows[method]
	if !ok {
		return 0
	}
	return window(args)
}

func stopVMReplyWindow(args interface{}) time.Duration {
	req, ok := args.(*platformv1.StopVMRequest)
	if !ok {
		return 0
	}
	return computesvc.StopReplyWindow(req.GetForce(), req.GetTimeoutSeconds())
}

// rebootVMReplyWindow is a stop's window: a reboot's stop half takes the
// default power-down window unless forced.
func rebootVMReplyWindow(args interface{}) time.Duration {
	req, ok := args.(*platformv1.RebootVMRequest)
	if !ok {
		return 0
	}
	return computesvc.StopReplyWindow(req.GetForce(), 0)
}

// vmLifecycleToolMap maps the ComputeService VM lifecycle methods to the
// platformd vm_* tools (pkg/api/mcp/vm_lifecycle_tools.go). Each tool takes
// its RPC's full request in protojson form and answers its response the
// same way, so every request field reaches the service (#704).
var vmLifecycleToolMap = map[string]string{
	platformv1.ComputeService_CreateVM_FullMethodName:          "vm_create",
	platformv1.ComputeService_ListVMs_FullMethodName:           "vm_list",
	platformv1.ComputeService_GetVM_FullMethodName:             "vm_get",
	platformv1.ComputeService_DeleteVM_FullMethodName:          "vm_delete",
	platformv1.ComputeService_StartVM_FullMethodName:           "vm_start",
	platformv1.ComputeService_StopVM_FullMethodName:            "vm_stop",
	platformv1.ComputeService_RebootVM_FullMethodName:          "vm_reboot",
	platformv1.ComputeService_SuspendVM_FullMethodName:         "vm_suspend",
	platformv1.ComputeService_ResumeVM_FullMethodName:          "vm_resume",
	platformv1.ComputeService_PrepareMigration_FullMethodName:  "vm_migration_prepare",
	platformv1.ComputeService_FinalizeMigration_FullMethodName: "vm_migration_finalize",
}

// vmSnapshotAttestTools maps the ComputeService snapshot and attestation
// methods to the platformd vm_snapshot_* and vm_attest* tools, each with the
// builder that renders the request as the tool's arguments. The snapshot
// verbs that name ids take the request's own field names.
var vmSnapshotAttestTools = map[string]struct {
	tool  string
	build func(method string) mcpArgBuilder
}{
	platformv1.ComputeService_CreateSnapshot_FullMethodName:      {"vm_snapshot_create", vmSnapshotCreateArgs},
	platformv1.ComputeService_ListSnapshots_FullMethodName:       {"vm_snapshot_list", vmFieldArgs("vm_id")},
	platformv1.ComputeService_GetSnapshot_FullMethodName:         {"vm_snapshot_get", vmFieldArgs("vm_id", "snapshot_id")},
	platformv1.ComputeService_DeleteSnapshot_FullMethodName:      {"vm_snapshot_delete", vmFieldArgs("vm_id", "snapshot_id")},
	platformv1.ComputeService_RestoreSnapshot_FullMethodName:     {"vm_snapshot_restore", vmFieldArgs("vm_id", "snapshot_id")},
	platformv1.ComputeService_AttestVM_FullMethodName:            {"vm_attest", vmAttestArgs},
	platformv1.ComputeService_VerifyVMAttestation_FullMethodName: {"vm_attest_verify", vmAttestVerifyArgs},
}

// vmFieldArgs renders a request whose tool arguments are exactly the named
// request fields, refusing a request that sets any other field.
func vmFieldArgs(carried ...string) func(method string) mcpArgBuilder {
	return func(method string) mcpArgBuilder {
		render := protoJSONArgs(method)
		return func(args interface{}) (map[string]interface{}, error) {
			request, ok := args.(proto.Message)
			if !ok || !request.ProtoReflect().IsValid() {
				return nil, ErrUnexpectedArgsType{Method: method}
			}
			if err := refuseUncarried(method, "", request, carried...); err != nil {
				return nil, err
			}
			return render(request)
		}
	}
}

// vmSnapshotCreateArgs flattens the snapshot config into vm_snapshot_create's
// name, description, memory_snapshot and disk_snapshot arguments.
func vmSnapshotCreateArgs(method string) mcpArgBuilder {
	return func(args interface{}) (map[string]interface{}, error) {
		request, ok := args.(*platformv1.CreateSnapshotRequest)
		if !ok || request == nil {
			return nil, ErrUnexpectedArgsType{Method: method}
		}
		config := request.GetConfig()
		return map[string]interface{}{
			"vm_id":           request.GetVmId(),
			"name":            config.GetName(),
			"description":     config.GetDescription(),
			"memory_snapshot": config.GetMemorySnapshot(),
			"disk_snapshot":   config.GetDiskSnapshot(),
		}, nil
	}
}

// vmAttestArgs renders AttestVM as vm_attest's vm_id, base64 nonce and
// include_pcrs. The tool quotes the SHA-256 bank, the only one AttestVM
// accepts, so a request for another bank is refused.
func vmAttestArgs(method string) mcpArgBuilder {
	return func(args interface{}) (map[string]interface{}, error) {
		request, ok := args.(*platformv1.AttestVMRequest)
		if !ok || request == nil {
			return nil, ErrUnexpectedArgsType{Method: method}
		}
		if !vmToolBank(request.GetPcrBank()) {
			return nil, ErrFieldNotSupported{Method: method, Field: "pcr_bank"}
		}
		pcrs := make([]interface{}, 0, len(request.GetPcrIndices()))
		for _, index := range request.GetPcrIndices() {
			pcrs = append(pcrs, index)
		}
		return map[string]interface{}{
			"vm_id":        request.GetVmId(),
			"nonce":        base64.StdEncoding.EncodeToString(request.GetNonce()),
			"include_pcrs": pcrs,
		}, nil
	}
}

// vmAttestVerifyArgs renders VerifyVMAttestation as vm_attest_verify's
// arguments: the base64 evidence, the declared signature_algorithm, and
// expected_pcrs as a map of PCR index to base64 value. Expected values are
// SHA-256, so a value from another bank is refused.
func vmAttestVerifyArgs(method string) mcpArgBuilder {
	return func(args interface{}) (map[string]interface{}, error) {
		request, ok := args.(*platformv1.VerifyVMAttestationRequest)
		if !ok || request == nil {
			return nil, ErrUnexpectedArgsType{Method: method}
		}
		expected := make(map[string]interface{}, len(request.GetExpectedPcrs()))
		for _, pcr := range request.GetExpectedPcrs() {
			if !vmToolBank(pcr.GetBank()) {
				return nil, ErrFieldNotSupported{Method: method, Field: "expected_pcrs.bank"}
			}
			expected[strconv.FormatUint(uint64(pcr.GetIndex()), 10)] = base64.StdEncoding.EncodeToString(pcr.GetValue())
		}
		return map[string]interface{}{
			"vm_id":               request.GetVmId(),
			"quote":               base64.StdEncoding.EncodeToString(request.GetQuote()),
			"signature":           base64.StdEncoding.EncodeToString(request.GetSignature()),
			"signature_algorithm": request.GetSignatureAlgorithm(),
			"nonce":               base64.StdEncoding.EncodeToString(request.GetNonce()),
			"expected_pcrs":       expected,
		}, nil
	}
}

// vmToolBank reports whether the vm_attest tools carry a PCR bank: SHA-256,
// named or left unspecified.
func vmToolBank(bank platformv1.PCRBank) bool {
	return bank == platformv1.PCRBank_PCR_BANK_UNSPECIFIED || bank == platformv1.PCRBank_PCR_BANK_SHA256
}

func init() {
	for method, tool := range vmLifecycleToolMap {
		grpcMethodToMCPToolMap[method] = tool
		mcpArgBuilders[method] = protoJSONArgs(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
	for method, entry := range vmSnapshotAttestTools {
		grpcMethodToMCPToolMap[method] = entry.tool
		mcpArgBuilders[method] = entry.build(method)
		mcpReplyDecoders[method] = protoJSONReply(method)
	}
}
