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
	"testing"

	"github.com/stretchr/testify/assert"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

const idevidServicePrefix = "/platform.v1.IDevIDService/"

// deviceIdentityParityRows pairs every QUIC device-identity opcode with its
// gRPC IDevIDService method and its MCP tool. The LDevID sub-opcode of the
// physical-TPM category belongs here: the daemon serves it with
// IDevIDService.CreateLDevID, not the TPM2 handler.
var deviceIdentityParityRows = []scopeParityRow{
	{name: "idevid info", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "GetIDevIDInfo",
		quicOpcode: quicwire.OpIDevIDInfo, mcpTool: "idevid_info"},
	{name: "idevid exists", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "HasIDevID",
		quicOpcode: quicwire.OpHasIDevID, mcpTool: "idevid_exists"},
	{name: "idevid get cert", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "GetIDevIDCertificate",
		quicOpcode: quicwire.OpIDevIDGetCert, mcpTool: "idevid_get_cert"},
	{name: "idevid generate", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "GenerateIDevID",
		quicOpcode: quicwire.OpIDevIDGenerate, mcpTool: "idevid_generate"},
	{name: "idevid csr", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "CreateIDevIDCSR",
		quicOpcode: quicwire.OpIDevIDCSR, mcpTool: "idevid_csr"},
	{name: "idevid install cert", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "InstallIDevIDCertificate",
		quicOpcode: quicwire.OpIDevIDInstallCert, mcpTool: "idevid_install_cert"},
	{name: "idevid delete", scope: "idevid:delete",
		grpcMethod: idevidServicePrefix + "DeleteIDevID",
		quicOpcode: quicwire.OpIDevIDDelete, mcpTool: "idevid_delete"},
	{name: "idevid delete cert", scope: "idevid:delete",
		grpcMethod: idevidServicePrefix + "DeleteIDevIDCertificate",
		quicOpcode: quicwire.OpIDevIDDeleteCert, mcpTool: "idevid_delete_cert"},
	{name: "iak info", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "GetIAKInfo",
		quicOpcode: quicwire.OpIAKInfo, mcpTool: "iak_info"},
	{name: "iak exists", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "HasIAK",
		quicOpcode: quicwire.OpHasIAK, mcpTool: "iak_exists"},
	{name: "iak get cert", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "GetIAKCertificate",
		quicOpcode: quicwire.OpIAKGetCert, mcpTool: "iak_get_cert"},
	{name: "iak generate", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "GenerateIAK",
		quicOpcode: quicwire.OpIAKGenerate, mcpTool: "iak_generate"},
	{name: "iak csr", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "CreateIAKCSR",
		quicOpcode: quicwire.OpIAKCSR, mcpTool: "iak_csr"},
	{name: "iak install cert", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "InstallIAKCertificate",
		quicOpcode: quicwire.OpIAKInstallCert, mcpTool: "iak_install_cert"},
	{name: "iak delete", scope: "idevid:delete",
		grpcMethod: idevidServicePrefix + "DeleteIAK",
		quicOpcode: quicwire.OpIAKDelete, mcpTool: "iak_delete"},
	{name: "iak delete cert", scope: "idevid:delete",
		grpcMethod: idevidServicePrefix + "DeleteIAKCertificate",
		quicOpcode: quicwire.OpIAKDeleteCert, mcpTool: "iak_delete_cert"},
	{name: "device attributes", scope: "idevid:read",
		grpcMethod: idevidServicePrefix + "GetDeviceAttributes",
		quicOpcode: quicwire.OpDeviceAttributes, mcpTool: "device_attributes"},
	{name: "activate credential", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "ActivateCredential",
		quicOpcode: quicwire.OpActivateCredential, mcpTool: "activate_credential"},
	{name: "create ldevid", scope: "idevid:write",
		grpcMethod: idevidServicePrefix + "CreateLDevID",
		quicOpcode: quicwire.OpTPM2Category, quicSub: []byte{quicwire.SubOpTPM2LDevIDCSR},
		mcpTool: "idevid_create_ldevid"},
}

// idevidMethodsWithoutQUICTwin are the IDevIDService methods no QUIC opcode
// serves. FlushTransientContexts is a gRPC maintenance call with no opcode.
var idevidMethodsWithoutQUICTwin = map[string]bool{
	idevidServicePrefix + "FlushTransientContexts": true,
}

// TestDeviceIdentityScopeParity asserts that one idevid:* grant covers each
// device-identity operation on gRPC, QUIC and MCP alike (#304). QUIC used to
// scope these opcodes under tpm:*.
func TestDeviceIdentityScopeParity(t *testing.T) {
	assertScopeParity(t, deviceIdentityParityRows)
}

// TestDeviceIdentityParityCoversIDevIDService fails when an IDevIDService
// method is neither paired with a QUIC opcode above nor named as having no
// QUIC twin, so a new method cannot skip the parity check.
func TestDeviceIdentityParityCoversIDevIDService(t *testing.T) {
	paired := make(map[string]bool, len(deviceIdentityParityRows))
	for _, row := range deviceIdentityParityRows {
		paired[row.grpcMethod] = true
	}
	for _, m := range platformv1.IDevIDService_ServiceDesc.Methods {
		method := idevidServicePrefix + m.MethodName
		assert.True(t, paired[method] || idevidMethodsWithoutQUICTwin[method],
			"%s has no row in deviceIdentityParityRows and is not named as having no QUIC twin", method)
	}
	for method := range idevidMethodsWithoutQUICTwin {
		assert.False(t, paired[method], "%s is paired with a QUIC opcode and named as having none", method)
	}
}
