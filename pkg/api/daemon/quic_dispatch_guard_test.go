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

package daemon

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// This file pins the QUIC opcode dispatch map in HandleRequest against
// shadowing regressions. Every wire byte (0x00-0xFF) and every exported
// opcode constant in sdk/go/wire/quicwire is driven through a bare
// QUICServiceHandler (all services nil) and classified by the
// family-identifying nil-service error each handler family returns.
//
// Wire ownership (single-byte opcode space, authoritative):
//
//	0x00-0x02 health            0x90 cluster; 0x91-0x97 reserved (JWT/auth)
//	0x03-0x1F vtpm              0x98      daemon
//	0x20-0x2D dns               0x99      TPM2 category
//	0x2E      overlay category  0x9A-0x9D ceremony/piv/luks/fido2
//	0x2F      gateway category  0x9E      tenant barrier category
//	0x30-0x3D device            0x9F      bmc category
//	0x3F      ipam category     0xA0-0xA8 ca
//	0x40-0x4F sdn               0xA9-0xAD iam users
//	0x50      ntp category      0xAE-0xAF container
//	0x51      iam category
//	0x52      vpn category
//	0x53      cache category
//	0x54      scheduler category
//	0x55      messaging category
//	0x56-0x5F tpm2 (idevid)     0xB0-0xB4 sdn extended
//	0x69      vm (ext cat)      0xB5-0xBF iam roles/groups
//	0x6B-0x6E tpm2 (iak ext)    0xC0-0xCB kms keys
//	0x6F      container         0xCC-0xCF switch/kms-ext/secrets/prov cats
//	0x70-0x7F attestation       0xD0-0xDA kms crypto
//	  (0x78-0x7B tpm2 carve)    0xDB-0xEB tenant
//	0x80-0x88 ca (certs)          (0xE7-0xE8 retired, reserved)
//	                            0xEC-0xEF pxe
//	0x89-0x8F daemon            0xF0-0xF5 reserved (DEK, unwired)
//	                            0xF6-0xFB iam extended
//	                            0xFC-0xFF pxe extended
//
// Constants whose byte is owned by another family at the top level
// (documented multiplexing) are encoded explicitly below:
//
//   - VM ops (OpVMCreate..OpVMList, 0x60-0x65, and
//     OpVMRestart..OpVMResume, 0xB6-0xB8, and
//     OpVMSnapshotCreate..OpVMSnapshotList, 0xBB-0xBE, and
//     OpVMAttest 0xB9, OpVMVerifyAttest 0xBF) and the
//     container ops (create/start/stop/remove/attest) travel as
//     sub-opcodes in payload[0] under quicwire.OpVMExtendedCategory (0x69).
//   - Overlay/gateway ops travel under their category opcodes 0x2E/0x2F.
//   - OpAttestCreatePolicy/OpAttestListPolicies (0xAA/0xAB) and
//     OpAttestContainerWorkload/DeviceWorkload/ListReports (0xED-0xEF)
//     have NO single-byte wire route: IAM users and PXE own those bytes
//     (SDK adapter + integration-test clients send the IAM/PXE ops).

// dispatchIntentMode describes how an opcode constant is expected to reach
// its service family through HandleRequest.
type dispatchIntentMode int

const (
	// wireDirect constants are sent as the top-level opcode byte.
	wireDirect dispatchIntentMode = iota
	// categorySub constants are carried in payload[0] under a category opcode.
	categorySub
	// shadowedByte constants share a byte owned by ANOTHER family at the
	// top level; the entry documents the byte owner reached on the wire.
	shadowedByte
	// reservedByte constants are declared but not wired to any handler;
	// they have no authorization entry, so the guard refuses them.
	reservedByte
)

// dispatchFamilySpec identifies a service family by the exact nil-service
// response a bare handler returns, plus any payload required to reach the
// family-identifying check (category opcodes that dispatch sub-opcodes
// before their nil-service checks).
type dispatchFamilySpec struct {
	payload []byte
	status  byte
	body    string
}

// quicDispatchFamilies maps family names to their bare-handler signatures.
var quicDispatchFamilies = map[string]dispatchFamilySpec{
	"health":         {status: quicwire.StatusOK},
	"vtpm":           {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: vtpm"},
	"dns":            {status: quicwire.StatusUnavailable, body: "DNS service not available"},
	"overlay":        {status: quicwire.StatusUnavailable, body: "service not available: overlay"},
	"gateway":        {status: quicwire.StatusUnavailable, body: "service not available: gateway"},
	"device":         {status: quicwire.StatusUnavailable, body: "service not available: device"},
	"ipam":           {status: quicwire.StatusUnavailable, body: "service not available: ipam"},
	"sdn":            {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: sdn"},
	"tpm2":           {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: tpm2"},
	"vm":             {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: vm"},
	"container":      {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: container"},
	"attestation":    {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: attestation"},
	"ca":             {status: quicwire.StatusUnavailable, body: "service not available: ca"},
	"daemon":         {status: quicwire.StatusUnavailable, body: "service not available: daemon"},
	"tpm2category":   {status: quicwire.StatusUnavailable, body: "TPM2 service not available"},
	"ceremony":       {status: quicwire.StatusUnavailable, body: "service not available: ceremony"},
	"piv":            {status: quicwire.StatusUnavailable, body: "service not available: piv"},
	"luks":           {status: quicwire.StatusUnavailable, body: "service not available: luks"},
	"fido2":          {status: quicwire.StatusUnavailable, body: "service not available: fido2"},
	"tenant":         {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: tenant"},
	"bmc":            {payload: []byte{quicwire.BMCSubEnroll}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: bmc"},
	"cluster":        {payload: []byte{quicwire.ClusterSubGetStatus}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: cluster"},
	"iam":            {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: iam"},
	"kms":            {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: kms"},
	"switch":         {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: switch"},
	"secrets":        {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: secrets"},
	"configdelivery": {payload: []byte{quicwire.ProvisioningSubGetNonce}, status: quicwire.StatusUnavailable, body: "config delivery service is not available"},
	"ntp":            {payload: []byte{quicwire.NTPSubGetStatus}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: ntp"},
	"vpn":            {payload: []byte{quicwire.VPNSubGetStatus}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: vpn"},
	"cache":          {payload: []byte{quicwire.CacheSubGetStats}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: cache"},
	"scheduler":      {payload: []byte{quicwire.SchedulerSubGetStatus}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: scheduler"},
	"messaging":      {payload: []byte{quicwire.MessagingSubGetStats}, status: quicwire.StatusUnavailable, body: "QUIC service unavailable: messaging"},
	"pxe":            {status: quicwire.StatusUnavailable, body: "QUIC service unavailable: pxe"},
}

// quicCategoryProbeSubs gives every category opcode a classified sub-opcode.
// The dispatcher authorizes before it routes, so a category request without a
// sub-opcode is refused by the guard; the probe carries the request past the
// guard to the family's nil-service check.
var quicCategoryProbeSubs = map[byte]byte{
	quicwire.OpOverlayCategory:       quicwire.OpOverlayStatus,
	quicwire.OpGatewayCategory:       quicwire.OpGatewayStatus,
	quicwire.OpIPAMCategory:          quicwire.OpGatewayListIPAMPools,
	quicwire.OpNTPCategory:           quicwire.NTPSubGetStatus,
	quicwire.OpIAMCategory:           quicwire.IAMSubTenantList,
	quicwire.OpVMExtendedCategory:    quicwire.OpVMRestart,
	quicwire.OpTPM2Category:          quicwire.SubOpTPM2Info,
	quicwire.OpCeremonyCategory:      quicwire.CeremonySubStatus,
	quicwire.OpPIVCategory:           quicwire.PIVSubListDevices,
	quicwire.OpLUKSCategory:          quicwire.LUKSSubStatus,
	quicwire.OpFIDO2Category:         quicwire.FIDO2SubListDevices,
	quicwire.OpTenantBarrierCategory: quicwire.TenantBarrierSubStatus,
	quicwire.OpBMCCategory:           quicwire.BMCSubEnroll,
	quicwire.OpClusterCategory:       quicwire.ClusterSubGetStatus,
	quicwire.OpSwitchCategory:        quicwire.SwitchSubListPorts,
	quicwire.OpKMSExtendedCategory:   quicwire.KMSSubGetKeyMetadata,
	quicwire.OpSecretsCategory:       quicwire.SecretsSubGet,
	quicwire.OpProvisioningCategory:  quicwire.ProvisioningSubGetNonce,
}

// dispatchProbePayload is the payload a bare dispatch of opcode carries: the
// family's own payload when it needs one, else the category probe sub-opcode.
func dispatchProbePayload(opcode byte, family string) []byte {
	if family == "reserved" {
		return nil
	}
	if payload := quicDispatchFamilies[family].payload; payload != nil {
		return payload
	}
	if sub, ok := quicCategoryProbeSubs[opcode]; ok {
		return []byte{sub}
	}
	return nil
}

// quicWireOwners is the authoritative byte-range ownership table for the
// single-byte opcode space. Every byte 0x00-0xFF must be covered by
// exactly one range.
var quicWireOwners = []struct {
	lo, hi byte
	family string
}{
	{0x00, 0x02, "health"},
	{0x03, 0x1F, "vtpm"},
	{0x20, 0x2A, "dns"},
	{0x2B, 0x2B, "reserved"}, // retired DNSUpdateConfig (#317), unclassified
	{0x2C, 0x2C, "dns"},
	{0x2D, 0x2D, "reserved"}, // retired DNSFlushCache (#317), unclassified
	{0x2E, 0x2E, "overlay"},
	{0x2F, 0x2F, "gateway"},
	{0x30, 0x3B, "device"},
	{0x3C, 0x3C, "reserved"}, // retired device Deactivate (#317), unclassified
	{0x3D, 0x3D, "device"},
	{0x3E, 0x3E, "reserved"}, // retired device GetMetrics (#317), unclassified
	{0x3F, 0x3F, "ipam"},
	{0x40, 0x4F, "sdn"},
	{0x50, 0x50, "ntp"},
	{0x51, 0x51, "iam"},
	{0x52, 0x52, "vpn"},
	{0x53, 0x53, "cache"},
	{0x54, 0x54, "scheduler"},
	{0x55, 0x55, "messaging"},
	{0x56, 0x5F, "tpm2"},
	{0x60, 0x68, "reserved"}, // retired top-level VM bytes (#704), unclassified
	{0x69, 0x69, "vm"},
	{0x6A, 0x6A, "reserved"}, // retired VMGetState (#704), unclassified
	{0x6B, 0x6E, "tpm2"},
	{0x6F, 0x6F, "container"},
	{0x70, 0x77, "attestation"},
	{0x78, 0x7B, "tpm2"},
	{0x7C, 0x7F, "attestation"},
	{0x80, 0x88, "ca"},
	{0x89, 0x8F, "daemon"},
	{0x90, 0x90, "cluster"},
	{0x91, 0x97, "reserved"},
	{0x98, 0x98, "daemon"},
	{0x99, 0x99, "tpm2category"},
	{0x9A, 0x9A, "ceremony"},
	{0x9B, 0x9B, "piv"},
	{0x9C, 0x9C, "luks"},
	{0x9D, 0x9D, "fido2"},
	{0x9E, 0x9E, "tenant"},
	{0x9F, 0x9F, "bmc"},
	{0xA0, 0xA8, "ca"},
	{0xA9, 0xAD, "iam"},
	{0xAE, 0xAF, "container"},
	{0xB0, 0xB4, "sdn"},
	{0xB5, 0xBF, "iam"},
	{0xC0, 0xCB, "kms"},
	{0xCC, 0xCC, "switch"},
	{0xCD, 0xCD, "kms"},
	{0xCE, 0xCE, "secrets"},
	{0xCF, 0xCF, "configdelivery"},
	{0xD0, 0xDA, "kms"},
	{0xDB, 0xE6, "tenant"},
	{0xE7, 0xE8, "reserved"}, // retired tenant bytes (#708), unclassified
	{0xE9, 0xEB, "tenant"},
	{0xEC, 0xEF, "pxe"},
	{0xF0, 0xF5, "reserved"},
	{0xF6, 0xFB, "iam"},
	{0xFC, 0xFF, "pxe"},
}

// dispatchOpcodeIntent records the routing intent for one exported opcode
// constant in pkg/api/quic.
type dispatchOpcodeIntent struct {
	value    byte
	mode     dispatchIntentMode
	family   string
	category byte // category opcode for categorySub entries
}

// quicDispatchOpcodeIntents lists EVERY exported Op* byte constant in
// pkg/api/quic (completeness enforced by
// TestQUICDispatchConstantTableComplete) with its expected routing.
var quicDispatchOpcodeIntents = map[string]dispatchOpcodeIntent{
	"OpHealth":                    {value: quicwire.OpHealth, mode: wireDirect, family: "health"},
	"OpGatewayStatus":             {value: quicwire.OpGatewayStatus, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpLiveness":                  {value: quicwire.OpLiveness, mode: wireDirect, family: "health"},
	"OpOverlayStatus":             {value: quicwire.OpOverlayStatus, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpGatewaySetMode":            {value: quicwire.OpGatewaySetMode, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayListVTEPs":          {value: quicwire.OpOverlayListVTEPs, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpReadiness":                 {value: quicwire.OpReadiness, mode: wireDirect, family: "health"},
	"OpGatewayBGPStatus":          {value: quicwire.OpGatewayBGPStatus, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayGetVTEP":            {value: quicwire.OpOverlayGetVTEP, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMCreateTemplate":        {value: quicwire.OpVTPMCreateTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayBGPPeers":           {value: quicwire.OpGatewayBGPPeers, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayListVNIs":           {value: quicwire.OpOverlayListVNIs, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMGetTemplate":           {value: quicwire.OpVTPMGetTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayAnnouncePrefix":     {value: quicwire.OpGatewayAnnouncePrefix, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayCreateVNI":          {value: quicwire.OpOverlayCreateVNI, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMDeleteTemplate":        {value: quicwire.OpVTPMDeleteTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayWithdrawPrefix":     {value: quicwire.OpGatewayWithdrawPrefix, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayDeleteVNI":          {value: quicwire.OpOverlayDeleteVNI, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMListTemplates":         {value: quicwire.OpVTPMListTemplates, mode: wireDirect, family: "vtpm"},
	"OpGatewayListPrefixes":       {value: quicwire.OpGatewayListPrefixes, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayListTunns":          {value: quicwire.OpOverlayListTunns, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMCloneTemplate":         {value: quicwire.OpVTPMCloneTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayListIPAMPools":      {value: quicwire.OpGatewayListIPAMPools, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayListMACs":           {value: quicwire.OpOverlayListMACs, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMExportBundle":          {value: quicwire.OpVTPMExportBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayAllocateIP":         {value: quicwire.OpGatewayAllocateIP, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpOverlayForgetMAC":          {value: quicwire.OpOverlayForgetMAC, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpOverlayTunnelStats":        {value: quicwire.OpOverlayTunnelStats, mode: categorySub, family: "overlay", category: quicwire.OpOverlayCategory},
	"OpVTPMImportBundle":          {value: quicwire.OpVTPMImportBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayReleaseIP":          {value: quicwire.OpGatewayReleaseIP, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMValidateBundle":        {value: quicwire.OpVTPMValidateBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayListAllocations":    {value: quicwire.OpGatewayListAllocations, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMGetBundlePath":         {value: quicwire.OpVTPMGetBundlePath, mode: wireDirect, family: "vtpm"},
	"OpGatewayCreateIPAMPool":     {value: quicwire.OpGatewayCreateIPAMPool, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMGetSocketPath":         {value: quicwire.OpVTPMGetSocketPath, mode: wireDirect, family: "vtpm"},
	"OpGatewayDeleteIPAMPool":     {value: quicwire.OpGatewayDeleteIPAMPool, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMGetNVRAMPath":          {value: quicwire.OpVTPMGetNVRAMPath, mode: wireDirect, family: "vtpm"},
	"OpGatewayGetIPAMPool":        {value: quicwire.OpGatewayGetIPAMPool, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMGetBundle":             {value: quicwire.OpVTPMGetBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayUpdateIPAMPool":     {value: quicwire.OpGatewayUpdateIPAMPool, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMIsRunning":             {value: quicwire.OpVTPMIsRunning, mode: wireDirect, family: "vtpm"},
	"OpGatewayListNetworkZones":   {value: quicwire.OpGatewayListNetworkZones, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMCreate":                {value: quicwire.OpVTPMCreate, mode: wireDirect, family: "vtpm"},
	"OpGatewayCreateNetworkZone":  {value: quicwire.OpGatewayCreateNetworkZone, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMDelete":                {value: quicwire.OpVTPMDelete, mode: wireDirect, family: "vtpm"},
	"OpGatewayUpdateNetworkZone":  {value: quicwire.OpGatewayUpdateNetworkZone, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMStart":                 {value: quicwire.OpVTPMStart, mode: wireDirect, family: "vtpm"},
	"OpGatewayDeleteNetworkZone":  {value: quicwire.OpGatewayDeleteNetworkZone, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMStop":                  {value: quicwire.OpVTPMStop, mode: wireDirect, family: "vtpm"},
	"OpGatewaySnapshot":           {value: quicwire.OpGatewaySnapshot, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayListSnapshots":      {value: quicwire.OpGatewayListSnapshots, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayAdmittedVTEP":       {value: quicwire.OpGatewayAdmittedVTEP, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayListAdmittedVTEPs":  {value: quicwire.OpGatewayListAdmittedVTEPs, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayLBAddVIP":           {value: quicwire.OpGatewayLBAddVIP, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayLBRemoveVIP":        {value: quicwire.OpGatewayLBRemoveVIP, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayLBGetVIP":           {value: quicwire.OpGatewayLBGetVIP, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayLBListVIPs":         {value: quicwire.OpGatewayLBListVIPs, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayLBSetVIPBackends":   {value: quicwire.OpGatewayLBSetVIPBackends, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayLBStatus":           {value: quicwire.OpGatewayLBStatus, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayPerfFlows":          {value: quicwire.OpGatewayPerfFlows, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayPerfDatapath":       {value: quicwire.OpGatewayPerfDatapath, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayPerfConntrack":      {value: quicwire.OpGatewayPerfConntrack, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpGatewayNAT64Status":        {value: quicwire.OpGatewayNAT64Status, mode: categorySub, family: "gateway", category: quicwire.OpGatewayCategory},
	"OpVTPMGetState":              {value: quicwire.OpVTPMGetState, mode: wireDirect, family: "vtpm"},
	"OpVTPMList":                  {value: quicwire.OpVTPMList, mode: wireDirect, family: "vtpm"},
	"OpVTPMGetEK":                 {value: quicwire.OpVTPMGetEK, mode: wireDirect, family: "vtpm"},
	"OpVTPMGetAK":                 {value: quicwire.OpVTPMGetAK, mode: wireDirect, family: "vtpm"},
	"OpVTPMCreateAK":              {value: quicwire.OpVTPMCreateAK, mode: wireDirect, family: "vtpm"},
	"OpVTPMQuote":                 {value: quicwire.OpVTPMQuote, mode: wireDirect, family: "vtpm"},
	"OpVTPMVerifyQuote":           {value: quicwire.OpVTPMVerifyQuote, mode: wireDirect, family: "vtpm"},
	"OpVTPMExtendPCR":             {value: quicwire.OpVTPMExtendPCR, mode: wireDirect, family: "vtpm"},
	"OpVTPMReadPCR":               {value: quicwire.OpVTPMReadPCR, mode: wireDirect, family: "vtpm"},
	"OpVTPMSeal":                  {value: quicwire.OpVTPMSeal, mode: wireDirect, family: "vtpm"},
	"OpVTPMUnseal":                {value: quicwire.OpVTPMUnseal, mode: wireDirect, family: "vtpm"},
	"OpVTPMGetRandom":             {value: quicwire.OpVTPMGetRandom, mode: wireDirect, family: "vtpm"},
	"OpDNSAddRecord":              {value: quicwire.OpDNSAddRecord, mode: wireDirect, family: "dns"},
	"OpDNSDeleteRecord":           {value: quicwire.OpDNSDeleteRecord, mode: wireDirect, family: "dns"},
	"OpDNSUpdateRecord":           {value: quicwire.OpDNSUpdateRecord, mode: wireDirect, family: "dns"},
	"OpDNSGetRecord":              {value: quicwire.OpDNSGetRecord, mode: wireDirect, family: "dns"},
	"OpDNSListRecords":            {value: quicwire.OpDNSListRecords, mode: wireDirect, family: "dns"},
	"OpDNSAddZone":                {value: quicwire.OpDNSAddZone, mode: wireDirect, family: "dns"},
	"OpDNSDeleteZone":             {value: quicwire.OpDNSDeleteZone, mode: wireDirect, family: "dns"},
	"OpDNSGetZone":                {value: quicwire.OpDNSGetZone, mode: wireDirect, family: "dns"},
	"OpDNSListZones":              {value: quicwire.OpDNSListZones, mode: wireDirect, family: "dns"},
	"OpDNSResolve":                {value: quicwire.OpDNSResolve, mode: wireDirect, family: "dns"},
	"OpDNSGetConfig":              {value: quicwire.OpDNSGetConfig, mode: wireDirect, family: "dns"},
	"OpDNSGetMetrics":             {value: quicwire.OpDNSGetMetrics, mode: wireDirect, family: "dns"},
	"OpOverlayCategory":           {value: quicwire.OpOverlayCategory, mode: wireDirect, family: "overlay"},
	"OpGatewayCategory":           {value: quicwire.OpGatewayCategory, mode: wireDirect, family: "gateway"},
	"OpDeviceRegister":            {value: quicwire.OpDeviceRegister, mode: wireDirect, family: "device"},
	"OpDeviceUnregister":          {value: quicwire.OpDeviceUnregister, mode: wireDirect, family: "device"},
	"OpDeviceGet":                 {value: quicwire.OpDeviceGet, mode: wireDirect, family: "device"},
	"OpDeviceList":                {value: quicwire.OpDeviceList, mode: wireDirect, family: "device"},
	"OpDeviceUpdate":              {value: quicwire.OpDeviceUpdate, mode: wireDirect, family: "device"},
	"OpDeviceGetProfile":          {value: quicwire.OpDeviceGetProfile, mode: wireDirect, family: "device"},
	"OpDeviceSetProfile":          {value: quicwire.OpDeviceSetProfile, mode: wireDirect, family: "device"},
	"OpDeviceListProfiles":        {value: quicwire.OpDeviceListProfiles, mode: wireDirect, family: "device"},
	"OpDeviceCreateProfile":       {value: quicwire.OpDeviceCreateProfile, mode: wireDirect, family: "device"},
	"OpDeviceDeleteProfile":       {value: quicwire.OpDeviceDeleteProfile, mode: wireDirect, family: "device"},
	"OpDeviceAttest":              {value: quicwire.OpDeviceAttest, mode: wireDirect, family: "device"},
	"OpDeviceActivate":            {value: quicwire.OpDeviceActivate, mode: wireDirect, family: "device"},
	"OpDeviceGetState":            {value: quicwire.OpDeviceGetState, mode: wireDirect, family: "device"},
	"OpIPAMCategory":              {value: quicwire.OpIPAMCategory, mode: wireDirect, family: "ipam"},
	"OpSDNGetPortState":           {value: quicwire.OpSDNGetPortState, mode: wireDirect, family: "sdn"},
	"OpSDNSetPortState":           {value: quicwire.OpSDNSetPortState, mode: wireDirect, family: "sdn"},
	"OpSDNListPorts":              {value: quicwire.OpSDNListPorts, mode: wireDirect, family: "sdn"},
	"OpSDNGetFlow":                {value: quicwire.OpSDNGetFlow, mode: wireDirect, family: "sdn"},
	"OpSDNAddFlow":                {value: quicwire.OpSDNAddFlow, mode: wireDirect, family: "sdn"},
	"OpSDNDeleteFlow":             {value: quicwire.OpSDNDeleteFlow, mode: wireDirect, family: "sdn"},
	"OpSDNListFlows":              {value: quicwire.OpSDNListFlows, mode: wireDirect, family: "sdn"},
	"OpSDNApplyPolicy":            {value: quicwire.OpSDNApplyPolicy, mode: wireDirect, family: "sdn"},
	"OpSDNGetPolicy":              {value: quicwire.OpSDNGetPolicy, mode: wireDirect, family: "sdn"},
	"OpSDNListPolicies":           {value: quicwire.OpSDNListPolicies, mode: wireDirect, family: "sdn"},
	"OpSDNGetBridge":              {value: quicwire.OpSDNGetBridge, mode: wireDirect, family: "sdn"},
	"OpSDNListBridges":            {value: quicwire.OpSDNListBridges, mode: wireDirect, family: "sdn"},
	"OpSDNGetMetrics":             {value: quicwire.OpSDNGetMetrics, mode: wireDirect, family: "sdn"},
	"OpSDNSetVLAN":                {value: quicwire.OpSDNSetVLAN, mode: wireDirect, family: "sdn"},
	"OpSDNGetVLAN":                {value: quicwire.OpSDNGetVLAN, mode: wireDirect, family: "sdn"},
	"OpSDNGetPort":                {value: quicwire.OpSDNGetPort, mode: wireDirect, family: "sdn"},
	"OpNTPCategory":               {value: quicwire.OpNTPCategory, mode: wireDirect, family: "ntp"},
	"OpIAMCategory":               {value: quicwire.OpIAMCategory, mode: wireDirect, family: "iam"},
	"OpVPNCategory":               {value: quicwire.OpVPNCategory, mode: wireDirect, family: "vpn"},
	"OpCacheCategory":             {value: quicwire.OpCacheCategory, mode: wireDirect, family: "cache"},
	"OpSchedulerCategory":         {value: quicwire.OpSchedulerCategory, mode: wireDirect, family: "scheduler"},
	"OpMessagingCategory":         {value: quicwire.OpMessagingCategory, mode: wireDirect, family: "messaging"},
	"OpIDevIDGenerate":            {value: quicwire.OpIDevIDGenerate, mode: wireDirect, family: "tpm2"},
	"OpIDevIDInfo":                {value: quicwire.OpIDevIDInfo, mode: wireDirect, family: "tpm2"},
	"OpIDevIDDelete":              {value: quicwire.OpIDevIDDelete, mode: wireDirect, family: "tpm2"},
	"OpIDevIDCSR":                 {value: quicwire.OpIDevIDCSR, mode: wireDirect, family: "tpm2"},
	"OpIDevIDInstallCert":         {value: quicwire.OpIDevIDInstallCert, mode: wireDirect, family: "tpm2"},
	"OpIDevIDGetCert":             {value: quicwire.OpIDevIDGetCert, mode: wireDirect, family: "tpm2"},
	"OpIAKGenerate":               {value: quicwire.OpIAKGenerate, mode: wireDirect, family: "tpm2"},
	"OpIAKInfo":                   {value: quicwire.OpIAKInfo, mode: wireDirect, family: "tpm2"},
	"OpIAKDelete":                 {value: quicwire.OpIAKDelete, mode: wireDirect, family: "tpm2"},
	"OpIAKCSR":                    {value: quicwire.OpIAKCSR, mode: wireDirect, family: "tpm2"},
	"OpVMCreate":                  {value: quicwire.OpVMCreate, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMDelete":                  {value: quicwire.OpVMDelete, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMStart":                   {value: quicwire.OpVMStart, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMStop":                    {value: quicwire.OpVMStop, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMGet":                     {value: quicwire.OpVMGet, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMList":                    {value: quicwire.OpVMList, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMExtendedCategory":        {value: quicwire.OpVMExtendedCategory, mode: wireDirect, family: "vm"},
	"OpIAKInstallCert":            {value: quicwire.OpIAKInstallCert, mode: wireDirect, family: "tpm2"},
	"OpIAKGetCert":                {value: quicwire.OpIAKGetCert, mode: wireDirect, family: "tpm2"},
	"OpDeviceAttributes":          {value: quicwire.OpDeviceAttributes, mode: wireDirect, family: "tpm2"},
	"OpActivateCredential":        {value: quicwire.OpActivateCredential, mode: wireDirect, family: "tpm2"},
	"OpContainerGet":              {value: quicwire.OpContainerGet, mode: wireDirect, family: "container"},
	"OpAttestQuote":               {value: quicwire.OpAttestQuote, mode: wireDirect, family: "attestation"},
	"OpAttestVerify":              {value: quicwire.OpAttestVerify, mode: wireDirect, family: "attestation"},
	"OpAttestCollectHost":         {value: quicwire.OpAttestCollectHost, mode: wireDirect, family: "attestation"},
	"OpAttestGetAK":               {value: quicwire.OpAttestGetAK, mode: wireDirect, family: "attestation"},
	"OpAttestChallenge":           {value: quicwire.OpAttestChallenge, mode: wireDirect, family: "attestation"},
	"OpAttestPollVerdicts":        {value: quicwire.OpAttestPollVerdicts, mode: wireDirect, family: "attestation"},
	"OpAttestGetManifest":         {value: quicwire.OpAttestGetManifest, mode: wireDirect, family: "attestation"},
	"OpAttestGetReport":           {value: quicwire.OpAttestGetReport, mode: wireDirect, family: "attestation"},
	"OpAttestGetPCRs":             {value: quicwire.OpAttestGetPCRs, mode: wireDirect, family: "attestation"},
	"OpAttestGetReportByID":       {value: quicwire.OpAttestGetReportByID, mode: wireDirect, family: "attestation"},
	"OpHasIDevID":                 {value: quicwire.OpHasIDevID, mode: wireDirect, family: "tpm2"},
	"OpHasIAK":                    {value: quicwire.OpHasIAK, mode: wireDirect, family: "tpm2"},
	"OpIDevIDDeleteCert":          {value: quicwire.OpIDevIDDeleteCert, mode: wireDirect, family: "tpm2"},
	"OpIAKDeleteCert":             {value: quicwire.OpIAKDeleteCert, mode: wireDirect, family: "tpm2"},
	"OpAttestBuildManifest":       {value: quicwire.OpAttestBuildManifest, mode: wireDirect, family: "attestation"},
	"OpAttestVerifyManifest":      {value: quicwire.OpAttestVerifyManifest, mode: wireDirect, family: "attestation"},
	"OpAttestHost":                {value: quicwire.OpAttestHost, mode: wireDirect, family: "attestation"},
	"OpAttestVMWorkload":          {value: quicwire.OpAttestVMWorkload, mode: wireDirect, family: "attestation"},
	"OpCertIssue":                 {value: quicwire.OpCertIssue, mode: wireDirect, family: "ca"},
	"OpCertRevoke":                {value: quicwire.OpCertRevoke, mode: wireDirect, family: "ca"},
	"OpCertRenew":                 {value: quicwire.OpCertRenew, mode: wireDirect, family: "ca"},
	"OpCertGet":                   {value: quicwire.OpCertGet, mode: wireDirect, family: "ca"},
	"OpCertList":                  {value: quicwire.OpCertList, mode: wireDirect, family: "ca"},
	"OpCertVerify":                {value: quicwire.OpCertVerify, mode: wireDirect, family: "ca"},
	"OpCertGetChain":              {value: quicwire.OpCertGetChain, mode: wireDirect, family: "ca"},
	"OpCertGetCRL":                {value: quicwire.OpCertGetCRL, mode: wireDirect, family: "ca"},
	"OpCertGetOCSP":               {value: quicwire.OpCertGetOCSP, mode: wireDirect, family: "ca"},
	"OpDaemonStatus":              {value: quicwire.OpDaemonStatus, mode: wireDirect, family: "daemon"},
	"OpDaemonVersion":             {value: quicwire.OpDaemonVersion, mode: wireDirect, family: "daemon"},
	"OpDaemonListServices":        {value: quicwire.OpDaemonListServices, mode: wireDirect, family: "daemon"},
	"OpDaemonGetService":          {value: quicwire.OpDaemonGetService, mode: wireDirect, family: "daemon"},
	"OpDaemonStartService":        {value: quicwire.OpDaemonStartService, mode: wireDirect, family: "daemon"},
	"OpDaemonStopService":         {value: quicwire.OpDaemonStopService, mode: wireDirect, family: "daemon"},
	"OpDaemonRestartService":      {value: quicwire.OpDaemonRestartService, mode: wireDirect, family: "daemon"},
	"OpClusterCategory":           {value: quicwire.OpClusterCategory, mode: wireDirect, family: "cluster"},
	"OpJWTVerify":                 {value: quicwire.OpJWTVerify, mode: reservedByte, family: "reserved"},
	"OpJWTRefresh":                {value: quicwire.OpJWTRefresh, mode: reservedByte, family: "reserved"},
	"OpJWTRevoke":                 {value: quicwire.OpJWTRevoke, mode: reservedByte, family: "reserved"},
	"OpJWTGetKeys":                {value: quicwire.OpJWTGetKeys, mode: reservedByte, family: "reserved"},
	"OpAuthLogin":                 {value: quicwire.OpAuthLogin, mode: reservedByte, family: "reserved"},
	"OpAuthLogout":                {value: quicwire.OpAuthLogout, mode: reservedByte, family: "reserved"},
	"OpAuthCheck":                 {value: quicwire.OpAuthCheck, mode: reservedByte, family: "reserved"},
	"OpDaemonListProtocols":       {value: quicwire.OpDaemonListProtocols, mode: wireDirect, family: "daemon"},
	"OpTPM2Category":              {value: quicwire.OpTPM2Category, mode: wireDirect, family: "tpm2category"},
	"OpCeremonyCategory":          {value: quicwire.OpCeremonyCategory, mode: wireDirect, family: "ceremony"},
	"OpPIVCategory":               {value: quicwire.OpPIVCategory, mode: wireDirect, family: "piv"},
	"OpLUKSCategory":              {value: quicwire.OpLUKSCategory, mode: wireDirect, family: "luks"},
	"OpFIDO2Category":             {value: quicwire.OpFIDO2Category, mode: wireDirect, family: "fido2"},
	"OpTenantBarrierCategory":     {value: quicwire.OpTenantBarrierCategory, mode: wireDirect, family: "tenant"},
	"OpBMCCategory":               {value: quicwire.OpBMCCategory, mode: wireDirect, family: "bmc"},
	"OpCAInfo":                    {value: quicwire.OpCAInfo, mode: wireDirect, family: "ca"},
	"OpCAIssue":                   {value: quicwire.OpCAIssue, mode: wireDirect, family: "ca"},
	"OpCARevoke":                  {value: quicwire.OpCARevoke, mode: wireDirect, family: "ca"},
	"OpCARenew":                   {value: quicwire.OpCARenew, mode: wireDirect, family: "ca"},
	"OpCAGet":                     {value: quicwire.OpCAGet, mode: wireDirect, family: "ca"},
	"OpCAList":                    {value: quicwire.OpCAList, mode: wireDirect, family: "ca"},
	"OpCAVerify":                  {value: quicwire.OpCAVerify, mode: wireDirect, family: "ca"},
	"OpCACRL":                     {value: quicwire.OpCACRL, mode: wireDirect, family: "ca"},
	"OpCABundle":                  {value: quicwire.OpCABundle, mode: wireDirect, family: "ca"},
	"OpIAMUserCreate":             {value: quicwire.OpIAMUserCreate, mode: wireDirect, family: "iam"},
	"OpAttestCreatePolicy":        {value: quicwire.OpAttestCreatePolicy, mode: shadowedByte, family: "iam"},
	"OpIAMUserDelete":             {value: quicwire.OpIAMUserDelete, mode: wireDirect, family: "iam"},
	"OpAttestListPolicies":        {value: quicwire.OpAttestListPolicies, mode: shadowedByte, family: "iam"},
	"OpIAMUserGet":                {value: quicwire.OpIAMUserGet, mode: wireDirect, family: "iam"},
	"OpIAMUserList":               {value: quicwire.OpIAMUserList, mode: wireDirect, family: "iam"},
	"OpIAMUserUpdate":             {value: quicwire.OpIAMUserUpdate, mode: wireDirect, family: "iam"},
	"OpContainerList":             {value: quicwire.OpContainerList, mode: wireDirect, family: "container"},
	"OpContainerLogs":             {value: quicwire.OpContainerLogs, mode: wireDirect, family: "container"},
	"OpSDNCreateBridge":           {value: quicwire.OpSDNCreateBridge, mode: wireDirect, family: "sdn"},
	"OpSDNDeleteBridge":           {value: quicwire.OpSDNDeleteBridge, mode: wireDirect, family: "sdn"},
	"OpSDNCreatePort":             {value: quicwire.OpSDNCreatePort, mode: wireDirect, family: "sdn"},
	"OpSDNDeletePort":             {value: quicwire.OpSDNDeletePort, mode: wireDirect, family: "sdn"},
	"OpSDNDeletePolicy":           {value: quicwire.OpSDNDeletePolicy, mode: wireDirect, family: "sdn"},
	"OpIAMRoleCreate":             {value: quicwire.OpIAMRoleCreate, mode: wireDirect, family: "iam"},
	"OpIAMRoleDelete":             {value: quicwire.OpIAMRoleDelete, mode: wireDirect, family: "iam"},
	"OpVMRestart":                 {value: quicwire.OpVMRestart, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMRoleGet":                {value: quicwire.OpIAMRoleGet, mode: wireDirect, family: "iam"},
	"OpVMSuspend":                 {value: quicwire.OpVMSuspend, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMRoleList":               {value: quicwire.OpIAMRoleList, mode: wireDirect, family: "iam"},
	"OpVMResume":                  {value: quicwire.OpVMResume, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMRoleAssign":             {value: quicwire.OpIAMRoleAssign, mode: wireDirect, family: "iam"},
	"OpVMAttest":                  {value: quicwire.OpVMAttest, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMRoleRevoke":             {value: quicwire.OpIAMRoleRevoke, mode: wireDirect, family: "iam"},
	"OpIAMGroupCreate":            {value: quicwire.OpIAMGroupCreate, mode: wireDirect, family: "iam"},
	"OpVMSnapshotCreate":          {value: quicwire.OpVMSnapshotCreate, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMGroupDelete":            {value: quicwire.OpIAMGroupDelete, mode: wireDirect, family: "iam"},
	"OpVMSnapshotRestore":         {value: quicwire.OpVMSnapshotRestore, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMGroupGet":               {value: quicwire.OpIAMGroupGet, mode: wireDirect, family: "iam"},
	"OpVMSnapshotDelete":          {value: quicwire.OpVMSnapshotDelete, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMGroupList":              {value: quicwire.OpIAMGroupList, mode: wireDirect, family: "iam"},
	"OpVMSnapshotList":            {value: quicwire.OpVMSnapshotList, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpIAMGroupAddMember":         {value: quicwire.OpIAMGroupAddMember, mode: wireDirect, family: "iam"},
	"OpVMVerifyAttest":            {value: quicwire.OpVMVerifyAttest, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpKMSGenerateKey":            {value: quicwire.OpKMSGenerateKey, mode: wireDirect, family: "kms"},
	"OpKMSImportKey":              {value: quicwire.OpKMSImportKey, mode: wireDirect, family: "kms"},
	"OpKMSGetKey":                 {value: quicwire.OpKMSGetKey, mode: wireDirect, family: "kms"},
	"OpKMSListKeys":               {value: quicwire.OpKMSListKeys, mode: wireDirect, family: "kms"},
	"OpKMSDeleteKey":              {value: quicwire.OpKMSDeleteKey, mode: wireDirect, family: "kms"},
	"OpKMSRotateKey":              {value: quicwire.OpKMSRotateKey, mode: wireDirect, family: "kms"},
	"OpKMSUpdateKeyStatus":        {value: quicwire.OpKMSUpdateKeyStatus, mode: wireDirect, family: "kms"},
	"OpKMSExportKey":              {value: quicwire.OpKMSExportKey, mode: wireDirect, family: "kms"},
	"OpKMSGetKeyVersions":         {value: quicwire.OpKMSGetKeyVersions, mode: wireDirect, family: "kms"},
	"OpKMSBackendStatus":          {value: quicwire.OpKMSBackendStatus, mode: wireDirect, family: "kms"},
	"OpKMSBatchEncrypt":           {value: quicwire.OpKMSBatchEncrypt, mode: wireDirect, family: "kms"},
	"OpKMSBatchDecrypt":           {value: quicwire.OpKMSBatchDecrypt, mode: wireDirect, family: "kms"},
	"OpSwitchCategory":            {value: quicwire.OpSwitchCategory, mode: wireDirect, family: "switch"},
	"OpKMSExtendedCategory":       {value: quicwire.OpKMSExtendedCategory, mode: wireDirect, family: "kms"},
	"OpSecretsCategory":           {value: quicwire.OpSecretsCategory, mode: wireDirect, family: "secrets"},
	"OpProvisioningCategory":      {value: quicwire.OpProvisioningCategory, mode: wireDirect, family: "configdelivery"},
	"OpKMSEncrypt":                {value: quicwire.OpKMSEncrypt, mode: wireDirect, family: "kms"},
	"OpKMSDecrypt":                {value: quicwire.OpKMSDecrypt, mode: wireDirect, family: "kms"},
	"OpKMSSign":                   {value: quicwire.OpKMSSign, mode: wireDirect, family: "kms"},
	"OpKMSVerify":                 {value: quicwire.OpKMSVerify, mode: wireDirect, family: "kms"},
	"OpKMSGenerateRandom":         {value: quicwire.OpKMSGenerateRandom, mode: wireDirect, family: "kms"},
	"OpKMSHash":                   {value: quicwire.OpKMSHash, mode: wireDirect, family: "kms"},
	"OpKMSHMAC":                   {value: quicwire.OpKMSHMAC, mode: wireDirect, family: "kms"},
	"OpKMSVerifyHMAC":             {value: quicwire.OpKMSVerifyHMAC, mode: wireDirect, family: "kms"},
	"OpKMSRewrap":                 {value: quicwire.OpKMSRewrap, mode: wireDirect, family: "kms"},
	"OpKMSGenerateDataKey":        {value: quicwire.OpKMSGenerateDataKey, mode: wireDirect, family: "kms"},
	"OpKMSGenerateWrappedDataKey": {value: quicwire.OpKMSGenerateWrappedDataKey, mode: wireDirect, family: "kms"},
	"OpTenantList":                {value: quicwire.OpTenantList, mode: wireDirect, family: "tenant"},
	"OpTenantGet":                 {value: quicwire.OpTenantGet, mode: wireDirect, family: "tenant"},
	"OpTenantGetByName":           {value: quicwire.OpTenantGetByName, mode: wireDirect, family: "tenant"},
	"OpTenantCreate":              {value: quicwire.OpTenantCreate, mode: wireDirect, family: "tenant"},
	"OpTenantUpdate":              {value: quicwire.OpTenantUpdate, mode: wireDirect, family: "tenant"},
	"OpTenantDelete":              {value: quicwire.OpTenantDelete, mode: wireDirect, family: "tenant"},
	"OpTenantSuspend":             {value: quicwire.OpTenantSuspend, mode: wireDirect, family: "tenant"},
	"OpTenantResume":              {value: quicwire.OpTenantResume, mode: wireDirect, family: "tenant"},
	"OpTenantGetQuotas":           {value: quicwire.OpTenantGetQuotas, mode: wireDirect, family: "tenant"},
	"OpTenantUpdateQuotas":        {value: quicwire.OpTenantUpdateQuotas, mode: wireDirect, family: "tenant"},
	"OpTenantGetUsage":            {value: quicwire.OpTenantGetUsage, mode: wireDirect, family: "tenant"},
	"OpTenantCheckQuota":          {value: quicwire.OpTenantCheckQuota, mode: wireDirect, family: "tenant"},
	"OpTenantSync":                {value: quicwire.OpTenantSync, mode: wireDirect, family: "tenant"},
	"OpTenantRotateDEK":           {value: quicwire.OpTenantRotateDEK, mode: wireDirect, family: "tenant"},
	"OpTenantGetDEKStatus":        {value: quicwire.OpTenantGetDEKStatus, mode: wireDirect, family: "tenant"},
	"OpContainerAttest":           {value: quicwire.OpContainerAttest, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpPXEListDevices":            {value: quicwire.OpPXEListDevices, mode: wireDirect, family: "pxe"},
	"OpAttestContainerWorkload":   {value: quicwire.OpAttestContainerWorkload, mode: shadowedByte, family: "pxe"},
	"OpPXEGetDevice":              {value: quicwire.OpPXEGetDevice, mode: wireDirect, family: "pxe"},
	"OpAttestDeviceWorkload":      {value: quicwire.OpAttestDeviceWorkload, mode: shadowedByte, family: "pxe"},
	"OpPXERegisterDevice":         {value: quicwire.OpPXERegisterDevice, mode: wireDirect, family: "pxe"},
	"OpAttestListReports":         {value: quicwire.OpAttestListReports, mode: shadowedByte, family: "pxe"},
	"OpPXEUpdateState":            {value: quicwire.OpPXEUpdateState, mode: wireDirect, family: "pxe"},
	"OpDEKCreate":                 {value: quicwire.OpDEKCreate, mode: reservedByte, family: "reserved"},
	"OpDEKGet":                    {value: quicwire.OpDEKGet, mode: reservedByte, family: "reserved"},
	"OpDEKList":                   {value: quicwire.OpDEKList, mode: reservedByte, family: "reserved"},
	"OpDEKDelete":                 {value: quicwire.OpDEKDelete, mode: reservedByte, family: "reserved"},
	"OpDEKRotate":                 {value: quicwire.OpDEKRotate, mode: reservedByte, family: "reserved"},
	"OpDEKGetStatus":              {value: quicwire.OpDEKGetStatus, mode: reservedByte, family: "reserved"},
	"OpIAMGroupRemoveMember":      {value: quicwire.OpIAMGroupRemoveMember, mode: wireDirect, family: "iam"},
	"OpIAMCheckPermission":        {value: quicwire.OpIAMCheckPermission, mode: wireDirect, family: "iam"},
	"OpIAMAuthenticate":           {value: quicwire.OpIAMAuthenticate, mode: wireDirect, family: "iam"},
	"OpIAMTokenCreate":            {value: quicwire.OpIAMTokenCreate, mode: wireDirect, family: "iam"},
	"OpIAMTokenRevoke":            {value: quicwire.OpIAMTokenRevoke, mode: wireDirect, family: "iam"},
	"OpIAMTokenVerify":            {value: quicwire.OpIAMTokenVerify, mode: wireDirect, family: "iam"},
	"OpVMMetrics":                 {value: quicwire.OpVMMetrics, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMAttachDisk":              {value: quicwire.OpVMAttachDisk, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMDetachDisk":              {value: quicwire.OpVMDetachDisk, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMResizeDisk":              {value: quicwire.OpVMResizeDisk, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpVMMigrate":                 {value: quicwire.OpVMMigrate, mode: categorySub, family: "vm", category: quicwire.OpVMExtendedCategory},
	"OpContainerExec":             {value: quicwire.OpContainerExec, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpContainerMetrics":          {value: quicwire.OpContainerMetrics, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpContainerCreate":           {value: quicwire.OpContainerCreate, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpPXEAuthorize":              {value: quicwire.OpPXEAuthorize, mode: wireDirect, family: "pxe"},
	"OpContainerStart":            {value: quicwire.OpContainerStart, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpPXEQuarantine":             {value: quicwire.OpPXEQuarantine, mode: wireDirect, family: "pxe"},
	"OpContainerStop":             {value: quicwire.OpContainerStop, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpPXERetry":                  {value: quicwire.OpPXERetry, mode: wireDirect, family: "pxe"},
	"OpContainerRemove":           {value: quicwire.OpContainerRemove, mode: categorySub, family: "container", category: quicwire.OpVMExtendedCategory},
	"OpPXERemoveDevice":           {value: quicwire.OpPXERemoveDevice, mode: wireDirect, family: "pxe"},
}

// newBareQUICDispatchHandler returns a handler with no services configured
// so every family responds with its distinctive nil-service error.
func newBareQUICDispatchHandler() *QUICServiceHandler {
	return newTestQUICServiceHandler(logging.DefaultLogger())
}

// iamTokenNotImplementedOpcodes are the IAM token operations that return
// StatusNotImplemented by OIDC design (token issuance and revocation happen
// through OIDC, not these QUIC ops). They are still routed to and owned by the
// iam family on the wire; they simply answer NotImplemented instead of the
// iam-unavailable error a bare handler returns for the other iam opcodes,
// OpIAMTokenVerify included.
var iamTokenNotImplementedOpcodes = map[byte]bool{
	quicwire.OpIAMTokenCreate: true,
	quicwire.OpIAMTokenRevoke: true,
}

// deviceIdentityKeyDeleteRefusals are the tpm2-family key-delete opcodes. They
// refuse whatever the TPM state (#304), as the gRPC IDevIDService does, so a
// bare handler answers the refusal instead of the tpm2-unavailable error.
var deviceIdentityKeyDeleteRefusals = map[byte]ErrDeviceIdentityKeyNotDeletable{
	quicwire.OpIDevIDDelete: {Key: "IDevID"},
	quicwire.OpIAKDelete:    {Key: "IAK"},
}

// identityCertDeleteOpcodes are the tpm2-family certificate-delete opcodes.
// They are served by the shared IDevID service, as on gRPC (#704), so a bare
// handler answers that service's absence instead of the tpm2-unavailable error.
var identityCertDeleteOpcodes = map[byte]bool{
	quicwire.OpIDevIDDeleteCert: true,
	quicwire.OpIAKDeleteCert:    true,
}

// assertDispatchFamily drives one request through HandleRequest and
// asserts the response carries the family signature.
func assertDispatchFamily(t *testing.T, h *QUICServiceHandler, opcode byte, payload []byte, family string) {
	t.Helper()

	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: opcode, Payload: payload})
	if resp == nil {
		t.Fatalf("opcode 0x%02X: nil response", opcode)
	}

	// IAM token opcodes are iam-owned on the wire but return
	// StatusNotImplemented by OIDC design (tokens are issued via OIDC, never
	// over the QUIC token ops), rather than the iam-unavailable error the rest
	// of the iam family returns on a bare handler. This is the honest parity
	// with the gRPC IAM service, which returns codes.Unimplemented for the same
	// three RPCs.
	if iamTokenNotImplementedOpcodes[opcode] {
		if resp.Status != quicwire.StatusNotImplemented {
			t.Fatalf("opcode 0x%02X: expected iam-token NotImplemented (OIDC), got status 0x%02X payload %q",
				opcode, resp.Status, resp.Payload)
		}
		return
	}

	if refused, ok := deviceIdentityKeyDeleteRefusals[opcode]; ok {
		if resp.Status != quicwire.StatusFailedPrecondition || string(resp.Payload) != refused.Error() {
			t.Fatalf("opcode 0x%02X: expected key-delete refusal %q, got status 0x%02X payload %q",
				opcode, refused.Error(), resp.Status, resp.Payload)
		}
		return
	}

	if identityCertDeleteOpcodes[opcode] {
		unserved := ErrIDevIDServiceNotConfigured{}
		if resp.Status != quicwire.StatusUnavailable || string(resp.Payload) != unserved.Error() {
			t.Fatalf("opcode 0x%02X: expected %q, got status 0x%02X payload %q",
				opcode, unserved.Error(), resp.Status, resp.Payload)
		}
		return
	}

	// A reserved byte has no permission in the authorization catalog, so the
	// guard refuses it before it reaches the dispatcher.
	if family == "reserved" {
		wantBody := quic.ErrOperationNotClassified{Opcode: opcode}.Error()
		if resp.Status != quicwire.StatusPermissionDenied {
			t.Fatalf("opcode 0x%02X: expected reserved (status 0x%02X), got status 0x%02X payload %q",
				opcode, quicwire.StatusPermissionDenied, resp.Status, resp.Payload)
		}
		if string(resp.Payload) != wantBody {
			t.Fatalf("opcode 0x%02X: expected reserved payload %q, got %q", opcode, wantBody, resp.Payload)
		}
		return
	}

	spec, ok := quicDispatchFamilies[family]
	if !ok {
		t.Fatalf("opcode 0x%02X: unknown family %q in test table", opcode, family)
	}
	if resp.Status != spec.status {
		t.Fatalf("opcode 0x%02X: expected family %q status 0x%02X, got status 0x%02X payload %q",
			opcode, family, spec.status, resp.Status, resp.Payload)
	}
	if spec.body != "" && string(resp.Payload) != spec.body {
		t.Fatalf("opcode 0x%02X: expected family %q payload %q, got %q",
			opcode, family, spec.body, resp.Payload)
	}
}

// TestQUICDispatchWireOwnership drives every byte of the single-byte
// opcode space through HandleRequest and asserts it reaches the family
// that owns the byte, pinning the whole dispatch map against shadowing.
func TestQUICDispatchWireOwnership(t *testing.T) {
	t.Parallel()

	// Coverage sanity: every byte covered by exactly one range.
	for op := 0; op <= 0xFF; op++ {
		covering := 0
		for _, r := range quicWireOwners {
			if byte(op) >= r.lo && byte(op) <= r.hi {
				covering++
			}
		}
		if covering != 1 {
			t.Fatalf("byte 0x%02X covered by %d ownership ranges, want exactly 1", op, covering)
		}
	}

	h := newBareQUICDispatchHandler()
	for _, r := range quicWireOwners {
		for op := int(r.lo); op <= int(r.hi); op++ {
			opcode := byte(op)
			family := r.family
			t.Run(fmt.Sprintf("0x%02X_%s", opcode, family), func(t *testing.T) {
				assertDispatchFamily(t, h, opcode, dispatchProbePayload(opcode, family), family)
			})
		}
	}
}

// TestQUICDispatchOpcodeConstantIntent drives every exported opcode
// constant through HandleRequest using its documented framing (direct,
// category sub-opcode, shadowed byte, or reserved) and asserts it reaches
// the intended service family.
func TestQUICDispatchOpcodeConstantIntent(t *testing.T) {
	t.Parallel()

	h := newBareQUICDispatchHandler()
	for name, intent := range quicDispatchOpcodeIntents {
		t.Run(name, func(t *testing.T) {
			switch intent.mode {
			case categorySub:
				// Sub-opcode framing: category opcode with the constant in
				// payload[0].
				assertDispatchFamily(t, h, intent.category, []byte{intent.value}, intent.family)
			case wireDirect, shadowedByte:
				assertDispatchFamily(t, h, intent.value, dispatchProbePayload(intent.value, intent.family), intent.family)
			case reservedByte:
				assertDispatchFamily(t, h, intent.value, nil, "reserved")
			default:
				t.Fatalf("unknown intent mode %d", intent.mode)
			}
		})
	}
}

// TestQUICDispatchConstantTableComplete enumerates every exported Op*
// byte constant declared in sdk/go/wire/quicwire sources and asserts the intent
// table above covers each one with the correct byte value, so newly added
// opcodes cannot land without an explicit dispatch-ownership decision.
func TestQUICDispatchConstantTableComplete(t *testing.T) {
	t.Parallel()

	declared := parseQUICOpcodeConstants(t)
	if len(declared) == 0 {
		t.Fatal("no exported Op* byte constants found in sdk/go/wire/quicwire")
	}

	for name, value := range declared {
		intent, ok := quicDispatchOpcodeIntents[name]
		if !ok {
			t.Errorf("constant %s (0x%02X) missing from quicDispatchOpcodeIntents — "+
				"declare its dispatch ownership explicitly", name, value)
			continue
		}
		if intent.value != value {
			t.Errorf("constant %s: intent table has 0x%02X but source declares 0x%02X",
				name, intent.value, value)
		}
	}

	for name := range quicDispatchOpcodeIntents {
		if _, ok := declared[name]; !ok {
			t.Errorf("intent table entry %s no longer declared in sdk/go/wire/quicwire", name)
		}
	}
}

// parseQUICOpcodeConstants scans the sdk/go/wire/quicwire sources (the
// QUIC wire contract, resolved in-tree through root's replace) for exported
// const declarations of type byte whose names start with "Op".
func parseQUICOpcodeConstants(t *testing.T) map[string]byte {
	t.Helper()
	return parseQUICByteConstants(t, func(name string) bool {
		return strings.HasPrefix(name, "Op")
	})
}

// parseQUICByteConstants returns every literal byte constant declared in the
// non-test sources of sdk/go/wire/quicwire whose name satisfies keep.
func parseQUICByteConstants(t *testing.T, keep func(name string) bool) map[string]byte {
	t.Helper()

	quicDir := filepath.Join("..", "..", "..", "sdk", "go", "wire", "quicwire")
	entries, err := os.ReadDir(quicDir)
	if err != nil {
		t.Fatalf("failed to read sdk/go/wire/quicwire: %v", err)
	}

	fset := token.NewFileSet()
	consts := make(map[string]byte)

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(quicDir, name), nil, 0)
		if err != nil {
			t.Fatalf("failed to parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				ident, ok := vs.Type.(*ast.Ident)
				if !ok || ident.Name != "byte" {
					continue
				}
				for i, cname := range vs.Names {
					if !keep(cname.Name) || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.INT {
						continue
					}
					v, err := strconv.ParseUint(lit.Value, 0, 8)
					if err != nil {
						t.Fatalf("constant %s: cannot parse value %s: %v", cname.Name, lit.Value, err)
					}
					consts[cname.Name] = byte(v)
				}
			}
		}
	}

	return consts
}
