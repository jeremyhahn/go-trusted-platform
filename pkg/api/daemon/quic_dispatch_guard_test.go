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
)

// This file pins the QUIC opcode dispatch map in HandleRequest against
// shadowing regressions. Every wire byte (0x00-0xFF) and every exported
// opcode constant in pkg/api/quic is driven through a bare
// QUICServiceHandler (all services nil) and classified by the
// family-identifying nil-service error each handler family returns.
//
// Wire ownership (single-byte opcode space, authoritative):
//
//	0x00-0x02 health            0x90-0x97 reserved (JWT/auth, unwired)
//	0x03-0x1F vtpm              0x98      daemon
//	0x20-0x2D dns               0x99      TPM2 category
//	0x2E      overlay category  0x9A-0x9D ceremony/piv/luks/fido2
//	0x2F      gateway category  0x9E      tenant barrier category
//	0x30-0x3E device            0x9F      bmc category
//	0x3F      ipam category     0xA0-0xA8 ca
//	0x40-0x4F sdn               0xA9-0xAD iam users
//	0x50      ntp category      0xAE-0xAF container
//	0x51-0x55 reserved (ntp)
//	0x56-0x5F tpm2 (idevid)     0xB0-0xB4 sdn extended
//	0x60-0x6A vm (0x69=ext cat) 0xB5-0xBF iam roles/groups
//	0x6B-0x6E tpm2 (iak ext)    0xC0-0xCB kms keys
//	0x6F      container         0xCC-0xCF switch/kms-ext/secrets/prov cats
//	0x70-0x7F attestation       0xD0-0xDA kms crypto
//	  (0x78-0x7B tpm2 carve)    0xDB-0xEB tenant
//	0x80-0x88 ca (certs)        0xEC-0xEF pxe
//	0x89-0x8F daemon            0xF0-0xF5 reserved (DEK, unwired)
//	                            0xF6-0xFB iam extended
//	                            0xFC-0xFF pxe extended
//
// Constants whose byte is owned by another family at the top level
// (documented multiplexing) are encoded explicitly below:
//
//   - Extended VM ops (OpVMRestart..OpVMVerifyAttest, 0xB6-0xBF) and the
//     container ops (create/start/stop/remove/attest) travel as
//     sub-opcodes in payload[0] under quic.OpVMExtendedCategory (0x69).
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
	// the dispatcher must answer unknown-opcode for them.
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
	"health":         {status: quic.StatusOK},
	"vtpm":           {status: quic.StatusUnavailable, body: "QUIC service unavailable: vtpm"},
	"dns":            {status: quic.StatusUnavailable, body: "DNS service not available"},
	"overlay":        {status: quic.StatusUnavailable, body: "service not available: overlay"},
	"gateway":        {status: quic.StatusUnavailable, body: "service not available: gateway"},
	"device":         {status: quic.StatusUnavailable, body: "service not available: device"},
	"ipam":           {status: quic.StatusUnavailable, body: "service not available: ipam"},
	"sdn":            {status: quic.StatusUnavailable, body: "QUIC service unavailable: sdn"},
	"tpm2":           {status: quic.StatusUnavailable, body: "QUIC service unavailable: tpm2"},
	"vm":             {status: quic.StatusUnavailable, body: "QUIC service unavailable: vm"},
	"container":      {status: quic.StatusUnavailable, body: "QUIC service unavailable: container"},
	"attestation":    {status: quic.StatusUnavailable, body: "QUIC service unavailable: attestation"},
	"ca":             {status: quic.StatusUnavailable, body: "service not available: ca"},
	"daemon":         {status: quic.StatusUnavailable, body: "service not available: daemon"},
	"tpm2category":   {status: quic.StatusUnavailable, body: "TPM2 service not available"},
	"ceremony":       {status: quic.StatusUnavailable, body: "service not available: ceremony"},
	"piv":            {status: quic.StatusUnavailable, body: "service not available: piv"},
	"luks":           {status: quic.StatusUnavailable, body: "service not available: luks"},
	"fido2":          {status: quic.StatusUnavailable, body: "service not available: fido2"},
	"tenant":         {status: quic.StatusUnavailable, body: "QUIC service unavailable: tenant"},
	"bmc":            {payload: []byte{quic.BMCSubEnroll}, status: quic.StatusUnavailable, body: "QUIC service unavailable: bmc-enroll"},
	"iam":            {status: quic.StatusUnavailable, body: "QUIC service unavailable: iam"},
	"kms":            {status: quic.StatusUnavailable, body: "QUIC service unavailable: kms"},
	"switch":         {status: quic.StatusUnavailable, body: "QUIC service unavailable: switch"},
	"secrets":        {status: quic.StatusUnavailable, body: "QUIC service unavailable: secrets"},
	"configdelivery": {payload: []byte{quic.ProvisioningSubGetNonce}, status: quic.StatusUnavailable, body: "config delivery service is not available"},
	"ntp":            {payload: []byte{quic.NTPSubGetStatus}, status: quic.StatusUnavailable, body: "QUIC service unavailable: ntp"},
	"pxe":            {status: quic.StatusUnavailable, body: "QUIC service unavailable: pxe"},
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
	{0x20, 0x2D, "dns"},
	{0x2E, 0x2E, "overlay"},
	{0x2F, 0x2F, "gateway"},
	{0x30, 0x3E, "device"},
	{0x3F, 0x3F, "ipam"},
	{0x40, 0x4F, "sdn"},
	{0x50, 0x50, "ntp"},
	{0x51, 0x55, "reserved"},
	{0x56, 0x5F, "tpm2"},
	{0x60, 0x6A, "vm"},
	{0x6B, 0x6E, "tpm2"},
	{0x6F, 0x6F, "container"},
	{0x70, 0x77, "attestation"},
	{0x78, 0x7B, "tpm2"},
	{0x7C, 0x7F, "attestation"},
	{0x80, 0x88, "ca"},
	{0x89, 0x8F, "daemon"},
	{0x90, 0x97, "reserved"},
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
	{0xDB, 0xEB, "tenant"},
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
	"OpHealth":                    {value: quic.OpHealth, mode: wireDirect, family: "health"},
	"OpGatewayStatus":             {value: quic.OpGatewayStatus, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpLiveness":                  {value: quic.OpLiveness, mode: wireDirect, family: "health"},
	"OpOverlayStatus":             {value: quic.OpOverlayStatus, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpGatewaySetMode":            {value: quic.OpGatewaySetMode, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayListVTEPs":          {value: quic.OpOverlayListVTEPs, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpReadiness":                 {value: quic.OpReadiness, mode: wireDirect, family: "health"},
	"OpGatewayBGPStatus":          {value: quic.OpGatewayBGPStatus, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayGetVTEP":            {value: quic.OpOverlayGetVTEP, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMCreateTemplate":        {value: quic.OpVTPMCreateTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayBGPPeers":           {value: quic.OpGatewayBGPPeers, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayListVNIs":           {value: quic.OpOverlayListVNIs, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMGetTemplate":           {value: quic.OpVTPMGetTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayAnnouncePrefix":     {value: quic.OpGatewayAnnouncePrefix, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayCreateVNI":          {value: quic.OpOverlayCreateVNI, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMDeleteTemplate":        {value: quic.OpVTPMDeleteTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayWithdrawPrefix":     {value: quic.OpGatewayWithdrawPrefix, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayDeleteVNI":          {value: quic.OpOverlayDeleteVNI, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMListTemplates":         {value: quic.OpVTPMListTemplates, mode: wireDirect, family: "vtpm"},
	"OpGatewayListPrefixes":       {value: quic.OpGatewayListPrefixes, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayListTunns":          {value: quic.OpOverlayListTunns, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMCloneTemplate":         {value: quic.OpVTPMCloneTemplate, mode: wireDirect, family: "vtpm"},
	"OpGatewayListIPAMPools":      {value: quic.OpGatewayListIPAMPools, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayListMACs":           {value: quic.OpOverlayListMACs, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMExportBundle":          {value: quic.OpVTPMExportBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayAllocateIP":         {value: quic.OpGatewayAllocateIP, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpOverlayForgetMAC":          {value: quic.OpOverlayForgetMAC, mode: categorySub, family: "overlay", category: quic.OpOverlayCategory},
	"OpVTPMImportBundle":          {value: quic.OpVTPMImportBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayReleaseIP":          {value: quic.OpGatewayReleaseIP, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMValidateBundle":        {value: quic.OpVTPMValidateBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayListAllocations":    {value: quic.OpGatewayListAllocations, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMGetBundlePath":         {value: quic.OpVTPMGetBundlePath, mode: wireDirect, family: "vtpm"},
	"OpGatewayCreateIPAMPool":     {value: quic.OpGatewayCreateIPAMPool, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMGetSocketPath":         {value: quic.OpVTPMGetSocketPath, mode: wireDirect, family: "vtpm"},
	"OpGatewayDeleteIPAMPool":     {value: quic.OpGatewayDeleteIPAMPool, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMGetNVRAMPath":          {value: quic.OpVTPMGetNVRAMPath, mode: wireDirect, family: "vtpm"},
	"OpGatewayGetIPAMPool":        {value: quic.OpGatewayGetIPAMPool, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMGetBundle":             {value: quic.OpVTPMGetBundle, mode: wireDirect, family: "vtpm"},
	"OpGatewayUpdateIPAMPool":     {value: quic.OpGatewayUpdateIPAMPool, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMIsRunning":             {value: quic.OpVTPMIsRunning, mode: wireDirect, family: "vtpm"},
	"OpGatewayListNetworkZones":   {value: quic.OpGatewayListNetworkZones, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMCreate":                {value: quic.OpVTPMCreate, mode: wireDirect, family: "vtpm"},
	"OpGatewayCreateNetworkZone":  {value: quic.OpGatewayCreateNetworkZone, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMDelete":                {value: quic.OpVTPMDelete, mode: wireDirect, family: "vtpm"},
	"OpGatewayUpdateNetworkZone":  {value: quic.OpGatewayUpdateNetworkZone, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMStart":                 {value: quic.OpVTPMStart, mode: wireDirect, family: "vtpm"},
	"OpGatewayDeleteNetworkZone":  {value: quic.OpGatewayDeleteNetworkZone, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMStop":                  {value: quic.OpVTPMStop, mode: wireDirect, family: "vtpm"},
	"OpGatewayAssignNetworkZone":  {value: quic.OpGatewayAssignNetworkZone, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayLBAddVIP":           {value: quic.OpGatewayLBAddVIP, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayLBRemoveVIP":        {value: quic.OpGatewayLBRemoveVIP, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayLBGetVIP":           {value: quic.OpGatewayLBGetVIP, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayLBListVIPs":         {value: quic.OpGatewayLBListVIPs, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayLBSetVIPBackends":   {value: quic.OpGatewayLBSetVIPBackends, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayLBStatus":           {value: quic.OpGatewayLBStatus, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayPerfFlows":          {value: quic.OpGatewayPerfFlows, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayPerfDatapath":       {value: quic.OpGatewayPerfDatapath, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpGatewayPerfConntrack":      {value: quic.OpGatewayPerfConntrack, mode: categorySub, family: "gateway", category: quic.OpGatewayCategory},
	"OpVTPMGetState":              {value: quic.OpVTPMGetState, mode: wireDirect, family: "vtpm"},
	"OpVTPMList":                  {value: quic.OpVTPMList, mode: wireDirect, family: "vtpm"},
	"OpVTPMGetEK":                 {value: quic.OpVTPMGetEK, mode: wireDirect, family: "vtpm"},
	"OpVTPMGetAK":                 {value: quic.OpVTPMGetAK, mode: wireDirect, family: "vtpm"},
	"OpVTPMCreateAK":              {value: quic.OpVTPMCreateAK, mode: wireDirect, family: "vtpm"},
	"OpVTPMQuote":                 {value: quic.OpVTPMQuote, mode: wireDirect, family: "vtpm"},
	"OpVTPMVerifyQuote":           {value: quic.OpVTPMVerifyQuote, mode: wireDirect, family: "vtpm"},
	"OpVTPMExtendPCR":             {value: quic.OpVTPMExtendPCR, mode: wireDirect, family: "vtpm"},
	"OpVTPMReadPCR":               {value: quic.OpVTPMReadPCR, mode: wireDirect, family: "vtpm"},
	"OpVTPMSeal":                  {value: quic.OpVTPMSeal, mode: wireDirect, family: "vtpm"},
	"OpVTPMUnseal":                {value: quic.OpVTPMUnseal, mode: wireDirect, family: "vtpm"},
	"OpVTPMGetRandom":             {value: quic.OpVTPMGetRandom, mode: wireDirect, family: "vtpm"},
	"OpDNSAddRecord":              {value: quic.OpDNSAddRecord, mode: wireDirect, family: "dns"},
	"OpDNSDeleteRecord":           {value: quic.OpDNSDeleteRecord, mode: wireDirect, family: "dns"},
	"OpDNSUpdateRecord":           {value: quic.OpDNSUpdateRecord, mode: wireDirect, family: "dns"},
	"OpDNSGetRecord":              {value: quic.OpDNSGetRecord, mode: wireDirect, family: "dns"},
	"OpDNSListRecords":            {value: quic.OpDNSListRecords, mode: wireDirect, family: "dns"},
	"OpDNSAddZone":                {value: quic.OpDNSAddZone, mode: wireDirect, family: "dns"},
	"OpDNSDeleteZone":             {value: quic.OpDNSDeleteZone, mode: wireDirect, family: "dns"},
	"OpDNSGetZone":                {value: quic.OpDNSGetZone, mode: wireDirect, family: "dns"},
	"OpDNSListZones":              {value: quic.OpDNSListZones, mode: wireDirect, family: "dns"},
	"OpDNSResolve":                {value: quic.OpDNSResolve, mode: wireDirect, family: "dns"},
	"OpDNSGetConfig":              {value: quic.OpDNSGetConfig, mode: wireDirect, family: "dns"},
	"OpDNSUpdateConfig":           {value: quic.OpDNSUpdateConfig, mode: wireDirect, family: "dns"},
	"OpDNSGetMetrics":             {value: quic.OpDNSGetMetrics, mode: wireDirect, family: "dns"},
	"OpDNSFlushCache":             {value: quic.OpDNSFlushCache, mode: wireDirect, family: "dns"},
	"OpOverlayCategory":           {value: quic.OpOverlayCategory, mode: wireDirect, family: "overlay"},
	"OpGatewayCategory":           {value: quic.OpGatewayCategory, mode: wireDirect, family: "gateway"},
	"OpDeviceRegister":            {value: quic.OpDeviceRegister, mode: wireDirect, family: "device"},
	"OpDeviceUnregister":          {value: quic.OpDeviceUnregister, mode: wireDirect, family: "device"},
	"OpDeviceGet":                 {value: quic.OpDeviceGet, mode: wireDirect, family: "device"},
	"OpDeviceList":                {value: quic.OpDeviceList, mode: wireDirect, family: "device"},
	"OpDeviceUpdate":              {value: quic.OpDeviceUpdate, mode: wireDirect, family: "device"},
	"OpDeviceGetProfile":          {value: quic.OpDeviceGetProfile, mode: wireDirect, family: "device"},
	"OpDeviceSetProfile":          {value: quic.OpDeviceSetProfile, mode: wireDirect, family: "device"},
	"OpDeviceListProfiles":        {value: quic.OpDeviceListProfiles, mode: wireDirect, family: "device"},
	"OpDeviceCreateProfile":       {value: quic.OpDeviceCreateProfile, mode: wireDirect, family: "device"},
	"OpDeviceDeleteProfile":       {value: quic.OpDeviceDeleteProfile, mode: wireDirect, family: "device"},
	"OpDeviceAttest":              {value: quic.OpDeviceAttest, mode: wireDirect, family: "device"},
	"OpDeviceActivate":            {value: quic.OpDeviceActivate, mode: wireDirect, family: "device"},
	"OpDeviceDeactivate":          {value: quic.OpDeviceDeactivate, mode: wireDirect, family: "device"},
	"OpDeviceGetState":            {value: quic.OpDeviceGetState, mode: wireDirect, family: "device"},
	"OpDeviceGetMetrics":          {value: quic.OpDeviceGetMetrics, mode: wireDirect, family: "device"},
	"OpIPAMCategory":              {value: quic.OpIPAMCategory, mode: wireDirect, family: "ipam"},
	"OpSDNGetPortState":           {value: quic.OpSDNGetPortState, mode: wireDirect, family: "sdn"},
	"OpSDNSetPortState":           {value: quic.OpSDNSetPortState, mode: wireDirect, family: "sdn"},
	"OpSDNListPorts":              {value: quic.OpSDNListPorts, mode: wireDirect, family: "sdn"},
	"OpSDNGetFlow":                {value: quic.OpSDNGetFlow, mode: wireDirect, family: "sdn"},
	"OpSDNAddFlow":                {value: quic.OpSDNAddFlow, mode: wireDirect, family: "sdn"},
	"OpSDNDeleteFlow":             {value: quic.OpSDNDeleteFlow, mode: wireDirect, family: "sdn"},
	"OpSDNListFlows":              {value: quic.OpSDNListFlows, mode: wireDirect, family: "sdn"},
	"OpSDNApplyPolicy":            {value: quic.OpSDNApplyPolicy, mode: wireDirect, family: "sdn"},
	"OpSDNGetPolicy":              {value: quic.OpSDNGetPolicy, mode: wireDirect, family: "sdn"},
	"OpSDNListPolicies":           {value: quic.OpSDNListPolicies, mode: wireDirect, family: "sdn"},
	"OpSDNGetBridge":              {value: quic.OpSDNGetBridge, mode: wireDirect, family: "sdn"},
	"OpSDNListBridges":            {value: quic.OpSDNListBridges, mode: wireDirect, family: "sdn"},
	"OpSDNGetMetrics":             {value: quic.OpSDNGetMetrics, mode: wireDirect, family: "sdn"},
	"OpSDNSetVLAN":                {value: quic.OpSDNSetVLAN, mode: wireDirect, family: "sdn"},
	"OpSDNGetVLAN":                {value: quic.OpSDNGetVLAN, mode: wireDirect, family: "sdn"},
	"OpSDNGetPort":                {value: quic.OpSDNGetPort, mode: wireDirect, family: "sdn"},
	"OpNTPCategory":               {value: quic.OpNTPCategory, mode: wireDirect, family: "ntp"},
	"OpIDevIDGenerate":            {value: quic.OpIDevIDGenerate, mode: wireDirect, family: "tpm2"},
	"OpIDevIDInfo":                {value: quic.OpIDevIDInfo, mode: wireDirect, family: "tpm2"},
	"OpIDevIDDelete":              {value: quic.OpIDevIDDelete, mode: wireDirect, family: "tpm2"},
	"OpIDevIDCSR":                 {value: quic.OpIDevIDCSR, mode: wireDirect, family: "tpm2"},
	"OpIDevIDInstallCert":         {value: quic.OpIDevIDInstallCert, mode: wireDirect, family: "tpm2"},
	"OpIDevIDGetCert":             {value: quic.OpIDevIDGetCert, mode: wireDirect, family: "tpm2"},
	"OpIAKGenerate":               {value: quic.OpIAKGenerate, mode: wireDirect, family: "tpm2"},
	"OpIAKInfo":                   {value: quic.OpIAKInfo, mode: wireDirect, family: "tpm2"},
	"OpIAKDelete":                 {value: quic.OpIAKDelete, mode: wireDirect, family: "tpm2"},
	"OpIAKCSR":                    {value: quic.OpIAKCSR, mode: wireDirect, family: "tpm2"},
	"OpVMCreate":                  {value: quic.OpVMCreate, mode: wireDirect, family: "vm"},
	"OpVMDelete":                  {value: quic.OpVMDelete, mode: wireDirect, family: "vm"},
	"OpVMStart":                   {value: quic.OpVMStart, mode: wireDirect, family: "vm"},
	"OpVMStop":                    {value: quic.OpVMStop, mode: wireDirect, family: "vm"},
	"OpVMGet":                     {value: quic.OpVMGet, mode: wireDirect, family: "vm"},
	"OpVMList":                    {value: quic.OpVMList, mode: wireDirect, family: "vm"},
	"OpVMAttachNet":               {value: quic.OpVMAttachNet, mode: wireDirect, family: "vm"},
	"OpVMDetachNet":               {value: quic.OpVMDetachNet, mode: wireDirect, family: "vm"},
	"OpVMActivate":                {value: quic.OpVMActivate, mode: wireDirect, family: "vm"},
	"OpVMExtendedCategory":        {value: quic.OpVMExtendedCategory, mode: wireDirect, family: "vm"},
	"OpVMGetState":                {value: quic.OpVMGetState, mode: wireDirect, family: "vm"},
	"OpIAKInstallCert":            {value: quic.OpIAKInstallCert, mode: wireDirect, family: "tpm2"},
	"OpIAKGetCert":                {value: quic.OpIAKGetCert, mode: wireDirect, family: "tpm2"},
	"OpDeviceAttributes":          {value: quic.OpDeviceAttributes, mode: wireDirect, family: "tpm2"},
	"OpActivateCredential":        {value: quic.OpActivateCredential, mode: wireDirect, family: "tpm2"},
	"OpContainerGet":              {value: quic.OpContainerGet, mode: wireDirect, family: "container"},
	"OpAttestQuote":               {value: quic.OpAttestQuote, mode: wireDirect, family: "attestation"},
	"OpAttestVerify":              {value: quic.OpAttestVerify, mode: wireDirect, family: "attestation"},
	"OpAttestCollectHost":         {value: quic.OpAttestCollectHost, mode: wireDirect, family: "attestation"},
	"OpAttestGetAK":               {value: quic.OpAttestGetAK, mode: wireDirect, family: "attestation"},
	"OpAttestChallenge":           {value: quic.OpAttestChallenge, mode: wireDirect, family: "attestation"},
	"OpAttestResponse":            {value: quic.OpAttestResponse, mode: wireDirect, family: "attestation"},
	"OpAttestGetManifest":         {value: quic.OpAttestGetManifest, mode: wireDirect, family: "attestation"},
	"OpAttestGetReport":           {value: quic.OpAttestGetReport, mode: wireDirect, family: "attestation"},
	"OpAttestGetPCRs":             {value: quic.OpAttestGetPCRs, mode: wireDirect, family: "attestation"},
	"OpAttestGetReportByID":       {value: quic.OpAttestGetReportByID, mode: wireDirect, family: "attestation"},
	"OpHasIDevID":                 {value: quic.OpHasIDevID, mode: wireDirect, family: "tpm2"},
	"OpHasIAK":                    {value: quic.OpHasIAK, mode: wireDirect, family: "tpm2"},
	"OpIDevIDDeleteCert":          {value: quic.OpIDevIDDeleteCert, mode: wireDirect, family: "tpm2"},
	"OpIAKDeleteCert":             {value: quic.OpIAKDeleteCert, mode: wireDirect, family: "tpm2"},
	"OpAttestBuildManifest":       {value: quic.OpAttestBuildManifest, mode: wireDirect, family: "attestation"},
	"OpAttestVerifyManifest":      {value: quic.OpAttestVerifyManifest, mode: wireDirect, family: "attestation"},
	"OpAttestHost":                {value: quic.OpAttestHost, mode: wireDirect, family: "attestation"},
	"OpAttestVMWorkload":          {value: quic.OpAttestVMWorkload, mode: wireDirect, family: "attestation"},
	"OpCertIssue":                 {value: quic.OpCertIssue, mode: wireDirect, family: "ca"},
	"OpCertRevoke":                {value: quic.OpCertRevoke, mode: wireDirect, family: "ca"},
	"OpCertRenew":                 {value: quic.OpCertRenew, mode: wireDirect, family: "ca"},
	"OpCertGet":                   {value: quic.OpCertGet, mode: wireDirect, family: "ca"},
	"OpCertList":                  {value: quic.OpCertList, mode: wireDirect, family: "ca"},
	"OpCertVerify":                {value: quic.OpCertVerify, mode: wireDirect, family: "ca"},
	"OpCertGetChain":              {value: quic.OpCertGetChain, mode: wireDirect, family: "ca"},
	"OpCertGetCRL":                {value: quic.OpCertGetCRL, mode: wireDirect, family: "ca"},
	"OpCertGetOCSP":               {value: quic.OpCertGetOCSP, mode: wireDirect, family: "ca"},
	"OpDaemonStatus":              {value: quic.OpDaemonStatus, mode: wireDirect, family: "daemon"},
	"OpDaemonVersion":             {value: quic.OpDaemonVersion, mode: wireDirect, family: "daemon"},
	"OpDaemonListServices":        {value: quic.OpDaemonListServices, mode: wireDirect, family: "daemon"},
	"OpDaemonGetService":          {value: quic.OpDaemonGetService, mode: wireDirect, family: "daemon"},
	"OpDaemonStartService":        {value: quic.OpDaemonStartService, mode: wireDirect, family: "daemon"},
	"OpDaemonStopService":         {value: quic.OpDaemonStopService, mode: wireDirect, family: "daemon"},
	"OpDaemonRestartService":      {value: quic.OpDaemonRestartService, mode: wireDirect, family: "daemon"},
	"OpJWTCreate":                 {value: quic.OpJWTCreate, mode: reservedByte, family: "reserved"},
	"OpJWTVerify":                 {value: quic.OpJWTVerify, mode: reservedByte, family: "reserved"},
	"OpJWTRefresh":                {value: quic.OpJWTRefresh, mode: reservedByte, family: "reserved"},
	"OpJWTRevoke":                 {value: quic.OpJWTRevoke, mode: reservedByte, family: "reserved"},
	"OpJWTGetKeys":                {value: quic.OpJWTGetKeys, mode: reservedByte, family: "reserved"},
	"OpAuthLogin":                 {value: quic.OpAuthLogin, mode: reservedByte, family: "reserved"},
	"OpAuthLogout":                {value: quic.OpAuthLogout, mode: reservedByte, family: "reserved"},
	"OpAuthCheck":                 {value: quic.OpAuthCheck, mode: reservedByte, family: "reserved"},
	"OpDaemonListProtocols":       {value: quic.OpDaemonListProtocols, mode: wireDirect, family: "daemon"},
	"OpTPM2Category":              {value: quic.OpTPM2Category, mode: wireDirect, family: "tpm2category"},
	"OpCeremonyCategory":          {value: quic.OpCeremonyCategory, mode: wireDirect, family: "ceremony"},
	"OpPIVCategory":               {value: quic.OpPIVCategory, mode: wireDirect, family: "piv"},
	"OpLUKSCategory":              {value: quic.OpLUKSCategory, mode: wireDirect, family: "luks"},
	"OpFIDO2Category":             {value: quic.OpFIDO2Category, mode: wireDirect, family: "fido2"},
	"OpTenantBarrierCategory":     {value: quic.OpTenantBarrierCategory, mode: wireDirect, family: "tenant"},
	"OpBMCCategory":               {value: quic.OpBMCCategory, mode: wireDirect, family: "bmc"},
	"OpCAInfo":                    {value: quic.OpCAInfo, mode: wireDirect, family: "ca"},
	"OpCAIssue":                   {value: quic.OpCAIssue, mode: wireDirect, family: "ca"},
	"OpCARevoke":                  {value: quic.OpCARevoke, mode: wireDirect, family: "ca"},
	"OpCARenew":                   {value: quic.OpCARenew, mode: wireDirect, family: "ca"},
	"OpCAGet":                     {value: quic.OpCAGet, mode: wireDirect, family: "ca"},
	"OpCAList":                    {value: quic.OpCAList, mode: wireDirect, family: "ca"},
	"OpCAVerify":                  {value: quic.OpCAVerify, mode: wireDirect, family: "ca"},
	"OpCACRL":                     {value: quic.OpCACRL, mode: wireDirect, family: "ca"},
	"OpCABundle":                  {value: quic.OpCABundle, mode: wireDirect, family: "ca"},
	"OpIAMUserCreate":             {value: quic.OpIAMUserCreate, mode: wireDirect, family: "iam"},
	"OpAttestCreatePolicy":        {value: quic.OpAttestCreatePolicy, mode: shadowedByte, family: "iam"},
	"OpIAMUserDelete":             {value: quic.OpIAMUserDelete, mode: wireDirect, family: "iam"},
	"OpAttestListPolicies":        {value: quic.OpAttestListPolicies, mode: shadowedByte, family: "iam"},
	"OpIAMUserGet":                {value: quic.OpIAMUserGet, mode: wireDirect, family: "iam"},
	"OpIAMUserList":               {value: quic.OpIAMUserList, mode: wireDirect, family: "iam"},
	"OpIAMUserUpdate":             {value: quic.OpIAMUserUpdate, mode: wireDirect, family: "iam"},
	"OpContainerList":             {value: quic.OpContainerList, mode: wireDirect, family: "container"},
	"OpContainerLogs":             {value: quic.OpContainerLogs, mode: wireDirect, family: "container"},
	"OpSDNCreateBridge":           {value: quic.OpSDNCreateBridge, mode: wireDirect, family: "sdn"},
	"OpSDNDeleteBridge":           {value: quic.OpSDNDeleteBridge, mode: wireDirect, family: "sdn"},
	"OpSDNCreatePort":             {value: quic.OpSDNCreatePort, mode: wireDirect, family: "sdn"},
	"OpSDNDeletePort":             {value: quic.OpSDNDeletePort, mode: wireDirect, family: "sdn"},
	"OpSDNDeletePolicy":           {value: quic.OpSDNDeletePolicy, mode: wireDirect, family: "sdn"},
	"OpIAMRoleCreate":             {value: quic.OpIAMRoleCreate, mode: wireDirect, family: "iam"},
	"OpIAMRoleDelete":             {value: quic.OpIAMRoleDelete, mode: wireDirect, family: "iam"},
	"OpVMRestart":                 {value: quic.OpVMRestart, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMRoleGet":                {value: quic.OpIAMRoleGet, mode: wireDirect, family: "iam"},
	"OpVMSuspend":                 {value: quic.OpVMSuspend, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMRoleList":               {value: quic.OpIAMRoleList, mode: wireDirect, family: "iam"},
	"OpVMResume":                  {value: quic.OpVMResume, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMRoleAssign":             {value: quic.OpIAMRoleAssign, mode: wireDirect, family: "iam"},
	"OpVMAttest":                  {value: quic.OpVMAttest, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMRoleRevoke":             {value: quic.OpIAMRoleRevoke, mode: wireDirect, family: "iam"},
	"OpVMConsole":                 {value: quic.OpVMConsole, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMGroupCreate":            {value: quic.OpIAMGroupCreate, mode: wireDirect, family: "iam"},
	"OpVMSnapshot":                {value: quic.OpVMSnapshot, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMGroupDelete":            {value: quic.OpIAMGroupDelete, mode: wireDirect, family: "iam"},
	"OpVMSnapshotRestore":         {value: quic.OpVMSnapshotRestore, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMGroupGet":               {value: quic.OpIAMGroupGet, mode: wireDirect, family: "iam"},
	"OpVMSnapshotDelete":          {value: quic.OpVMSnapshotDelete, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMGroupList":              {value: quic.OpIAMGroupList, mode: wireDirect, family: "iam"},
	"OpVMSnapshotList":            {value: quic.OpVMSnapshotList, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpIAMGroupAddMember":         {value: quic.OpIAMGroupAddMember, mode: wireDirect, family: "iam"},
	"OpVMVerifyAttest":            {value: quic.OpVMVerifyAttest, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpKMSGenerateKey":            {value: quic.OpKMSGenerateKey, mode: wireDirect, family: "kms"},
	"OpKMSImportKey":              {value: quic.OpKMSImportKey, mode: wireDirect, family: "kms"},
	"OpKMSGetKey":                 {value: quic.OpKMSGetKey, mode: wireDirect, family: "kms"},
	"OpKMSListKeys":               {value: quic.OpKMSListKeys, mode: wireDirect, family: "kms"},
	"OpKMSDeleteKey":              {value: quic.OpKMSDeleteKey, mode: wireDirect, family: "kms"},
	"OpKMSRotateKey":              {value: quic.OpKMSRotateKey, mode: wireDirect, family: "kms"},
	"OpKMSUpdateKeyStatus":        {value: quic.OpKMSUpdateKeyStatus, mode: wireDirect, family: "kms"},
	"OpKMSExportKey":              {value: quic.OpKMSExportKey, mode: wireDirect, family: "kms"},
	"OpKMSGetKeyVersions":         {value: quic.OpKMSGetKeyVersions, mode: wireDirect, family: "kms"},
	"OpKMSBackendStatus":          {value: quic.OpKMSBackendStatus, mode: wireDirect, family: "kms"},
	"OpKMSBatchEncrypt":           {value: quic.OpKMSBatchEncrypt, mode: wireDirect, family: "kms"},
	"OpKMSBatchDecrypt":           {value: quic.OpKMSBatchDecrypt, mode: wireDirect, family: "kms"},
	"OpSwitchCategory":            {value: quic.OpSwitchCategory, mode: wireDirect, family: "switch"},
	"OpKMSExtendedCategory":       {value: quic.OpKMSExtendedCategory, mode: wireDirect, family: "kms"},
	"OpSecretsCategory":           {value: quic.OpSecretsCategory, mode: wireDirect, family: "secrets"},
	"OpProvisioningCategory":      {value: quic.OpProvisioningCategory, mode: wireDirect, family: "configdelivery"},
	"OpKMSEncrypt":                {value: quic.OpKMSEncrypt, mode: wireDirect, family: "kms"},
	"OpKMSDecrypt":                {value: quic.OpKMSDecrypt, mode: wireDirect, family: "kms"},
	"OpKMSSign":                   {value: quic.OpKMSSign, mode: wireDirect, family: "kms"},
	"OpKMSVerify":                 {value: quic.OpKMSVerify, mode: wireDirect, family: "kms"},
	"OpKMSGenerateRandom":         {value: quic.OpKMSGenerateRandom, mode: wireDirect, family: "kms"},
	"OpKMSHash":                   {value: quic.OpKMSHash, mode: wireDirect, family: "kms"},
	"OpKMSHMAC":                   {value: quic.OpKMSHMAC, mode: wireDirect, family: "kms"},
	"OpKMSVerifyHMAC":             {value: quic.OpKMSVerifyHMAC, mode: wireDirect, family: "kms"},
	"OpKMSRewrap":                 {value: quic.OpKMSRewrap, mode: wireDirect, family: "kms"},
	"OpKMSGenerateDataKey":        {value: quic.OpKMSGenerateDataKey, mode: wireDirect, family: "kms"},
	"OpKMSGenerateWrappedDataKey": {value: quic.OpKMSGenerateWrappedDataKey, mode: wireDirect, family: "kms"},
	"OpTenantList":                {value: quic.OpTenantList, mode: wireDirect, family: "tenant"},
	"OpTenantGet":                 {value: quic.OpTenantGet, mode: wireDirect, family: "tenant"},
	"OpTenantGetByName":           {value: quic.OpTenantGetByName, mode: wireDirect, family: "tenant"},
	"OpTenantCreate":              {value: quic.OpTenantCreate, mode: wireDirect, family: "tenant"},
	"OpTenantUpdate":              {value: quic.OpTenantUpdate, mode: wireDirect, family: "tenant"},
	"OpTenantDelete":              {value: quic.OpTenantDelete, mode: wireDirect, family: "tenant"},
	"OpTenantSuspend":             {value: quic.OpTenantSuspend, mode: wireDirect, family: "tenant"},
	"OpTenantResume":              {value: quic.OpTenantResume, mode: wireDirect, family: "tenant"},
	"OpTenantGetQuotas":           {value: quic.OpTenantGetQuotas, mode: wireDirect, family: "tenant"},
	"OpTenantUpdateQuotas":        {value: quic.OpTenantUpdateQuotas, mode: wireDirect, family: "tenant"},
	"OpTenantGetUsage":            {value: quic.OpTenantGetUsage, mode: wireDirect, family: "tenant"},
	"OpTenantCheckQuota":          {value: quic.OpTenantCheckQuota, mode: wireDirect, family: "tenant"},
	"OpTenantValidateVLAN":        {value: quic.OpTenantValidateVLAN, mode: wireDirect, family: "tenant"},
	"OpTenantGetBridge":           {value: quic.OpTenantGetBridge, mode: wireDirect, family: "tenant"},
	"OpTenantSync":                {value: quic.OpTenantSync, mode: wireDirect, family: "tenant"},
	"OpTenantRotateDEK":           {value: quic.OpTenantRotateDEK, mode: wireDirect, family: "tenant"},
	"OpTenantGetDEKStatus":        {value: quic.OpTenantGetDEKStatus, mode: wireDirect, family: "tenant"},
	"OpContainerAttest":           {value: quic.OpContainerAttest, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpPXEListDevices":            {value: quic.OpPXEListDevices, mode: wireDirect, family: "pxe"},
	"OpAttestContainerWorkload":   {value: quic.OpAttestContainerWorkload, mode: shadowedByte, family: "pxe"},
	"OpPXEGetDevice":              {value: quic.OpPXEGetDevice, mode: wireDirect, family: "pxe"},
	"OpAttestDeviceWorkload":      {value: quic.OpAttestDeviceWorkload, mode: shadowedByte, family: "pxe"},
	"OpPXERegisterDevice":         {value: quic.OpPXERegisterDevice, mode: wireDirect, family: "pxe"},
	"OpAttestListReports":         {value: quic.OpAttestListReports, mode: shadowedByte, family: "pxe"},
	"OpPXEUpdateState":            {value: quic.OpPXEUpdateState, mode: wireDirect, family: "pxe"},
	"OpDEKCreate":                 {value: quic.OpDEKCreate, mode: reservedByte, family: "reserved"},
	"OpDEKGet":                    {value: quic.OpDEKGet, mode: reservedByte, family: "reserved"},
	"OpDEKList":                   {value: quic.OpDEKList, mode: reservedByte, family: "reserved"},
	"OpDEKDelete":                 {value: quic.OpDEKDelete, mode: reservedByte, family: "reserved"},
	"OpDEKRotate":                 {value: quic.OpDEKRotate, mode: reservedByte, family: "reserved"},
	"OpDEKGetStatus":              {value: quic.OpDEKGetStatus, mode: reservedByte, family: "reserved"},
	"OpIAMGroupRemoveMember":      {value: quic.OpIAMGroupRemoveMember, mode: wireDirect, family: "iam"},
	"OpIAMCheckPermission":        {value: quic.OpIAMCheckPermission, mode: wireDirect, family: "iam"},
	"OpIAMAuthenticate":           {value: quic.OpIAMAuthenticate, mode: wireDirect, family: "iam"},
	"OpIAMTokenCreate":            {value: quic.OpIAMTokenCreate, mode: wireDirect, family: "iam"},
	"OpIAMTokenRevoke":            {value: quic.OpIAMTokenRevoke, mode: wireDirect, family: "iam"},
	"OpIAMTokenVerify":            {value: quic.OpIAMTokenVerify, mode: wireDirect, family: "iam"},
	"OpVMMetrics":                 {value: quic.OpVMMetrics, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpVMAttachDisk":              {value: quic.OpVMAttachDisk, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpVMDetachDisk":              {value: quic.OpVMDetachDisk, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpVMResizeDisk":              {value: quic.OpVMResizeDisk, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpVMMigrate":                 {value: quic.OpVMMigrate, mode: categorySub, family: "vm", category: quic.OpVMExtendedCategory},
	"OpContainerExec":             {value: quic.OpContainerExec, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpContainerMetrics":          {value: quic.OpContainerMetrics, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpContainerCreate":           {value: quic.OpContainerCreate, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpPXEAuthorize":              {value: quic.OpPXEAuthorize, mode: wireDirect, family: "pxe"},
	"OpContainerStart":            {value: quic.OpContainerStart, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpPXEQuarantine":             {value: quic.OpPXEQuarantine, mode: wireDirect, family: "pxe"},
	"OpContainerStop":             {value: quic.OpContainerStop, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpPXERetry":                  {value: quic.OpPXERetry, mode: wireDirect, family: "pxe"},
	"OpContainerRemove":           {value: quic.OpContainerRemove, mode: categorySub, family: "container", category: quic.OpVMExtendedCategory},
	"OpPXERemoveDevice":           {value: quic.OpPXERemoveDevice, mode: wireDirect, family: "pxe"},
}

// newBareQUICDispatchHandler returns a handler with no services configured
// so every family responds with its distinctive nil-service error.
func newBareQUICDispatchHandler() *QUICServiceHandler {
	return NewQUICServiceHandler(logging.DefaultLogger())
}

// assertDispatchFamily drives one request through HandleRequest and
// asserts the response carries the family signature.
// iamTokenNotImplementedOpcodes are the IAM token operations that return
// StatusNotImplemented by OIDC design (token issuance/verification/revocation
// happens through OIDC, not these QUIC ops). They are still routed to and owned
// by the iam family on the wire; they simply answer NotImplemented instead of
// the iam-unavailable error a bare handler returns for the other iam opcodes.
var iamTokenNotImplementedOpcodes = map[byte]bool{
	quic.OpIAMTokenCreate: true,
	quic.OpIAMTokenRevoke: true,
	quic.OpIAMTokenVerify: true,
}

func assertDispatchFamily(t *testing.T, h *QUICServiceHandler, opcode byte, payload []byte, family string) {
	t.Helper()

	resp := h.HandleRequest(context.Background(), &quic.Request{Opcode: opcode, Payload: payload})
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
		if resp.Status != quic.StatusNotImplemented {
			t.Fatalf("opcode 0x%02X: expected iam-token NotImplemented (OIDC), got status 0x%02X payload %q",
				opcode, resp.Status, resp.Payload)
		}
		return
	}

	if family == "reserved" {
		wantBody := fmt.Sprintf("unknown QUIC opcode: 0x%02X", opcode)
		if resp.Status != quic.StatusNotImplemented {
			t.Fatalf("opcode 0x%02X: expected reserved (status 0x%02X), got status 0x%02X payload %q",
				opcode, quic.StatusNotImplemented, resp.Status, resp.Payload)
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
				var payload []byte
				if family != "reserved" {
					payload = quicDispatchFamilies[family].payload
				}
				assertDispatchFamily(t, h, opcode, payload, family)
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
				payload := quicDispatchFamilies[intent.family].payload
				assertDispatchFamily(t, h, intent.value, payload, intent.family)
			case reservedByte:
				assertDispatchFamily(t, h, intent.value, nil, "reserved")
			default:
				t.Fatalf("unknown intent mode %d", intent.mode)
			}
		})
	}
}

// TestQUICDispatchConstantTableComplete enumerates every exported Op*
// byte constant declared in pkg/api/quic sources and asserts the intent
// table above covers each one with the correct byte value, so newly added
// opcodes cannot land without an explicit dispatch-ownership decision.
func TestQUICDispatchConstantTableComplete(t *testing.T) {
	t.Parallel()

	declared := parseQUICOpcodeConstants(t)
	if len(declared) == 0 {
		t.Fatal("no exported Op* byte constants found in pkg/api/quic")
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
			t.Errorf("intent table entry %s no longer declared in pkg/api/quic", name)
		}
	}
}

// parseQUICOpcodeConstants scans the pkg/api/quic sources for exported
// const declarations of type byte whose names start with "Op".
func parseQUICOpcodeConstants(t *testing.T) map[string]byte {
	t.Helper()

	quicDir := filepath.Join("..", "quic")
	entries, err := os.ReadDir(quicDir)
	if err != nil {
		t.Fatalf("failed to read pkg/api/quic: %v", err)
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
					if !strings.HasPrefix(cname.Name, "Op") || i >= len(vs.Values) {
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
