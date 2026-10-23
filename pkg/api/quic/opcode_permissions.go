// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package quic

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// QUIC Operation -> Permission Catalog
// =============================================================================
//
// Every QUIC operation the daemon routes is authorized against this catalog
// before it is dispatched. An operation is either an opcode routed on its own
// byte, or a category opcode plus the sub-opcode it carries in payload[0].
//
// The catalog fails closed: an opcode or sub-opcode that is not listed here is
// refused (ErrOperationNotClassified), so a new operation cannot be served
// until it is given a permission. The only operations served without
// credentials are the documented preAuthOpcodes and preAuthSubOpcodes.
//
// The resource/action pairs mirror the gRPC method catalog
// (pkg/api/grpc/method_permissions.go) and the MCP tool catalog
// (pkg/api/mcp/authz.go) wherever those transports expose the same capability.
// The three catalogs are keyed differently (opcode, FullMethod, tool name), so
// they cannot share one table; docs/daemon/api.md is the cross-transport view.

// Action names of the platform token scope vocabulary ("resource:action").
const (
	actionRead    = "read"
	actionWrite   = "write"
	actionDelete  = "delete"
	actionAdmin   = "admin"
	actionSignCSR = "sign-csr"

	// go-qrdb registers the certificate family with its own verbs; ca:write
	// is not a permission any role can hold.
	actionGenerate = "generate"
	actionRevoke   = "revoke"
	actionList     = "list"

	// The BMC family splits its writes: power-off, reset and cycle need
	// bmc:power and virtual media needs bmc:media.
	actionPower = "power"
	actionMedia = "media"
)

// ErrOperationNotClassified is returned for an opcode, or a category
// sub-opcode, that has no entry in the permission catalog. Such an operation
// is refused rather than served without authorization.
type ErrOperationNotClassified struct {
	Opcode byte
	Sub    byte
	HasSub bool
}

func (e ErrOperationNotClassified) Error() string {
	msg := "QUIC operation not classified for authorization: opcode " + hexByte(e.Opcode)
	if e.HasSub {
		msg += " sub-opcode " + hexByte(e.Sub)
	}
	return msg
}

// ErrSubOpcodeMissing is returned for a category opcode whose payload does not
// carry the sub-opcode that selects the operation.
type ErrSubOpcodeMissing struct {
	Opcode byte
}

func (e ErrSubOpcodeMissing) Error() string {
	return "QUIC category opcode " + hexByte(e.Opcode) + " requires a sub-opcode in payload[0]"
}

// hexByte renders a byte as 0xNN.
func hexByte(b byte) string {
	return fmt.Sprintf("0x%02X", b)
}

// OpcodePermission is the permission an operation requires.
type OpcodePermission struct {
	Resource string
	Action   string
}

// Scope returns the colon "resource:action" platform token scope, or the empty
// string for an empty permission.
func (p OpcodePermission) Scope() string {
	return scopeForOperation(p.Resource, p.Action)
}

// LookupOperationPermission resolves the permission a request needs. The
// payload is consulted only for category opcodes, whose payload[0] selects
// the operation. preAuth is true for the operations served without
// credentials. Anything else that is not in the catalog returns
// ErrOperationNotClassified, and a category opcode with an empty payload
// returns ErrSubOpcodeMissing.
func LookupOperationPermission(opcode byte, payload []byte) (perm OpcodePermission, preAuth bool, err error) {
	if _, ok := preAuthOpcodes[opcode]; ok {
		return OpcodePermission{}, true, nil
	}
	if subs, ok := categoryPermissions[opcode]; ok {
		if len(payload) == 0 {
			return OpcodePermission{}, false, ErrSubOpcodeMissing{Opcode: opcode}
		}
		if _, ok := preAuthSubOpcodes[opcode][payload[0]]; ok {
			return OpcodePermission{}, true, nil
		}
		perm, ok := subs[payload[0]]
		if !ok {
			return OpcodePermission{}, false, ErrOperationNotClassified{Opcode: opcode, Sub: payload[0], HasSub: true}
		}
		return perm, false, nil
	}
	perm, ok := opcodePermissions[opcode]
	if !ok {
		return OpcodePermission{}, false, ErrOperationNotClassified{Opcode: opcode}
	}
	return perm, false, nil
}

// preAuthOpcodes are the only operations served without credentials. Each
// value records why the operation cannot require a token.
var preAuthOpcodes = map[byte]string{
	quicwire.OpHealth:    "load-balancer and orchestrator probe; reports only process health and must answer before any credential exists (gRPC skips HealthCheck the same way)",
	quicwire.OpLiveness:  "liveness probe; same reasoning as OpHealth",
	quicwire.OpReadiness: "readiness probe; same reasoning as OpHealth",
	quicwire.OpIAMAuthenticate: "credential exchange: the caller presents a username and password to obtain " +
		"the token every other operation requires, so it cannot itself require one",
}

// preAuthSubOpcodes are the single sub-operations of a category opcode that
// are served without credentials, keyed by category and then sub-opcode.
// Each value records why the operation cannot require a token.
var preAuthSubOpcodes = map[byte]map[byte]string{
	quicwire.OpProvisioningCategory: {
		quicwire.DeviceSubBootCertificate: "a diskless node holds no platform token and no certificate yet; " +
			"the boot service authenticates the request itself against the node's own TLS channel",
		quicwire.DeviceSubBootDelivery: "a diskless node holds no platform token; the boot service verifies " +
			"the node's attestation evidence, bound to its own TLS channel, before it delivers anything",

		// Pre-enrollment config delivery, open as on gRPC and MCP. The operator
		// half (FulfillSession, ListSessions, GetSession) stays scoped.
		quicwire.ProvisioningSubGetNonce: "a pre-enrollment machine holds no platform credential; the nonce " +
			"is single-use and only feeds the authenticated fetch and sign requests",
		quicwire.ProvisioningSubFetchConfig: "a pre-enrollment machine holds no platform credential; the service " +
			"authenticates the request itself (single-use nonce, EAB HMAC, EK-certificate binding)",
		quicwire.ProvisioningSubSignDigest: "a pre-enrollment machine holds no platform credential; the service " +
			"authenticates the request itself (single-use nonce, EAB HMAC, EK-certificate binding)",
		quicwire.ProvisioningSubPollSession: "a pre-enrollment machine holds no platform credential; the random " +
			"session ID handed out by an authenticated fetch is the poll capability",
	},
	quicwire.OpIAMCategory: {
		// The invitee half of the invitation flow, open as on gRPC, REST and MCP.
		// The operator half (Create, Get, List, Revoke, Delete) stays scoped.
		quicwire.InvitationSubGetByToken: "an invitee holds no platform credential yet; the invitation token " +
			"in the request is the credential",
		quicwire.InvitationSubAccept: "an invitee holds no platform credential yet; the invitation token " +
			"in the request is the credential",
	},
}

// Permissions shared by many entries.
var (
	vtpmRead   = OpcodePermission{Resource: "vtpm", Action: actionRead}
	vtpmWrite  = OpcodePermission{Resource: "vtpm", Action: actionWrite}
	vtpmDelete = OpcodePermission{Resource: "vtpm", Action: actionDelete}

	dnsRead   = OpcodePermission{Resource: "dns", Action: actionRead}
	dnsWrite  = OpcodePermission{Resource: "dns", Action: actionWrite}
	dnsDelete = OpcodePermission{Resource: "dns", Action: actionDelete}

	deviceRead   = OpcodePermission{Resource: "device", Action: actionRead}
	deviceWrite  = OpcodePermission{Resource: "device", Action: actionWrite}
	deviceDelete = OpcodePermission{Resource: "device", Action: actionDelete}

	sdnRead   = OpcodePermission{Resource: "sdn", Action: actionRead}
	sdnWrite  = OpcodePermission{Resource: "sdn", Action: actionWrite}
	sdnDelete = OpcodePermission{Resource: "sdn", Action: actionDelete}

	proxyRead   = OpcodePermission{Resource: "proxy", Action: actionRead}
	proxyWrite  = OpcodePermission{Resource: "proxy", Action: actionWrite}
	proxyDelete = OpcodePermission{Resource: "proxy", Action: actionDelete}

	ntpRead  = OpcodePermission{Resource: "ntp", Action: actionRead}
	ntpWrite = OpcodePermission{Resource: "ntp", Action: actionWrite}

	vpnRead  = OpcodePermission{Resource: "vpn", Action: actionRead}
	vpnWrite = OpcodePermission{Resource: "vpn", Action: actionWrite}
	vpnAdmin = OpcodePermission{Resource: "vpn", Action: actionAdmin}

	cacheRead   = OpcodePermission{Resource: "cache", Action: actionRead}
	cacheWrite  = OpcodePermission{Resource: "cache", Action: actionWrite}
	cacheDelete = OpcodePermission{Resource: "cache", Action: actionDelete}

	schedulerRead   = OpcodePermission{Resource: "scheduler", Action: actionRead}
	schedulerWrite  = OpcodePermission{Resource: "scheduler", Action: actionWrite}
	schedulerDelete = OpcodePermission{Resource: "scheduler", Action: actionDelete}

	messagingRead   = OpcodePermission{Resource: "messaging", Action: actionRead}
	messagingWrite  = OpcodePermission{Resource: "messaging", Action: actionWrite}
	messagingDelete = OpcodePermission{Resource: "messaging", Action: actionDelete}

	objectStorageRead   = OpcodePermission{Resource: "objectstorage", Action: actionRead}
	objectStorageWrite  = OpcodePermission{Resource: "objectstorage", Action: actionWrite}
	objectStorageDelete = OpcodePermission{Resource: "objectstorage", Action: actionDelete}

	tpmRead   = OpcodePermission{Resource: "tpm", Action: actionRead}
	tpmWrite  = OpcodePermission{Resource: "tpm", Action: actionWrite}
	tpmDelete = OpcodePermission{Resource: "tpm", Action: actionDelete}

	idevidRead   = OpcodePermission{Resource: "idevid", Action: actionRead}
	idevidWrite  = OpcodePermission{Resource: "idevid", Action: actionWrite}
	idevidDelete = OpcodePermission{Resource: "idevid", Action: actionDelete}

	vmRead   = OpcodePermission{Resource: "vm", Action: actionRead}
	vmWrite  = OpcodePermission{Resource: "vm", Action: actionWrite}
	vmDelete = OpcodePermission{Resource: "vm", Action: actionDelete}

	containerRead   = OpcodePermission{Resource: "container", Action: actionRead}
	containerWrite  = OpcodePermission{Resource: "container", Action: actionWrite}
	containerDelete = OpcodePermission{Resource: "container", Action: actionDelete}

	attestationRead  = OpcodePermission{Resource: "attestation", Action: actionRead}
	attestationWrite = OpcodePermission{Resource: "attestation", Action: actionWrite}

	caRead = OpcodePermission{Resource: "ca", Action: actionRead}

	certsGenerate = OpcodePermission{Resource: "certs", Action: actionGenerate}
	certsRevoke   = OpcodePermission{Resource: "certs", Action: actionRevoke}
	certsRead     = OpcodePermission{Resource: "certs", Action: actionRead}
	certsList     = OpcodePermission{Resource: "certs", Action: actionList}

	platformRead  = OpcodePermission{Resource: "platform", Action: actionRead}
	platformWrite = OpcodePermission{Resource: "platform", Action: actionWrite}

	iamRead   = OpcodePermission{Resource: "iam", Action: actionRead}
	iamWrite  = OpcodePermission{Resource: "iam", Action: actionWrite}
	iamDelete = OpcodePermission{Resource: "iam", Action: actionDelete}

	tenantRead   = OpcodePermission{Resource: "tenant", Action: actionRead}
	tenantWrite  = OpcodePermission{Resource: "tenant", Action: actionWrite}
	tenantDelete = OpcodePermission{Resource: "tenant", Action: actionDelete}

	kmsRead   = OpcodePermission{Resource: "kms", Action: actionRead}
	kmsWrite  = OpcodePermission{Resource: "kms", Action: actionWrite}
	kmsDelete = OpcodePermission{Resource: "kms", Action: actionDelete}

	secretsRead   = OpcodePermission{Resource: "secrets", Action: actionRead}
	secretsWrite  = OpcodePermission{Resource: "secrets", Action: actionWrite}
	secretsList   = OpcodePermission{Resource: "secrets", Action: actionList}
	secretsDelete = OpcodePermission{Resource: "secrets", Action: actionDelete}

	switchRead  = OpcodePermission{Resource: "switch", Action: actionRead}
	switchWrite = OpcodePermission{Resource: "switch", Action: actionWrite}

	provisioningRead  = OpcodePermission{Resource: "provisioning", Action: actionRead}
	provisioningWrite = OpcodePermission{Resource: "provisioning", Action: actionWrite}

	eabRead   = OpcodePermission{Resource: "eab", Action: actionRead}
	eabWrite  = OpcodePermission{Resource: "eab", Action: actionWrite}
	eabDelete = OpcodePermission{Resource: "eab", Action: actionDelete}

	invitationRead   = OpcodePermission{Resource: "invitation", Action: actionRead}
	invitationWrite  = OpcodePermission{Resource: "invitation", Action: actionWrite}
	invitationDelete = OpcodePermission{Resource: "invitation", Action: actionDelete}

	ceremonyRead  = OpcodePermission{Resource: "ceremony", Action: actionRead}
	ceremonyWrite = OpcodePermission{Resource: "ceremony", Action: actionWrite}

	pivRead   = OpcodePermission{Resource: "piv", Action: actionRead}
	pivWrite  = OpcodePermission{Resource: "piv", Action: actionWrite}
	pivDelete = OpcodePermission{Resource: "piv", Action: actionDelete}

	luksRead   = OpcodePermission{Resource: "luks", Action: actionRead}
	luksWrite  = OpcodePermission{Resource: "luks", Action: actionWrite}
	luksDelete = OpcodePermission{Resource: "luks", Action: actionDelete}

	fido2Read  = OpcodePermission{Resource: "fido2", Action: actionRead}
	fido2Write = OpcodePermission{Resource: "fido2", Action: actionWrite}

	bmcRead  = OpcodePermission{Resource: "bmc", Action: actionRead}
	bmcWrite = OpcodePermission{Resource: "bmc", Action: actionWrite}
	bmcPower = OpcodePermission{Resource: "bmc", Action: actionPower}
	bmcMedia = OpcodePermission{Resource: "bmc", Action: actionMedia}
	bmcAdmin = OpcodePermission{Resource: "bmc", Action: actionAdmin}

	clusterRead  = OpcodePermission{Resource: "cluster", Action: actionRead}
	clusterWrite = OpcodePermission{Resource: "cluster", Action: actionWrite}

	pxeRead   = OpcodePermission{Resource: "pxe", Action: actionRead}
	pxeWrite  = OpcodePermission{Resource: "pxe", Action: actionWrite}
	pxeDelete = OpcodePermission{Resource: "pxe", Action: actionDelete}
)

// opcodePermissions covers the opcodes routed on their own byte. A byte that
// two constants share (OpAttestCreatePolicy is OpIAMUserDelete on the wire)
// carries the permission of the family that owns it at dispatch.
var opcodePermissions = map[byte]OpcodePermission{
	// vTPM templates and bundles (gRPC VTPMService)
	quicwire.OpVTPMCreateTemplate: vtpmWrite,
	quicwire.OpVTPMGetTemplate:    vtpmRead,
	quicwire.OpVTPMDeleteTemplate: vtpmDelete,
	quicwire.OpVTPMListTemplates:  vtpmRead,
	quicwire.OpVTPMCloneTemplate:  vtpmWrite,
	quicwire.OpVTPMExportBundle:   vtpmRead,
	quicwire.OpVTPMImportBundle:   vtpmWrite,
	quicwire.OpVTPMValidateBundle: vtpmRead,
	quicwire.OpVTPMGetBundlePath:  vtpmRead,
	quicwire.OpVTPMGetSocketPath:  vtpmRead,
	quicwire.OpVTPMGetNVRAMPath:   vtpmRead,
	quicwire.OpVTPMGetBundle:      vtpmRead,
	quicwire.OpVTPMIsRunning:      vtpmRead,

	// vTPM instances
	quicwire.OpVTPMCreate:      vtpmWrite,
	quicwire.OpVTPMDelete:      vtpmDelete,
	quicwire.OpVTPMStart:       vtpmWrite,
	quicwire.OpVTPMStop:        vtpmWrite,
	quicwire.OpVTPMGetState:    vtpmRead,
	quicwire.OpVTPMList:        vtpmRead,
	quicwire.OpVTPMGetEK:       vtpmRead,
	quicwire.OpVTPMGetAK:       vtpmRead,
	quicwire.OpVTPMCreateAK:    vtpmWrite,
	quicwire.OpVTPMQuote:       vtpmRead,
	quicwire.OpVTPMVerifyQuote: vtpmRead,
	quicwire.OpVTPMExtendPCR:   vtpmWrite,
	quicwire.OpVTPMReadPCR:     vtpmRead,
	quicwire.OpVTPMSeal:        vtpmWrite,
	quicwire.OpVTPMUnseal:      vtpmRead,
	quicwire.OpVTPMGetRandom:   vtpmRead,

	// DNS (gRPC DNSService)
	quicwire.OpDNSAddRecord:    dnsWrite,
	quicwire.OpDNSDeleteRecord: dnsDelete,
	quicwire.OpDNSUpdateRecord: dnsWrite,
	quicwire.OpDNSGetRecord:    dnsRead,
	quicwire.OpDNSListRecords:  dnsRead,
	quicwire.OpDNSAddZone:      dnsWrite,
	quicwire.OpDNSDeleteZone:   dnsDelete,
	quicwire.OpDNSGetZone:      dnsRead,
	quicwire.OpDNSListZones:    dnsRead,
	quicwire.OpDNSResolve:      dnsRead,
	quicwire.OpDNSGetConfig:    dnsRead,
	quicwire.OpDNSGetMetrics:   dnsRead,

	// Devices and device profiles (gRPC DeviceService)
	quicwire.OpDeviceRegister:      deviceWrite,
	quicwire.OpDeviceUnregister:    deviceDelete,
	quicwire.OpDeviceGet:           deviceRead,
	quicwire.OpDeviceList:          deviceRead,
	quicwire.OpDeviceUpdate:        deviceWrite,
	quicwire.OpDeviceGetProfile:    deviceRead,
	quicwire.OpDeviceSetProfile:    deviceWrite,
	quicwire.OpDeviceListProfiles:  deviceRead,
	quicwire.OpDeviceCreateProfile: deviceWrite,
	quicwire.OpDeviceDeleteProfile: deviceDelete,
	// Attestation persists: the first verified quote seeds the profile's PCR
	// baseline and a failed one quarantines the device.
	quicwire.OpDeviceAttest:   deviceWrite,
	quicwire.OpDeviceActivate: deviceWrite,
	quicwire.OpDeviceGetState: deviceRead,

	// SDN (gRPC SDNService)
	quicwire.OpSDNGetPortState: sdnRead,
	quicwire.OpSDNSetPortState: sdnWrite,
	quicwire.OpSDNListPorts:    sdnRead,
	quicwire.OpSDNGetFlow:      sdnRead,
	quicwire.OpSDNAddFlow:      sdnWrite,
	quicwire.OpSDNDeleteFlow:   sdnDelete,
	quicwire.OpSDNListFlows:    sdnRead,
	quicwire.OpSDNApplyPolicy:  sdnWrite,
	quicwire.OpSDNGetPolicy:    sdnRead,
	quicwire.OpSDNListPolicies: sdnRead,
	quicwire.OpSDNGetBridge:    sdnRead,
	quicwire.OpSDNListBridges:  sdnRead,
	quicwire.OpSDNGetMetrics:   sdnRead,
	quicwire.OpSDNSetVLAN:      sdnWrite,
	quicwire.OpSDNGetVLAN:      sdnRead,
	quicwire.OpSDNGetPort:      sdnRead,
	quicwire.OpSDNCreateBridge: sdnWrite,
	quicwire.OpSDNDeleteBridge: sdnDelete,
	quicwire.OpSDNCreatePort:   sdnWrite,
	quicwire.OpSDNDeletePort:   sdnDelete,
	quicwire.OpSDNDeletePolicy: sdnDelete,

	// Device identity: IDevID / IAK / credential activation (gRPC
	// IDevIDService and the MCP idevid_* / iak_* tools)
	quicwire.OpIDevIDGenerate:     idevidWrite,
	quicwire.OpIDevIDInfo:         idevidRead,
	quicwire.OpIDevIDDelete:       idevidDelete,
	quicwire.OpIDevIDCSR:          idevidWrite,
	quicwire.OpIDevIDInstallCert:  idevidWrite,
	quicwire.OpIDevIDGetCert:      idevidRead,
	quicwire.OpIAKGenerate:        idevidWrite,
	quicwire.OpIAKInfo:            idevidRead,
	quicwire.OpIAKDelete:          idevidDelete,
	quicwire.OpIAKCSR:             idevidWrite,
	quicwire.OpIAKInstallCert:     idevidWrite,
	quicwire.OpIAKGetCert:         idevidRead,
	quicwire.OpDeviceAttributes:   idevidRead,
	quicwire.OpActivateCredential: idevidWrite,
	quicwire.OpHasIDevID:          idevidRead,
	quicwire.OpHasIAK:             idevidRead,
	quicwire.OpIDevIDDeleteCert:   idevidDelete,
	quicwire.OpIAKDeleteCert:      idevidDelete,

	// Containers routed on their own byte
	quicwire.OpContainerGet:  containerRead,
	quicwire.OpContainerList: containerRead,
	quicwire.OpContainerLogs: containerRead,

	// Attestation (MCP attestation_* tools: reads are attestation:read,
	// anything that collects fresh evidence is attestation:write). A quote
	// makes the node TPM sign the caller's nonce and discloses the PCRs it
	// covers, so it is a write, like OpAttestCollectHost.
	quicwire.OpAttestQuote:          attestationWrite,
	quicwire.OpAttestVerify:         attestationRead,
	quicwire.OpAttestCollectHost:    attestationWrite,
	quicwire.OpAttestGetAK:          attestationRead,
	quicwire.OpAttestChallenge:      attestationWrite,
	quicwire.OpAttestPollVerdicts:   attestationRead,
	quicwire.OpAttestGetReport:      attestationRead,
	quicwire.OpAttestGetPCRs:        attestationRead,
	quicwire.OpAttestBuildManifest:  attestationWrite,
	quicwire.OpAttestVerifyManifest: attestationRead,
	quicwire.OpAttestHost:           attestationWrite,
	quicwire.OpAttestVMWorkload:     attestationWrite,

	// Certificates and the CA (gRPC CAService). Certificates are the go-qrdb
	// certs family; the CA's own metadata, bundle and CRL are ca:read.
	quicwire.OpCertIssue:    certsGenerate,
	quicwire.OpCertRevoke:   certsRevoke,
	quicwire.OpCertRenew:    certsGenerate,
	quicwire.OpCertGet:      certsRead,
	quicwire.OpCertList:     certsList,
	quicwire.OpCertVerify:   certsRead,
	quicwire.OpCertGetChain: certsRead,
	quicwire.OpCertGetCRL:   caRead,
	quicwire.OpCertGetOCSP:  caRead,
	quicwire.OpCAInfo:       caRead,
	quicwire.OpCAIssue:      certsGenerate,
	quicwire.OpCARevoke:     certsRevoke,
	quicwire.OpCARenew:      certsGenerate,
	quicwire.OpCAGet:        certsRead,
	quicwire.OpCAList:       certsList,
	quicwire.OpCAVerify:     certsRead,
	quicwire.OpCACRL:        caRead,
	quicwire.OpCABundle:     caRead,

	// Daemon management (gRPC PlatformDaemon). ListProtocols has no gRPC
	// twin; it is a daemon read like Status and Version.
	quicwire.OpDaemonStatus:         platformRead,
	quicwire.OpDaemonVersion:        platformRead,
	quicwire.OpDaemonListServices:   platformRead,
	quicwire.OpDaemonGetService:     platformRead,
	quicwire.OpDaemonStartService:   platformWrite,
	quicwire.OpDaemonStopService:    platformWrite,
	quicwire.OpDaemonRestartService: platformWrite,
	quicwire.OpDaemonListProtocols:  platformRead,

	// IAM users, roles, groups and tokens (gRPC PlatformIAMService)
	quicwire.OpIAMUserCreate:        iamWrite,
	quicwire.OpIAMUserDelete:        iamDelete,
	quicwire.OpIAMUserGet:           iamRead,
	quicwire.OpIAMUserList:          iamRead,
	quicwire.OpIAMUserUpdate:        iamWrite,
	quicwire.OpIAMRoleCreate:        iamWrite,
	quicwire.OpIAMRoleDelete:        iamDelete,
	quicwire.OpIAMRoleGet:           iamRead,
	quicwire.OpIAMRoleList:          iamRead,
	quicwire.OpIAMRoleAssign:        iamWrite,
	quicwire.OpIAMRoleRevoke:        iamWrite,
	quicwire.OpIAMGroupCreate:       iamWrite,
	quicwire.OpIAMGroupDelete:       iamDelete,
	quicwire.OpIAMGroupGet:          iamRead,
	quicwire.OpIAMGroupList:         iamRead,
	quicwire.OpIAMGroupAddMember:    iamWrite,
	quicwire.OpIAMGroupRemoveMember: iamWrite,
	quicwire.OpIAMCheckPermission:   iamRead,
	quicwire.OpIAMTokenCreate:       iamWrite,
	quicwire.OpIAMTokenRevoke:       iamWrite,
	quicwire.OpIAMTokenVerify:       iamRead,

	// Platform tenancy (gRPC TenantService): quotas, usage, sync and DEK
	// custody, so the tenant scopes. IAM tenant records have their own
	// category, OpIAMCategory.
	quicwire.OpTenantList:         tenantRead,
	quicwire.OpTenantGet:          tenantRead,
	quicwire.OpTenantGetByName:    tenantRead,
	quicwire.OpTenantCreate:       tenantWrite,
	quicwire.OpTenantUpdate:       tenantWrite,
	quicwire.OpTenantDelete:       tenantDelete,
	quicwire.OpTenantSuspend:      tenantWrite,
	quicwire.OpTenantResume:       tenantWrite,
	quicwire.OpTenantGetQuotas:    tenantRead,
	quicwire.OpTenantUpdateQuotas: tenantWrite,
	quicwire.OpTenantGetUsage:     tenantRead,
	quicwire.OpTenantCheckQuota:   tenantRead,
	quicwire.OpTenantSync:         tenantWrite,
	quicwire.OpTenantRotateDEK:    tenantWrite,
	quicwire.OpTenantGetDEKStatus: tenantRead,

	// KMS keys and crypto (gRPC KeyManagementService)
	quicwire.OpKMSGenerateKey:            kmsWrite,
	quicwire.OpKMSImportKey:              kmsWrite,
	quicwire.OpKMSGetKey:                 kmsRead,
	quicwire.OpKMSListKeys:               kmsRead,
	quicwire.OpKMSDeleteKey:              kmsDelete,
	quicwire.OpKMSRotateKey:              kmsWrite,
	quicwire.OpKMSUpdateKeyStatus:        kmsWrite,
	quicwire.OpKMSExportKey:              kmsRead,
	quicwire.OpKMSGetKeyVersions:         kmsRead,
	quicwire.OpKMSBackendStatus:          kmsRead,
	quicwire.OpKMSBatchEncrypt:           kmsWrite,
	quicwire.OpKMSBatchDecrypt:           kmsRead,
	quicwire.OpKMSEncrypt:                kmsWrite,
	quicwire.OpKMSDecrypt:                kmsRead,
	quicwire.OpKMSSign:                   kmsWrite,
	quicwire.OpKMSVerify:                 kmsRead,
	quicwire.OpKMSGenerateRandom:         kmsRead,
	quicwire.OpKMSHash:                   kmsRead,
	quicwire.OpKMSHMAC:                   kmsWrite,
	quicwire.OpKMSVerifyHMAC:             kmsRead,
	quicwire.OpKMSRewrap:                 kmsWrite,
	quicwire.OpKMSGenerateDataKey:        kmsWrite,
	quicwire.OpKMSGenerateWrappedDataKey: kmsWrite,

	// PXE boot devices
	quicwire.OpPXEListDevices:    pxeRead,
	quicwire.OpPXEGetDevice:      pxeRead,
	quicwire.OpPXERegisterDevice: pxeWrite,
	quicwire.OpPXEUpdateState:    pxeWrite,
	quicwire.OpPXEAuthorize:      pxeWrite,
	quicwire.OpPXEQuarantine:     pxeWrite,
	quicwire.OpPXERetry:          pxeWrite,
	quicwire.OpPXERemoveDevice:   pxeDelete,
}

// ipamSubPermissions are the gateway IPAM sub-opcodes. They are reachable
// under the gateway category and under the dedicated IPAM category, which
// accepts nothing else (MCP gateway_ipam_* tools).
var ipamSubPermissions = map[byte]OpcodePermission{
	quicwire.OpGatewayListIPAMPools:   sdnRead,
	quicwire.OpGatewayAllocateIP:      sdnWrite,
	quicwire.OpGatewayReleaseIP:       sdnWrite,
	quicwire.OpGatewayListAllocations: sdnRead,
	quicwire.OpGatewayCreateIPAMPool:  sdnWrite,
	quicwire.OpGatewayDeleteIPAMPool:  sdnDelete,
	quicwire.OpGatewayGetIPAMPool:     sdnRead,
	quicwire.OpGatewayUpdateIPAMPool:  sdnWrite,
}

// categoryPermissions covers the category opcodes, keyed by the sub-opcode in
// payload[0]. Sub-opcode values repeat across categories, so each category
// has its own table.
var categoryPermissions = map[byte]map[byte]OpcodePermission{
	quicwire.OpOverlayCategory: {
		quicwire.OpOverlayStatus:      sdnRead,
		quicwire.OpOverlayListVTEPs:   sdnRead,
		quicwire.OpOverlayGetVTEP:     sdnRead,
		quicwire.OpOverlayListVNIs:    sdnRead,
		quicwire.OpOverlayCreateVNI:   sdnWrite,
		quicwire.OpOverlayDeleteVNI:   sdnDelete,
		quicwire.OpOverlayListTunns:   sdnRead,
		quicwire.OpOverlayListMACs:    sdnRead,
		quicwire.OpOverlayForgetMAC:   sdnWrite,
		quicwire.OpOverlayTunnelStats: sdnRead,
	},

	// Gateway (gRPC GatewayService and MCP gateway_* tools) plus the proxy
	// sub-opcodes it multiplexes (gRPC ProxyService).
	quicwire.OpGatewayCategory: withSubs(ipamSubPermissions, map[byte]OpcodePermission{
		quicwire.OpGatewayStatus:            sdnRead,
		quicwire.OpGatewaySetMode:           sdnWrite,
		quicwire.OpGatewayBGPStatus:         sdnRead,
		quicwire.OpGatewayBGPPeers:          sdnRead,
		quicwire.OpGatewayAnnouncePrefix:    sdnWrite,
		quicwire.OpGatewayWithdrawPrefix:    sdnWrite,
		quicwire.OpGatewayListPrefixes:      sdnRead,
		quicwire.OpGatewayListNetworkZones:  sdnRead,
		quicwire.OpGatewayCreateNetworkZone: sdnWrite,
		quicwire.OpGatewayUpdateNetworkZone: sdnWrite,
		quicwire.OpGatewayDeleteNetworkZone: sdnDelete,
		quicwire.OpGatewaySnapshot:          sdnRead,
		quicwire.OpGatewayListSnapshots:     sdnRead,
		quicwire.OpGatewayLBAddVIP:          sdnWrite,
		quicwire.OpGatewayLBRemoveVIP:       sdnDelete,
		quicwire.OpGatewayLBGetVIP:          sdnRead,
		quicwire.OpGatewayLBListVIPs:        sdnRead,
		quicwire.OpGatewayLBSetVIPBackends:  sdnWrite,
		quicwire.OpGatewayLBStatus:          sdnRead,
		// Reading flows resets the sampling window (gRPC GetPerfFlows).
		quicwire.OpGatewayPerfFlows:     sdnWrite,
		quicwire.OpGatewayPerfDatapath:  sdnRead,
		quicwire.OpGatewayPerfConntrack: sdnRead,
		quicwire.OpGatewayNAT64Status:   sdnRead,

		quicwire.OpGatewayAdmittedVTEP:      sdnRead,
		quicwire.OpGatewayListAdmittedVTEPs: sdnRead,

		quicwire.ProxySubRouteCreate: proxyWrite,
		quicwire.ProxySubRouteGet:    proxyRead,
		quicwire.ProxySubRouteUpdate: proxyWrite,
		quicwire.ProxySubRouteDelete: proxyDelete,
		quicwire.ProxySubRouteList:   proxyRead,
		quicwire.ProxySubPoolCreate:  proxyWrite,
		quicwire.ProxySubPoolGet:     proxyRead,
		quicwire.ProxySubPoolUpdate:  proxyWrite,
		quicwire.ProxySubPoolDelete:  proxyDelete,
		quicwire.ProxySubPoolList:    proxyRead,
		quicwire.ProxySubConfigGet:   proxyRead,
		quicwire.ProxySubStatusGet:   proxyRead,
		quicwire.ProxySubReload:      proxyWrite,
		quicwire.ProxySubZoneMatrix:  proxyRead,
	}),

	quicwire.OpIPAMCategory: ipamSubPermissions,

	// Time synchronization (gRPC NTPService)
	quicwire.OpNTPCategory: {
		quicwire.NTPSubGetStatus:   ntpRead,
		quicwire.NTPSubListSources: ntpRead,
		quicwire.NTPSubStep:        ntpWrite,
	},

	// VPN control plane (gRPC VPNService). Posture policies are tenant
	// security policy, so every policy operation needs vpn:admin.
	quicwire.OpVPNCategory: {
		quicwire.VPNSubEnrolPeer:           vpnWrite,
		quicwire.VPNSubListPeers:           vpnRead,
		quicwire.VPNSubRevokePeer:          vpnWrite,
		quicwire.VPNSubGetStatus:           vpnRead,
		quicwire.VPNSubGetPosturePolicy:    vpnAdmin,
		quicwire.VPNSubSetPosturePolicy:    vpnAdmin,
		quicwire.VPNSubDeletePosturePolicy: vpnAdmin,
		quicwire.VPNSubListPosturePolicies: vpnAdmin,
	},
	// Application services reached through the composed go-quicbaas SDK.
	// The scopes match the gRPC method catalog.
	quicwire.OpCacheCategory: {
		quicwire.CacheSubGetStats:     cacheRead,
		quicwire.CacheSubClear:        cacheDelete,
		quicwire.CacheSubGetConfig:    cacheRead,
		quicwire.CacheSubUpdateConfig: cacheWrite,
	},
	quicwire.OpSchedulerCategory: {
		quicwire.SchedulerSubCreateJob:     schedulerWrite,
		quicwire.SchedulerSubGetJob:        schedulerRead,
		quicwire.SchedulerSubUpdateJob:     schedulerWrite,
		quicwire.SchedulerSubDeleteJob:     schedulerDelete,
		quicwire.SchedulerSubListJobs:      schedulerRead,
		quicwire.SchedulerSubTriggerJob:    schedulerWrite,
		quicwire.SchedulerSubPauseJob:      schedulerWrite,
		quicwire.SchedulerSubResumeJob:     schedulerWrite,
		quicwire.SchedulerSubCancelJob:     schedulerWrite,
		quicwire.SchedulerSubGetJobHistory: schedulerRead,
		quicwire.SchedulerSubGetStatus:     schedulerRead,
	},
	quicwire.OpMessagingCategory: {
		quicwire.MessagingSubCreateChannel:   messagingWrite,
		quicwire.MessagingSubDeleteChannel:   messagingDelete,
		quicwire.MessagingSubGetChannel:      messagingRead,
		quicwire.MessagingSubListChannels:    messagingRead,
		quicwire.MessagingSubPublish:         messagingWrite,
		quicwire.MessagingSubGetStats:        messagingRead,
		quicwire.MessagingSubGetDedupStats:   messagingRead,
		quicwire.MessagingSubGetChannelStats: messagingRead,
	},
	quicwire.OpObjectStorageCategory: {
		quicwire.ObjectStorageSubPutObject:         objectStorageWrite,
		quicwire.ObjectStorageSubGetObject:         objectStorageRead,
		quicwire.ObjectStorageSubDeleteObject:      objectStorageDelete,
		quicwire.ObjectStorageSubHeadObject:        objectStorageRead,
		quicwire.ObjectStorageSubListObjects:       objectStorageRead,
		quicwire.ObjectStorageSubCopyObject:        objectStorageWrite,
		quicwire.ObjectStorageSubListObjectsByTag:  objectStorageRead,
		quicwire.ObjectStorageSubListTenantObjects: objectStorageRead,
	},

	// IAM tenant records (gRPC PlatformIAMService tenant methods)
	quicwire.OpIAMCategory: {
		quicwire.IAMSubTenantCreate: iamWrite,
		quicwire.IAMSubTenantGet:    iamRead,
		quicwire.IAMSubTenantList:   iamRead,
		quicwire.IAMSubTenantUpdate: iamWrite,
		quicwire.IAMSubTenantDelete: iamDelete,
		quicwire.IAMSubGroupUpdate:  iamWrite,
		quicwire.IAMSubRoleUpdate:   iamWrite,

		// Invitations. GetByToken and Accept are preAuthSubOpcodes.
		quicwire.InvitationSubCreate: invitationWrite,
		quicwire.InvitationSubGet:    invitationRead,
		quicwire.InvitationSubList:   invitationRead,
		quicwire.InvitationSubRevoke: invitationWrite,
		quicwire.InvitationSubDelete: invitationDelete,
	},

	// Compute: extended VM operations and the container operations.
	quicwire.OpVMExtendedCategory: {
		quicwire.OpVMCreate:          vmWrite,
		quicwire.OpVMDelete:          vmDelete,
		quicwire.OpVMStart:           vmWrite,
		quicwire.OpVMStop:            vmWrite,
		quicwire.OpVMGet:             vmRead,
		quicwire.OpVMList:            vmRead,
		quicwire.OpVMRestart:         vmWrite,
		quicwire.OpVMSuspend:         vmWrite,
		quicwire.OpVMResume:          vmWrite,
		quicwire.OpVMSnapshotCreate:  vmWrite,
		quicwire.OpVMSnapshotRestore: vmWrite,
		quicwire.OpVMSnapshotDelete:  vmDelete,
		quicwire.OpVMSnapshotList:    vmRead,
		quicwire.OpVMSnapshotGet:     vmRead,
		quicwire.OpVMAttest:          vmRead,
		quicwire.OpVMVerifyAttest:    vmRead,
		quicwire.OpVMMetrics:         vmRead,
		quicwire.OpVMAttachDisk:      vmWrite,
		quicwire.OpVMDetachDisk:      vmWrite,
		quicwire.OpVMResizeDisk:      vmWrite,
		quicwire.OpVMMigrate:         vmWrite,

		quicwire.OpVMPrepareMigration:  vmWrite,
		quicwire.OpVMFinalizeMigration: vmWrite,

		quicwire.OpContainerCreate:  containerWrite,
		quicwire.OpContainerStart:   containerWrite,
		quicwire.OpContainerStop:    containerWrite,
		quicwire.OpContainerRemove:  containerDelete,
		quicwire.OpContainerGet:     containerRead,
		quicwire.OpContainerList:    containerRead,
		quicwire.OpContainerLogs:    containerRead,
		quicwire.OpContainerAttest:  containerRead,
		quicwire.OpContainerExec:    containerWrite,
		quicwire.OpContainerMetrics: containerRead,
	},

	// Physical TPM 2.0. The daemon serves the LDevID sub-opcode with
	// IDevIDService.CreateLDevID, so it takes that method's idevid scope.
	quicwire.OpTPM2Category: {
		quicwire.SubOpTPM2Info:          tpmRead,
		quicwire.SubOpTPM2Provision:     tpmWrite,
		quicwire.SubOpTPM2Clear:         tpmDelete,
		quicwire.SubOpTPM2GetEK:         tpmRead,
		quicwire.SubOpTPM2CreateEK:      tpmWrite,
		quicwire.SubOpTPM2DeleteEK:      tpmDelete,
		quicwire.SubOpTPM2GetEKCert:     tpmRead,
		quicwire.SubOpTPM2ImportEKCert:  tpmWrite,
		quicwire.SubOpTPM2GetSRK:        tpmRead,
		quicwire.SubOpTPM2CreateSRK:     tpmWrite,
		quicwire.SubOpTPM2DeleteSRK:     tpmDelete,
		quicwire.SubOpTPM2GetIAK:        tpmRead,
		quicwire.SubOpTPM2CreateIAK:     tpmWrite,
		quicwire.SubOpTPM2DeleteIAK:     tpmDelete,
		quicwire.SubOpTPM2Quote:         tpmRead,
		quicwire.SubOpTPM2VerifyQuote:   tpmRead,
		quicwire.SubOpTPM2ReadPCRs:      tpmRead,
		quicwire.SubOpTPM2ExtendPCR:     tpmWrite,
		quicwire.SubOpTPM2EventLog:      tpmRead,
		quicwire.SubOpTPM2Random:        tpmRead,
		quicwire.SubOpTPM2Seal:          tpmWrite,
		quicwire.SubOpTPM2Unseal:        tpmRead,
		quicwire.SubOpTPM2Capabilities:  tpmRead,
		quicwire.SubOpTPM2NVRead:        tpmRead,
		quicwire.SubOpTPM2NVWrite:       tpmWrite,
		quicwire.SubOpTPM2NVDelete:      tpmDelete,
		quicwire.SubOpTPM2NVList:        tpmRead,
		quicwire.SubOpTPM2IDevIDCSR:     tpmWrite,
		quicwire.SubOpTPM2LDevIDCSR:     idevidWrite,
		quicwire.SubOpTPM2PlatformAttrs: tpmRead,
		quicwire.SubOpTPM2GetIDevID:     tpmRead,
		quicwire.SubOpTPM2MakeCred:      tpmRead,
		quicwire.SubOpTPM2ActivateCred:  tpmWrite,
		quicwire.SubOpTPM2Certify:       tpmRead,
	},

	// Bootstrap ceremony. Init is not pre-auth here: first-boot
	// initialization is served by the barrier gate's POST /init.
	quicwire.OpCeremonyCategory: {
		quicwire.CeremonySubInit:               ceremonyWrite,
		quicwire.CeremonySubStatus:             ceremonyRead,
		quicwire.CeremonySubClaimCertBegin:     ceremonyWrite,
		quicwire.CeremonySubClaimCertComplete:  ceremonyWrite,
		quicwire.CeremonySubClaimShareBegin:    ceremonyWrite,
		quicwire.CeremonySubSignCSR:            ceremonyWrite,
		quicwire.CeremonySubClaimShareComplete: ceremonyWrite,
	},

	quicwire.OpPIVCategory: {
		quicwire.PIVSubListDevices: pivRead,
		quicwire.PIVSubListSlots:   pivRead,
		quicwire.PIVSubSlotInfo:    pivRead,
		quicwire.PIVSubGenerate:    pivWrite,
		quicwire.PIVSubImport:      pivWrite,
		quicwire.PIVSubSign:        pivWrite,
		quicwire.PIVSubAttest:      pivRead,
		quicwire.PIVSubReset:       pivDelete,
	},

	quicwire.OpLUKSCategory: {
		quicwire.LUKSSubStatus:           luksRead,
		quicwire.LUKSSubListSlots:        luksRead,
		quicwire.LUKSSubInfo:             luksRead,
		quicwire.LUKSSubEnrollPassphrase: luksWrite,
		quicwire.LUKSSubEnrollFIDO2:      luksWrite,
		quicwire.LUKSSubEnrollTPM:        luksWrite,
		quicwire.LUKSSubEnrollRecovery:   luksWrite,
		quicwire.LUKSSubRemoveKey:        luksDelete,
		quicwire.LUKSSubTestUnlock:       luksRead,
		quicwire.LUKSSubChangePassphrase: luksWrite,
	},

	quicwire.OpFIDO2Category: {
		quicwire.FIDO2SubListDevices:  fido2Read,
		quicwire.FIDO2SubWaitDevice:   fido2Read,
		quicwire.FIDO2SubInfo:         fido2Read,
		quicwire.FIDO2SubRegister:     fido2Write,
		quicwire.FIDO2SubAuthenticate: fido2Write,
	},

	// Per-tenant barrier (gRPC TenantService): the tenant scopes the
	// tenant opcodes carry.
	quicwire.OpTenantBarrierCategory: {
		quicwire.TenantBarrierSubInit:   tenantWrite,
		quicwire.TenantBarrierSubUnseal: tenantWrite,
		quicwire.TenantBarrierSubSeal:   tenantWrite,
		quicwire.TenantBarrierSubStatus: tenantRead,
	},

	// BMC (gRPC BMCService): each sub-opcode takes its method's scope.
	// Powering on is a write; powering off, reset and cycle need bmc:power.
	quicwire.OpBMCCategory: {
		quicwire.BMCSubPowerOn:               bmcWrite,
		quicwire.BMCSubPowerOff:              bmcPower,
		quicwire.BMCSubPowerReset:            bmcPower,
		quicwire.BMCSubPowerCycle:            bmcPower,
		quicwire.BMCSubPowerStatus:           bmcRead,
		quicwire.BMCSubSetBootDevice:         bmcWrite,
		quicwire.BMCSubGetBootDevice:         bmcRead,
		quicwire.BMCSubMountISO:              bmcMedia,
		quicwire.BMCSubUnmountISO:            bmcMedia,
		quicwire.BMCSubVirtualMediaStatus:    bmcRead,
		quicwire.BMCSubGetSensors:            bmcRead,
		quicwire.BMCSubGetSystemInfo:         bmcRead,
		quicwire.BMCSubProvision:             bmcAdmin,
		quicwire.BMCSubProvisionStatus:       bmcRead,
		quicwire.BMCSubGetWebCertificate:     bmcRead,
		quicwire.BMCSubReplaceWebCertificate: bmcAdmin,
		quicwire.BMCSubEnroll:                bmcAdmin,
		quicwire.BMCSubRestore:               bmcAdmin,
		quicwire.BMCSubListUsers:             bmcRead,
		quicwire.BMCSubCreateUser:            bmcAdmin,
		quicwire.BMCSubDeleteUser:            bmcAdmin,
		quicwire.BMCSubSetUserPassword:       bmcAdmin,
		quicwire.BMCSubSetUserPrivilege:      bmcAdmin,
	},

	quicwire.OpClusterCategory: {
		quicwire.ClusterSubBootstrap: clusterWrite,
		quicwire.ClusterSubJoin:      clusterWrite,
		quicwire.ClusterSubLeave:     clusterWrite,
		quicwire.ClusterSubGetStatus: clusterRead,
		quicwire.ClusterSubListNodes: clusterRead,
	},

	quicwire.OpSwitchCategory: {
		quicwire.SwitchSubListPorts:     switchRead,
		quicwire.SwitchSubGetPortStatus: switchRead,
		quicwire.SwitchSubSetPortVLAN:   switchWrite,
		quicwire.SwitchSubEnablePort:    switchWrite,
		quicwire.SwitchSubDisablePort:   switchWrite,
	},

	quicwire.OpKMSExtendedCategory: {
		quicwire.KMSSubRevokeKey:              kmsWrite,
		quicwire.KMSSubGetKeyMetadata:         kmsRead,
		quicwire.KMSSubUpdateKeyMetadata:      kmsWrite,
		quicwire.KMSSubSetKeyPolicy:           kmsWrite,
		quicwire.KMSSubGetKeyPolicy:           kmsRead,
		quicwire.KMSSubGetSupportedAlgorithms: kmsRead,
		quicwire.KMSSubSignCSR:                CASignCSRPermission,
		quicwire.KMSSubCreateDEK:              kmsWrite,
		quicwire.KMSSubListDEKs:               kmsRead,
		quicwire.KMSSubGetDEK:                 kmsRead,
		quicwire.KMSSubGetDEKStatus:           kmsRead,
		quicwire.KMSSubRotateDEK:              kmsWrite,
		quicwire.KMSSubDeleteDEK:              kmsDelete,
		quicwire.KMSSubSetDefaultDEK:          kmsWrite,
		quicwire.KMSSubSetDEKSafety:           kmsWrite,
		quicwire.KMSSubClearDEKSafety:         kmsWrite,
	},

	quicwire.OpSecretsCategory: {
		quicwire.SecretsSubStore:             secretsWrite,
		quicwire.SecretsSubGet:               secretsRead,
		quicwire.SecretsSubList:              secretsList,
		quicwire.SecretsSubDelete:            secretsDelete,
		quicwire.SecretsSubSetRotationPolicy: secretsWrite,
		quicwire.SecretsSubGetRotationPolicy: secretsRead,
		quicwire.SecretsSubGetVersion:        secretsRead,
		quicwire.SecretsSubListVersions:      secretsList,
		quicwire.SecretsSubRotate:            secretsWrite,
		quicwire.SecretsSubRollback:          secretsWrite,
		quicwire.SecretsSubUpdateStatus:      secretsWrite,
	},

	// Provisioning: config delivery, EAB credentials and device profile
	// assignment share this category.
	quicwire.OpProvisioningCategory: {
		// GetNonce, FetchConfig, SignDigest and PollSession are preAuthSubOpcodes.
		quicwire.ProvisioningSubFulfillSession: provisioningWrite,
		quicwire.ProvisioningSubListSessions:   provisioningRead,
		quicwire.ProvisioningSubGetSession:     provisioningRead,

		quicwire.EABSubCreateCredential:          eabWrite,
		quicwire.EABSubGetCredential:             eabRead,
		quicwire.EABSubGetCredentialByKeyID:      eabRead,
		quicwire.EABSubListCredentials:           eabRead,
		quicwire.EABSubRevokeCredential:          eabWrite,
		quicwire.EABSubValidateCredential:        eabRead,
		quicwire.EABSubDeleteCredential:          eabDelete,
		quicwire.EABSubGetCredentialQRCode:       eabRead,
		quicwire.EABSubGetEnrollmentURL:          eabRead,
		quicwire.EABSubMarkCredentialUsed:        eabWrite,
		quicwire.EABSubCleanupExpiredCredentials: eabDelete,

		// Device profile assignment, the attestation certificate record and
		// the device templates. Recording the certificate changes the anchor
		// the attestation verifier chains to.
		quicwire.DeviceProfileSubAssign:       deviceWrite,
		quicwire.DeviceProfileSubUnassign:     deviceWrite,
		quicwire.DeviceSubRecordAttestCert:    deviceWrite,
		quicwire.DeviceSubDisable:             deviceWrite,
		quicwire.DeviceSubEnable:              deviceWrite,
		quicwire.DeviceSubTemplateCreate:      deviceWrite,
		quicwire.DeviceSubTemplateGet:         deviceRead,
		quicwire.DeviceSubTemplateList:        deviceRead,
		quicwire.DeviceSubTemplateUpdate:      deviceWrite,
		quicwire.DeviceSubTemplateDelete:      deviceDelete,
		quicwire.DeviceSubProfileFromTemplate: deviceWrite,
		quicwire.DeviceSubFindMatchingProfile: deviceRead,
		quicwire.DeviceSubFindConfigForDevice: deviceRead,

		// The PXEService methods without a direct opcode, scoped as on gRPC.
		quicwire.PXESubGetDeviceByMAC:    pxeRead,
		quicwire.PXESubSetDeviceEnrolled: pxeWrite,
		quicwire.PXESubGetEvents:         pxeRead,
		quicwire.PXESubGetStatus:         pxeRead,
		quicwire.PXESubStartService:      pxeWrite,
		quicwire.PXESubStopService:       pxeWrite,
		quicwire.PXESubWebhookComplete:   pxeWrite,
	},
}

// withSubs returns a new table holding the entries of every table given.
func withSubs(tables ...map[byte]OpcodePermission) map[byte]OpcodePermission {
	merged := make(map[byte]OpcodePermission)
	for _, table := range tables {
		for sub, perm := range table {
			merged[sub] = perm
		}
	}
	return merged
}
