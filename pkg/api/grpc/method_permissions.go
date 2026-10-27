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

package grpc

// =============================================================================
// gRPC Method -> Scope Permission Catalog
// =============================================================================
//
// This is the gRPC projection of the QUIC operation catalog
// (quic.LookupOperationPermission) and the MCP toolPermissions catalog onto
// the platform token scope vocabulary. Scopes are the qrdb-canonical colon
// "<resource>:<action>" form (e.g. "dns:write"), which is verbatim what the
// broker mints into the scp claim from a subject's qrdb-resolved permissions.
//
// The map is keyed by the gRPC FullMethod string ("/platform.v1.Service/Method")
// so the interceptor can resolve a method's required scope in O(1) and enforce
// it against the validated AuthorizedContext (RequireScope), matching the QUIC
// (AuthMiddleware.GuardRequest) and MCP (AuthorizeTool) per-operation
// enforcement.
//
// The catalog is default deny. Every method the daemon registers on its gRPC
// server must appear either here, with the scope it requires, or in
// preAuthMethods below. The interceptor refuses any other method with
// codes.PermissionDenied before it looks at a token, so a method added without
// a classification cannot be reached. TestGRPCMethodCatalog_* derives the method
// list from the generated service descriptors and fails on any gap.
//
// Resource names and the read/write/delete split follow QUIC and MCP where
// those transports carry the same capability. BMC uses the owner-ruled
// read/write/power/media/admin vocabulary documented in pkg/api/mcp/authz.go.
// Resource families go-qrdb owns (ca, certs, ceremony, piv, seal, secrets,
// trust) use the exact actions go-qrdb registers: the broker can mint only a
// registered permission, so any other action there would be unreachable.

// grpcMethodPermissions maps a gRPC FullMethod to its required colon
// "resource:action" scope. It is built once and treated as read-only.
var grpcMethodPermissions = buildGRPCMethodPermissions()

// preAuthMethods lists the gRPC methods the interceptor serves without a
// platform token. Each one is called before the caller can hold a token, or
// carries its own credential in the request. Every other method needs both a
// valid token and the scope grpcMethodPermissions names for it.
var preAuthMethods = map[string]struct{}{
	// The readiness and liveness probe. It answers one SERVING status for one
	// named service, and orchestrators call it without credentials. The rest of
	// the health surface is scoped: Health/List enumerates every registered
	// service, Health/Watch holds a stream open for as long as the caller likes,
	// and PlatformDaemon/GetHealth names each component with its failure.
	"/grpc.health.v1.Health/Check": {},

	// The platform's own liveness and readiness probes, served without a
	// token for the same reason as Health/Check: an orchestrator probes before
	// it holds a credential. Each answers a boolean and the overall status,
	// never a component name, so it discloses no more than Health/Check;
	// the component breakdown stays behind PlatformDaemon/GetHealth.
	"/platform.v1.PlatformDaemon/Liveness":  {},
	"/platform.v1.PlatformDaemon/Readiness": {},

	// Invitation redemption. The invitation token in the request is the
	// credential: an invitee has no platform session yet. Matches the ungated
	// REST invitee routes and the MCP get_by_token / accept tools.
	"/platform.v1.InvitationService/GetInvitationByToken": {},
	"/platform.v1.InvitationService/AcceptInvitation":     {},

	// Pre-enrollment config delivery. The machine authenticates inside the
	// request (single-use nonce, EAB HMAC, EK-certificate binding) before it
	// holds any platform credential, and the session ID is the poll capability.
	// Matches the ungated REST /provisioning routes. The operator half of this
	// service (ListSessions, GetSession, FulfillSession) is scoped.
	"/platform.v1.ConfigDeliveryService/GetNonce":    {},
	"/platform.v1.ConfigDeliveryService/FetchConfig": {},
	"/platform.v1.ConfigDeliveryService/SignDigest":  {},
	"/platform.v1.ConfigDeliveryService/PollSession": {},

	// Diskless boot. The node holds no platform token and, for
	// BootCertificate, no certificate yet. The boot service authenticates
	// both calls itself: it verifies the node's proof, or its chain and
	// quote, bound to the connection. The daemon's TCP skip list exempts them
	// from the mTLS interceptor for the same reason.
	"/platform.v1.DeviceService/BootCertificate": {},
	"/platform.v1.DeviceService/BootDelivery":    {},
}

// ScopeForMethod returns the colon "resource:action" scope a gRPC method
// requires, or the empty string when the method is not in the catalog. The
// interceptor refuses an empty result unless isPreAuthMethod reports the
// method as pre-auth. The lookup is constant time.
func ScopeForMethod(fullMethod string) string {
	return grpcMethodPermissions[fullMethod]
}

// isPreAuthMethod reports whether a gRPC method is served without a token.
func isPreAuthMethod(fullMethod string) bool {
	_, ok := preAuthMethods[fullMethod]
	return ok
}

// buildGRPCMethodPermissions constructs the FullMethod -> scope catalog. The
// resource/action pairs mirror the QUIC operation catalog and the MCP
// toolPermissions for the same capabilities; the daemon's QUIC authorization
// contract test pins the parity.
func buildGRPCMethodPermissions() map[string]string {
	const (
		read   = "read"
		write  = "write"
		del    = "delete"
		power  = "power"
		media  = "media"
		admin  = "admin"
		vtpm   = "vtpm"
		dns    = "dns"
		device = "device"
		sdn    = "sdn"
		kms    = "kms"
		iam    = "iam"
		ca     = "ca"
		prox   = "proxy"
		ntp    = "ntp"
		vpn    = "vpn"

		cacheRes     = "cache"
		schedulerRes = "scheduler"
		messagingRes = "messaging"

		objectStorageRes = "objectstorage"

		platform     = "platform"
		attestation  = "attestation"
		bmc          = "bmc"
		ceremony     = "ceremony"
		cluster      = "cluster"
		container    = "container"
		vm           = "vm"
		provisioning = "provisioning"
		eab          = "eab"
		fido2        = "fido2"
		idevid       = "idevid"
		invitation   = "invitation"
		luks         = "luks"
		piv          = "piv"
		pxe          = "pxe"
		registry     = "registry"
		switchPorts  = "switch"
		tpm          = "tpm"
		tenant       = "tenant"
		secrets      = "secrets"
	)

	// Resources go-qrdb owns take the actions its permission registry holds
	// (go-qrdb pkg/permission). A role can hold only a registered permission,
	// so any other action in these families would make the method unreachable.
	const (
		certs = "certs"
		seal  = "seal"
		trust = "trust"

		create             = "create"
		list               = "list"
		update             = "update"
		generate           = "generate"
		revoke             = "revoke"
		use                = "use"
		status             = "status"
		bootstrap          = "bootstrap"
		initialize         = "initialize"
		unseal             = "unseal"
		sealBarrier        = "seal"
		rekey              = "rekey"
		claimCert          = "claim_cert"
		claimShareBegin    = "claim_share_begin"
		claimShareComplete = "claim_share_complete"
		signCSR            = "sign_csr"

		// caSignCSR certifies an existing KMS key for code signing. It is a
		// platform action in a go-qrdb family, so no role can be granted it
		// by name: only ca:* or *:* covers it, which keeps it with the
		// platform admin. certs:generate, which issues certificates for keys
		// the CA generates itself, does not reach it.
		caSignCSR = "sign-csr"
	)

	scope := func(resource, action string) string {
		return resource + ":" + action
	}

	return map[string]string{
		// ---------------------------------------------------------------------
		// vTPM (VTPMService)
		// ---------------------------------------------------------------------
		"/platform.v1.VTPMService/CreateTemplate":   scope(vtpm, write),
		"/platform.v1.VTPMService/CloneTemplate":    scope(vtpm, write),
		"/platform.v1.VTPMService/DeleteTemplate":   scope(vtpm, del),
		"/platform.v1.VTPMService/GetTemplate":      scope(vtpm, read),
		"/platform.v1.VTPMService/ListTemplates":    scope(vtpm, read),
		"/platform.v1.VTPMService/CreateBundle":     scope(vtpm, write),
		"/platform.v1.VTPMService/DeleteBundle":     scope(vtpm, del),
		"/platform.v1.VTPMService/ExportBundle":     scope(vtpm, read),
		"/platform.v1.VTPMService/ImportBundle":     scope(vtpm, write),
		"/platform.v1.VTPMService/GetBundle":        scope(vtpm, read),
		"/platform.v1.VTPMService/GetBundlePath":    scope(vtpm, read),
		"/platform.v1.VTPMService/ListBundles":      scope(vtpm, read),
		"/platform.v1.VTPMService/ValidateBundle":   scope(vtpm, read),
		"/platform.v1.VTPMService/GetNVRAMPath":     scope(vtpm, read),
		"/platform.v1.VTPMService/GetTPMSocketPath": scope(vtpm, read),
		"/platform.v1.VTPMService/IsVTPMRunning":    scope(vtpm, read),
		"/platform.v1.VTPMService/StartVTPM":        scope(vtpm, write),
		"/platform.v1.VTPMService/StopVTPM":         scope(vtpm, write),
		"/platform.v1.VTPMService/QuoteVTPM":        scope(vtpm, read),
		"/platform.v1.VTPMService/ExtendVTPMPCR":    scope(vtpm, write),
		"/platform.v1.VTPMService/ReadVTPMPCR":      scope(vtpm, read),
		"/platform.v1.VTPMService/SealVTPM":         scope(vtpm, write),
		"/platform.v1.VTPMService/UnsealVTPM":       scope(vtpm, read),

		// ---------------------------------------------------------------------
		// DNS (DNSService)
		// ---------------------------------------------------------------------
		"/platform.v1.DNSService/AddRecord":       scope(dns, write),
		"/platform.v1.DNSService/UpdateRecord":    scope(dns, write),
		"/platform.v1.DNSService/DeleteRecord":    scope(dns, del),
		"/platform.v1.DNSService/ListRecords":     scope(dns, read),
		"/platform.v1.DNSService/CreateZone":      scope(dns, write),
		"/platform.v1.DNSService/UpdateZone":      scope(dns, write),
		"/platform.v1.DNSService/DeleteZone":      scope(dns, del),
		"/platform.v1.DNSService/GetZone":         scope(dns, read),
		"/platform.v1.DNSService/ListZones":       scope(dns, read),
		"/platform.v1.DNSService/Resolve":         scope(dns, read),
		"/platform.v1.DNSService/Register":        scope(dns, write),
		"/platform.v1.DNSService/SignZone":        scope(dns, write),
		"/platform.v1.DNSService/GetDNSSECStatus": scope(dns, read),

		// ---------------------------------------------------------------------
		// NTP (NTPService) — time synchronization. Step mutates the system
		// clock (an operator recovery action), so it requires ntp:write; the
		// status and source queries are reads.
		// ---------------------------------------------------------------------
		"/platform.v1.NTPService/GetStatus":   scope(ntp, read),
		"/platform.v1.NTPService/ListSources": scope(ntp, read),
		"/platform.v1.NTPService/Step":        scope(ntp, write),

		// ---------------------------------------------------------------------
		// VPN (VPNService) — peer enrolment, session status and tenant
		// posture policies. A posture policy decides who reaches a zone, so
		// every policy operation requires vpn:admin (docs/vpn/api.md).
		// ---------------------------------------------------------------------
		"/platform.v1.VPNService/EnrolPeer":           scope(vpn, write),
		"/platform.v1.VPNService/ListPeers":           scope(vpn, read),
		"/platform.v1.VPNService/RevokePeer":          scope(vpn, write),
		"/platform.v1.VPNService/GetStatus":           scope(vpn, read),
		"/platform.v1.VPNService/GetPosturePolicy":    scope(vpn, admin),
		"/platform.v1.VPNService/SetPosturePolicy":    scope(vpn, admin),
		"/platform.v1.VPNService/DeletePosturePolicy": scope(vpn, admin),
		"/platform.v1.VPNService/ListPosturePolicies": scope(vpn, admin),

		// Cache, Scheduler, Messaging — the application services the
		// composed go-quicbaas SDK serves (docs/sdk/api.md §3.5).
		"/platform.v1.CacheService/GetStats":     scope(cacheRes, read),
		"/platform.v1.CacheService/GetConfig":    scope(cacheRes, read),
		"/platform.v1.CacheService/UpdateConfig": scope(cacheRes, write),
		"/platform.v1.CacheService/Clear":        scope(cacheRes, del),

		"/platform.v1.SchedulerService/CreateJob":     scope(schedulerRes, write),
		"/platform.v1.SchedulerService/GetJob":        scope(schedulerRes, read),
		"/platform.v1.SchedulerService/UpdateJob":     scope(schedulerRes, write),
		"/platform.v1.SchedulerService/DeleteJob":     scope(schedulerRes, del),
		"/platform.v1.SchedulerService/ListJobs":      scope(schedulerRes, read),
		"/platform.v1.SchedulerService/TriggerJob":    scope(schedulerRes, write),
		"/platform.v1.SchedulerService/PauseJob":      scope(schedulerRes, write),
		"/platform.v1.SchedulerService/ResumeJob":     scope(schedulerRes, write),
		"/platform.v1.SchedulerService/CancelJob":     scope(schedulerRes, write),
		"/platform.v1.SchedulerService/GetJobHistory": scope(schedulerRes, read),
		"/platform.v1.SchedulerService/GetStatus":     scope(schedulerRes, read),

		"/platform.v1.MessagingService/CreateChannel":   scope(messagingRes, write),
		"/platform.v1.MessagingService/DeleteChannel":   scope(messagingRes, del),
		"/platform.v1.MessagingService/GetChannel":      scope(messagingRes, read),
		"/platform.v1.MessagingService/ListChannels":    scope(messagingRes, read),
		"/platform.v1.MessagingService/Publish":         scope(messagingRes, write),
		"/platform.v1.MessagingService/GetStats":        scope(messagingRes, read),
		"/platform.v1.MessagingService/GetDedupStats":   scope(messagingRes, read),
		"/platform.v1.MessagingService/GetChannelStats": scope(messagingRes, read),

		"/platform.v1.ObjectStorageService/PutObject":         scope(objectStorageRes, write),
		"/platform.v1.ObjectStorageService/GetObject":         scope(objectStorageRes, read),
		"/platform.v1.ObjectStorageService/DeleteObject":      scope(objectStorageRes, del),
		"/platform.v1.ObjectStorageService/HeadObject":        scope(objectStorageRes, read),
		"/platform.v1.ObjectStorageService/ListObjects":       scope(objectStorageRes, read),
		"/platform.v1.ObjectStorageService/CopyObject":        scope(objectStorageRes, write),
		"/platform.v1.ObjectStorageService/ListObjectsByTag":  scope(objectStorageRes, read),
		"/platform.v1.ObjectStorageService/ListTenantObjects": scope(objectStorageRes, read),

		// ---------------------------------------------------------------------
		// Proxy (ProxyService) — reverse-proxy route/pool source of truth
		// ---------------------------------------------------------------------
		"/platform.v1.ProxyService/CreateRoute":       scope(prox, write),
		"/platform.v1.ProxyService/GetRoute":          scope(prox, read),
		"/platform.v1.ProxyService/UpdateRoute":       scope(prox, write),
		"/platform.v1.ProxyService/DeleteRoute":       scope(prox, del),
		"/platform.v1.ProxyService/ListRoutes":        scope(prox, read),
		"/platform.v1.ProxyService/CreatePool":        scope(prox, write),
		"/platform.v1.ProxyService/GetPool":           scope(prox, read),
		"/platform.v1.ProxyService/UpdatePool":        scope(prox, write),
		"/platform.v1.ProxyService/DeletePool":        scope(prox, del),
		"/platform.v1.ProxyService/ListPools":         scope(prox, read),
		"/platform.v1.ProxyService/GetProxyConfig":    scope(prox, read),
		"/platform.v1.ProxyService/GetProxyStatus":    scope(prox, read),
		"/platform.v1.ProxyService/ReloadProxyConfig": scope(prox, write),
		"/platform.v1.ProxyService/GetZoneMatrix":     scope(prox, read),

		// ---------------------------------------------------------------------
		// Device (DeviceService)
		// ---------------------------------------------------------------------
		"/platform.v1.DeviceService/CreateDevice":              scope(device, write),
		"/platform.v1.DeviceService/UpdateDevice":              scope(device, write),
		"/platform.v1.DeviceService/DeleteDevice":              scope(device, del),
		"/platform.v1.DeviceService/GetDevice":                 scope(device, read),
		"/platform.v1.DeviceService/ListDevices":               scope(device, read),
		"/platform.v1.DeviceService/CountDevices":              scope(device, read),
		"/platform.v1.DeviceService/ActivateDevice":            scope(device, write),
		"/platform.v1.DeviceService/AssignProfileToDevice":     scope(device, write),
		"/platform.v1.DeviceService/UnassignProfileFromDevice": scope(device, write),
		"/platform.v1.DeviceService/FindConfigForDevice":       scope(device, read),
		"/platform.v1.DeviceService/FindDeviceBySerial":        scope(device, read),
		// Attestation persists: the first verified quote seeds the profile's
		// PCR baseline and a failed one quarantines the device.
		"/platform.v1.DeviceService/AttestDevice":                 scope(device, write),
		"/platform.v1.DeviceService/RecordAttestationCertificate": scope(device, write),
		"/platform.v1.DeviceService/CreateProfile":                scope(device, write),
		"/platform.v1.DeviceService/CreateTemplate":               scope(device, write),
		"/platform.v1.DeviceService/GetTemplate":                  scope(device, read),
		"/platform.v1.DeviceService/ListTemplates":                scope(device, read),
		"/platform.v1.DeviceService/UpdateTemplate":               scope(device, write),
		"/platform.v1.DeviceService/DeleteTemplate":               scope(device, del),
		"/platform.v1.DeviceService/CreateProfileFromTemplate":    scope(device, write),
		"/platform.v1.DeviceService/UpdateProfile":                scope(device, write),
		"/platform.v1.DeviceService/DeleteProfile":                scope(device, del),
		"/platform.v1.DeviceService/GetProfile":                   scope(device, read),
		"/platform.v1.DeviceService/ListProfiles":                 scope(device, read),
		"/platform.v1.DeviceService/CountProfiles":                scope(device, read),
		"/platform.v1.DeviceService/FindMatchingProfile":          scope(device, read),
		"/platform.v1.DeviceService/FindProfileByMACAddress":      scope(device, read),
		"/platform.v1.DeviceService/FindProfileBySerial":          scope(device, read),
		// The lifecycle transitions (#250) block or re-admit a switch port
		// and are writes on every transport.
		"/platform.v1.DeviceService/DisableDevice": scope(device, write),
		"/platform.v1.DeviceService/EnableDevice":  scope(device, write),

		// ---------------------------------------------------------------------
		// Gateway load balancer VIPs (GatewayService)
		// ---------------------------------------------------------------------
		"/platform.v1.GatewayService/AddVIP":         scope(sdn, write),
		"/platform.v1.GatewayService/RemoveVIP":      scope(sdn, del),
		"/platform.v1.GatewayService/GetVIP":         scope(sdn, read),
		"/platform.v1.GatewayService/ListVIPs":       scope(sdn, read),
		"/platform.v1.GatewayService/SetVIPBackends": scope(sdn, write),
		"/platform.v1.GatewayService/GetLBStatus":    scope(sdn, read),
		"/platform.v1.GatewayService/GetNAT64Status": scope(sdn, read),

		// -----------------------------------------------------------------
		// Gateway telemetry snapshots (GatewayService, #594)
		// -----------------------------------------------------------------
		// The snapshot is a read of what the datapath programmed: sessions,
		// tunnels, uplink policy routes, filters and the base pipeline.
		"/platform.v1.GatewayService/GetGatewaySnapshot":       scope(sdn, read),
		"/platform.v1.GatewayService/ListGatewaySnapshots":     scope(sdn, read),
		"/platform.v1.GatewayService/GetGatewayAdmittedVTEP":   scope(sdn, read),
		"/platform.v1.GatewayService/ListGatewayAdmittedVTEPs": scope(sdn, read),

		// -----------------------------------------------------------------
		// Gateway performance verification (GatewayService)
		// -----------------------------------------------------------------
		// GetPerfFlows mutates bridge flow tables (ephemeral install +
		// cookie-scoped delete in table 250), so it requires sdn:write;
		// the datapath / conntrack counters are read-only.
		"/platform.v1.GatewayService/GetPerfFlows":     scope(sdn, write),
		"/platform.v1.GatewayService/GetPerfDatapath":  scope(sdn, read),
		"/platform.v1.GatewayService/GetPerfConntrack": scope(sdn, read),

		// -----------------------------------------------------------------
		// Gateway IPAM, BGP and mode (GatewayService). IPAM matches the MCP
		// gateway_ipam_* tools.
		// -----------------------------------------------------------------
		"/platform.v1.GatewayService/CreateIPAMPool":        scope(sdn, write),
		"/platform.v1.GatewayService/UpdateIPAMPool":        scope(sdn, write),
		"/platform.v1.GatewayService/DeleteIPAMPool":        scope(sdn, del),
		"/platform.v1.GatewayService/GetIPAMPool":           scope(sdn, read),
		"/platform.v1.GatewayService/ListIPAMPools":         scope(sdn, read),
		"/platform.v1.GatewayService/AllocateIP":            scope(sdn, write),
		"/platform.v1.GatewayService/ReleaseIP":             scope(sdn, write),
		"/platform.v1.GatewayService/ListAllocations":       scope(sdn, read),
		"/platform.v1.GatewayService/AnnouncePrefix":        scope(sdn, write),
		"/platform.v1.GatewayService/WithdrawPrefix":        scope(sdn, write),
		"/platform.v1.GatewayService/GetBGPStatus":          scope(sdn, read),
		"/platform.v1.GatewayService/ListAnnouncedPrefixes": scope(sdn, read),
		"/platform.v1.GatewayService/ListBGPPeers":          scope(sdn, read),
		"/platform.v1.GatewayService/GetGatewayStatus":      scope(sdn, read),
		"/platform.v1.GatewayService/SetGatewayMode":        scope(sdn, write),

		// ---------------------------------------------------------------------
		// SDN (SDNService). Network zones match the MCP gateway_zone_* tools.
		// ---------------------------------------------------------------------
		"/platform.v1.SDNService/CreateBridge":      scope(sdn, write),
		"/platform.v1.SDNService/DeleteBridge":      scope(sdn, del),
		"/platform.v1.SDNService/GetBridge":         scope(sdn, read),
		"/platform.v1.SDNService/ListBridges":       scope(sdn, read),
		"/platform.v1.SDNService/AddPort":           scope(sdn, write),
		"/platform.v1.SDNService/DeletePort":        scope(sdn, del),
		"/platform.v1.SDNService/GetPort":           scope(sdn, read),
		"/platform.v1.SDNService/ListPorts":         scope(sdn, read),
		"/platform.v1.SDNService/SetPortState":      scope(sdn, write),
		"/platform.v1.SDNService/GetPortStats":      scope(sdn, read),
		"/platform.v1.SDNService/AuthenticatePort":  scope(sdn, write),
		"/platform.v1.SDNService/RevokePortAuth":    scope(sdn, write),
		"/platform.v1.SDNService/ApplyPolicy":       scope(sdn, write),
		"/platform.v1.SDNService/GetPolicy":         scope(sdn, read),
		"/platform.v1.SDNService/ListPolicies":      scope(sdn, read),
		"/platform.v1.SDNService/DeletePolicy":      scope(sdn, del),
		"/platform.v1.SDNService/AddFlow":           scope(sdn, write),
		"/platform.v1.SDNService/DeleteFlow":        scope(sdn, del),
		"/platform.v1.SDNService/FlushFlows":        scope(sdn, write),
		"/platform.v1.SDNService/ListFlows":         scope(sdn, read),
		"/platform.v1.SDNService/GetFlowStats":      scope(sdn, read),
		"/platform.v1.SDNService/StreamFlowLogs":    scope(sdn, read),
		"/platform.v1.SDNService/CreateVLAN":        scope(sdn, write),
		"/platform.v1.SDNService/DeleteVLAN":        scope(sdn, del),
		"/platform.v1.SDNService/ListVLANs":         scope(sdn, read),
		"/platform.v1.SDNService/CreateNetworkZone": scope(sdn, write),
		"/platform.v1.SDNService/UpdateNetworkZone": scope(sdn, write),
		"/platform.v1.SDNService/DeleteNetworkZone": scope(sdn, del),
		"/platform.v1.SDNService/ListNetworkZones":  scope(sdn, read),

		// ---------------------------------------------------------------------
		// Overlay (OverlayService) — EVPN/VXLAN, part of the SDN surface
		// ---------------------------------------------------------------------
		"/platform.v1.OverlayService/CreateVNI":        scope(sdn, write),
		"/platform.v1.OverlayService/DeleteVNI":        scope(sdn, del),
		"/platform.v1.OverlayService/ForgetMAC":        scope(sdn, write),
		"/platform.v1.OverlayService/GetOverlayStatus": scope(sdn, read),
		"/platform.v1.OverlayService/GetTunnelStats":   scope(sdn, read),
		"/platform.v1.OverlayService/GetVTEP":          scope(sdn, read),
		"/platform.v1.OverlayService/ListRemoteMACs":   scope(sdn, read),
		"/platform.v1.OverlayService/ListTunnels":      scope(sdn, read),
		"/platform.v1.OverlayService/ListVNIs":         scope(sdn, read),
		"/platform.v1.OverlayService/ListVTEPs":        scope(sdn, read),

		// ---------------------------------------------------------------------
		// KMS (KeyManagementService)
		// ---------------------------------------------------------------------
		"/platform.v1.KeyManagementService/GenerateKey":            scope(kms, write),
		"/platform.v1.KeyManagementService/ImportKey":              scope(kms, write),
		"/platform.v1.KeyManagementService/GetKey":                 scope(kms, read),
		"/platform.v1.KeyManagementService/GetKeyVersions":         scope(kms, read),
		"/platform.v1.KeyManagementService/ListKeys":               scope(kms, read),
		"/platform.v1.KeyManagementService/DeleteKey":              scope(kms, del),
		"/platform.v1.KeyManagementService/RotateKey":              scope(kms, write),
		"/platform.v1.KeyManagementService/UpdateKeyStatus":        scope(kms, write),
		"/platform.v1.KeyManagementService/ExportKey":              scope(kms, read),
		"/platform.v1.KeyManagementService/Encrypt":                scope(kms, write),
		"/platform.v1.KeyManagementService/Decrypt":                scope(kms, read),
		"/platform.v1.KeyManagementService/BatchEncrypt":           scope(kms, write),
		"/platform.v1.KeyManagementService/BatchDecrypt":           scope(kms, read),
		"/platform.v1.KeyManagementService/Sign":                   scope(kms, write),
		"/platform.v1.KeyManagementService/Verify":                 scope(kms, read),
		"/platform.v1.KeyManagementService/HMAC":                   scope(kms, write),
		"/platform.v1.KeyManagementService/VerifyHMAC":             scope(kms, read),
		"/platform.v1.KeyManagementService/Hash":                   scope(kms, read),
		"/platform.v1.KeyManagementService/GenerateDataKey":        scope(kms, write),
		"/platform.v1.KeyManagementService/GenerateWrappedDataKey": scope(kms, write),
		"/platform.v1.KeyManagementService/GenerateRandom":         scope(kms, read),
		"/platform.v1.KeyManagementService/Rewrap":                 scope(kms, write),
		"/platform.v1.KeyManagementService/BackendStatus":          scope(kms, read),

		// ---------------------------------------------------------------------
		// QuicBaaS KMS services the daemon re-registers (KeyManagement, Crypto,
		// DEKManagement, SecretsManagement). The split follows the platform
		// KeyManagementService above: producing ciphertext, signatures or keys
		// is a write, consuming them (decrypt, unwrap, verify) is a read.
		// ---------------------------------------------------------------------
		"/quicbaas.kms.v1.KeyManagement/GenerateKey":             scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/ImportKey":               scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/GetKey":                  scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/GetPublicKey":            scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/ListKeys":                scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/ListKeyVersions":         scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/RotateKey":               scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/RevokeKey":               scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/DeleteKey":               scope(kms, del),
		"/quicbaas.kms.v1.KeyManagement/UpdateKeyStatus":         scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/GetKeyMetadata":          scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/UpdateKeyMetadata":       scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/SetKeyPolicy":            scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/GetKeyPolicy":            scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/DeleteKeyPolicy":         scope(kms, del),
		"/quicbaas.kms.v1.KeyManagement/SetKeyRotationPolicy":    scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/GetKeyRotationPolicy":    scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/DeleteKeyRotationPolicy": scope(kms, del),
		"/quicbaas.kms.v1.KeyManagement/GetSupportedAlgorithms":  scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/BackendStatus":           scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/BackendTest":             scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/ExportKey":               scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/UnwrapKey":               scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/SetKeySafety":            scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/ClearKeySafety":          scope(kms, write),
		"/quicbaas.kms.v1.KeyManagement/SafetyCheck":             scope(kms, read),
		"/quicbaas.kms.v1.KeyManagement/SafetyReport":            scope(kms, read),

		"/quicbaas.kms.v1.Crypto/Encrypt":                scope(kms, write),
		"/quicbaas.kms.v1.Crypto/Decrypt":                scope(kms, read),
		"/quicbaas.kms.v1.Crypto/Rewrap":                 scope(kms, write),
		"/quicbaas.kms.v1.Crypto/EncryptBatch":           scope(kms, write),
		"/quicbaas.kms.v1.Crypto/DecryptBatch":           scope(kms, read),
		"/quicbaas.kms.v1.Crypto/GenerateDataKey":        scope(kms, write),
		"/quicbaas.kms.v1.Crypto/GenerateWrappedDataKey": scope(kms, write),
		"/quicbaas.kms.v1.Crypto/Sign":                   scope(kms, write),
		"/quicbaas.kms.v1.Crypto/Verify":                 scope(kms, read),
		"/quicbaas.kms.v1.Crypto/GenerateHMAC":           scope(kms, write),
		"/quicbaas.kms.v1.Crypto/VerifyHMAC":             scope(kms, read),
		"/quicbaas.kms.v1.Crypto/GenerateRandom":         scope(kms, read),
		"/quicbaas.kms.v1.Crypto/Hash":                   scope(kms, read),

		"/quicbaas.kms.v1.DEKManagement/CreateDEK":               scope(kms, write),
		"/quicbaas.kms.v1.DEKManagement/GetDEK":                  scope(kms, read),
		"/quicbaas.kms.v1.DEKManagement/ListDEKs":                scope(kms, read),
		"/quicbaas.kms.v1.DEKManagement/RotateDEK":               scope(kms, write),
		"/quicbaas.kms.v1.DEKManagement/DeleteDEK":               scope(kms, del),
		"/quicbaas.kms.v1.DEKManagement/GetDEKStatus":            scope(kms, read),
		"/quicbaas.kms.v1.DEKManagement/SetDefaultDEK":           scope(kms, write),
		"/quicbaas.kms.v1.DEKManagement/SetDEKSafety":            scope(kms, write),
		"/quicbaas.kms.v1.DEKManagement/ClearDEKSafety":          scope(kms, write),
		"/quicbaas.kms.v1.DEKManagement/StartReencryption":       scope(kms, write),
		"/quicbaas.kms.v1.DEKManagement/GetReencryptionProgress": scope(kms, read),

		"/quicbaas.kms.v1.SecretsManagement/StoreSecret":          scope(secrets, write),
		"/quicbaas.kms.v1.SecretsManagement/GetSecret":            scope(secrets, read),
		"/quicbaas.kms.v1.SecretsManagement/ListSecrets":          scope(secrets, list),
		"/quicbaas.kms.v1.SecretsManagement/DeleteSecret":         scope(secrets, del),
		"/quicbaas.kms.v1.SecretsManagement/GetSecretVersion":     scope(secrets, read),
		"/quicbaas.kms.v1.SecretsManagement/ListSecretVersions":   scope(secrets, list),
		"/quicbaas.kms.v1.SecretsManagement/RollbackSecret":       scope(secrets, write),
		"/quicbaas.kms.v1.SecretsManagement/RotateSecret":         scope(secrets, write),
		"/quicbaas.kms.v1.SecretsManagement/UpdateSecretStatus":   scope(secrets, write),
		"/quicbaas.kms.v1.SecretsManagement/SetRotationPolicy":    scope(secrets, write),
		"/quicbaas.kms.v1.SecretsManagement/GetRotationPolicy":    scope(secrets, read),
		"/quicbaas.kms.v1.SecretsManagement/GetSecretsByPrefix":   scope(secrets, read),
		"/quicbaas.kms.v1.SecretsManagement/EnsureSecret":         scope(secrets, write),
		"/quicbaas.kms.v1.SecretsManagement/WatchSecretsByPrefix": scope(secrets, read),

		// ---------------------------------------------------------------------
		// IAM (PlatformIAMService)
		// ---------------------------------------------------------------------
		"/platform.v1.PlatformIAMService/CreateUser":        scope(iam, write),
		"/platform.v1.PlatformIAMService/UpdateUser":        scope(iam, write),
		"/platform.v1.PlatformIAMService/DeleteUser":        scope(iam, del),
		"/platform.v1.PlatformIAMService/GetUser":           scope(iam, read),
		"/platform.v1.PlatformIAMService/ListUsers":         scope(iam, read),
		"/platform.v1.PlatformIAMService/CreateRole":        scope(iam, write),
		"/platform.v1.PlatformIAMService/UpdateRole":        scope(iam, write),
		"/platform.v1.PlatformIAMService/DeleteRole":        scope(iam, del),
		"/platform.v1.PlatformIAMService/GetRole":           scope(iam, read),
		"/platform.v1.PlatformIAMService/ListRoles":         scope(iam, read),
		"/platform.v1.PlatformIAMService/AssignRole":        scope(iam, write),
		"/platform.v1.PlatformIAMService/RevokeRole":        scope(iam, write),
		"/platform.v1.PlatformIAMService/CreateGroup":       scope(iam, write),
		"/platform.v1.PlatformIAMService/UpdateGroup":       scope(iam, write),
		"/platform.v1.PlatformIAMService/DeleteGroup":       scope(iam, del),
		"/platform.v1.PlatformIAMService/GetGroup":          scope(iam, read),
		"/platform.v1.PlatformIAMService/ListGroups":        scope(iam, read),
		"/platform.v1.PlatformIAMService/AddGroupMember":    scope(iam, write),
		"/platform.v1.PlatformIAMService/RemoveGroupMember": scope(iam, write),
		"/platform.v1.PlatformIAMService/CreatePolicy":      scope(iam, write),
		"/platform.v1.PlatformIAMService/UpdatePolicy":      scope(iam, write),
		"/platform.v1.PlatformIAMService/DeletePolicy":      scope(iam, del),
		"/platform.v1.PlatformIAMService/GetPolicy":         scope(iam, read),
		"/platform.v1.PlatformIAMService/ListPolicies":      scope(iam, read),
		"/platform.v1.PlatformIAMService/TestPolicy":        scope(iam, read),
		"/platform.v1.PlatformIAMService/ValidatePolicy":    scope(iam, read),
		"/platform.v1.PlatformIAMService/CheckPermission":   scope(iam, read),
		"/platform.v1.PlatformIAMService/CreateTenant":      scope(iam, write),
		"/platform.v1.PlatformIAMService/UpdateTenant":      scope(iam, write),
		"/platform.v1.PlatformIAMService/DeleteTenant":      scope(iam, del),
		"/platform.v1.PlatformIAMService/GetTenant":         scope(iam, read),
		"/platform.v1.PlatformIAMService/ListTenants":       scope(iam, read),
		"/platform.v1.PlatformIAMService/RegisterApp":       scope(iam, write),
		"/platform.v1.PlatformIAMService/UpdateApp":         scope(iam, write),
		"/platform.v1.PlatformIAMService/DeleteApp":         scope(iam, del),
		"/platform.v1.PlatformIAMService/GetApp":            scope(iam, read),
		"/platform.v1.PlatformIAMService/ListApps":          scope(iam, read),
		"/platform.v1.PlatformIAMService/RotateAppSecret":   scope(iam, write),
		"/platform.v1.PlatformIAMService/CreateToken":       scope(iam, write),
		"/platform.v1.PlatformIAMService/RevokeToken":       scope(iam, write),
		"/platform.v1.PlatformIAMService/VerifyToken":       scope(iam, read),

		// ---------------------------------------------------------------------
		// CA (CAService). The CA itself is the ca family; the certificates it
		// issues are certs. Installing CA certificates into the system trust
		// store changes what the host trusts, so both directions are trust:write.
		// ---------------------------------------------------------------------
		"/platform.v1.CAService/InitCA":                  scope(ca, create),
		"/platform.v1.CAService/SignCSR":                 scope(ca, caSignCSR),
		"/platform.v1.CAService/GetCAInfo":               scope(ca, read),
		"/platform.v1.CAService/GetCABundle":             scope(ca, read),
		"/platform.v1.CAService/GetCRL":                  scope(ca, read),
		"/platform.v1.CAService/IssueCertificate":        scope(certs, generate),
		"/platform.v1.CAService/RenewCertificate":        scope(certs, generate),
		"/platform.v1.CAService/RevokeCertificate":       scope(certs, revoke),
		"/platform.v1.CAService/GetCertificate":          scope(certs, read),
		"/platform.v1.CAService/VerifyCertificate":       scope(certs, read),
		"/platform.v1.CAService/ListCertificates":        scope(certs, list),
		"/platform.v1.CAService/InstallCACertificates":   scope(trust, write),
		"/platform.v1.CAService/UninstallCACertificates": scope(trust, write),

		// ---------------------------------------------------------------------
		// Daemon control (PlatformDaemon). Shutting the daemon down and dumping
		// raw entity storage are platform:admin; the other mutators are
		// platform:write. GetHealth reports every component by name with its
		// failure message, which maps the deployment for an attacker, so it is
		// a scoped read like the REST /api/v1/platform/health route.
		// ---------------------------------------------------------------------
		"/platform.v1.PlatformDaemon/GetHealth":        scope(platform, read),
		"/platform.v1.PlatformDaemon/GetStatus":        scope(platform, read),
		"/platform.v1.PlatformDaemon/GetVersion":       scope(platform, read),
		"/platform.v1.PlatformDaemon/GetConfig":        scope(platform, read),
		"/platform.v1.PlatformDaemon/GetServiceStatus": scope(platform, read),
		"/platform.v1.PlatformDaemon/ListServices":     scope(platform, read),
		"/platform.v1.PlatformDaemon/ListEntityTypes":  scope(platform, read),
		"/platform.v1.PlatformDaemon/StreamEvents":     scope(platform, read),
		"/platform.v1.PlatformDaemon/StreamLogs":       scope(platform, read),
		"/platform.v1.PlatformDaemon/StreamMetrics":    scope(platform, read),
		"/platform.v1.PlatformDaemon/UpdateConfig":     scope(platform, write),
		"/platform.v1.PlatformDaemon/ReloadConfig":     scope(platform, write),
		"/platform.v1.PlatformDaemon/StartService":     scope(platform, write),
		"/platform.v1.PlatformDaemon/StopService":      scope(platform, write),
		"/platform.v1.PlatformDaemon/RestartService":   scope(platform, write),
		"/platform.v1.PlatformDaemon/Shutdown":         scope(platform, admin),
		"/platform.v1.PlatformDaemon/DumpEntityType":   scope(platform, admin),

		// ---------------------------------------------------------------------
		// Standard gRPC health (grpc.health.v1.Health). Check is the pre-auth
		// probe; List and Watch are platform reads.
		// ---------------------------------------------------------------------
		"/grpc.health.v1.Health/List":  scope(platform, read),
		"/grpc.health.v1.Health/Watch": scope(platform, read),

		// ---------------------------------------------------------------------
		// Attestation (AttestationService). Reads serve cached reports and
		// verify evidence; refreshing and collecting spend TPM time, so they are
		// writes, as with the MCP attestation_device_refresh tool.
		// ---------------------------------------------------------------------
		"/platform.v1.AttestationService/GetDeviceReport":             scope(attestation, read),
		"/platform.v1.AttestationService/ListDeviceReports":           scope(attestation, read),
		"/platform.v1.AttestationService/StreamDeviceVerdicts":        scope(attestation, read),
		"/platform.v1.AttestationService/PollDeviceVerdicts":          scope(attestation, read),
		"/platform.v1.AttestationService/DescribeCallerPolicy":        scope(attestation, read),
		"/platform.v1.AttestationService/RefreshDeviceReport":         scope(attestation, write),
		"/platform.v1.AttestationService/GetAttestationQuote":         scope(attestation, read),
		"/platform.v1.AttestationService/VerifyAttestationQuote":      scope(attestation, read),
		"/platform.v1.AttestationService/BuildManifest":               scope(attestation, write),
		"/platform.v1.AttestationService/GetManifest":                 scope(attestation, read),
		"/platform.v1.AttestationService/ListManifests":               scope(attestation, read),
		"/platform.v1.AttestationService/VerifyManifest":              scope(attestation, read),
		"/platform.v1.AttestationService/DeleteManifest":              scope(attestation, del),
		"/platform.v1.AttestationService/CollectHostAttestation":      scope(attestation, write),
		"/platform.v1.AttestationService/CollectVMAttestation":        scope(attestation, write),
		"/platform.v1.AttestationService/CollectContainerAttestation": scope(attestation, write),

		// ---------------------------------------------------------------------
		// BMC (BMCService). Same vocabulary as the MCP platform_bmc_* tools:
		// read observes, write changes state recoverably, power interrupts a
		// running node, media chooses what it boots, admin changes which
		// credentials the BMC trusts. Provision composes boot device, virtual
		// media and power in one call, so it takes admin: neither bmc:media nor
		// bmc:power alone may confer the whole sequence.
		// ---------------------------------------------------------------------
		"/platform.v1.BMCService/PowerStatus":           scope(bmc, read),
		"/platform.v1.BMCService/GetBootDevice":         scope(bmc, read),
		"/platform.v1.BMCService/VirtualMediaStatus":    scope(bmc, read),
		"/platform.v1.BMCService/GetSensors":            scope(bmc, read),
		"/platform.v1.BMCService/GetSystemInfo":         scope(bmc, read),
		"/platform.v1.BMCService/ListUsers":             scope(bmc, read),
		"/platform.v1.BMCService/GetWebCertificate":     scope(bmc, read),
		"/platform.v1.BMCService/ProvisionStatus":       scope(bmc, read),
		"/platform.v1.BMCService/PowerOn":               scope(bmc, write),
		"/platform.v1.BMCService/SetBootDevice":         scope(bmc, write),
		"/platform.v1.BMCService/PowerOff":              scope(bmc, power),
		"/platform.v1.BMCService/PowerReset":            scope(bmc, power),
		"/platform.v1.BMCService/PowerCycle":            scope(bmc, power),
		"/platform.v1.BMCService/MountISO":              scope(bmc, media),
		"/platform.v1.BMCService/UnmountISO":            scope(bmc, media),
		"/platform.v1.BMCService/EnrollBMC":             scope(bmc, admin),
		"/platform.v1.BMCService/RestoreFactoryCert":    scope(bmc, admin),
		"/platform.v1.BMCService/ReplaceWebCertificate": scope(bmc, admin),
		"/platform.v1.BMCService/CreateUser":            scope(bmc, admin),
		"/platform.v1.BMCService/DeleteUser":            scope(bmc, admin),
		"/platform.v1.BMCService/SetUserPassword":       scope(bmc, admin),
		"/platform.v1.BMCService/SetUserPrivilege":      scope(bmc, admin),
		"/platform.v1.BMCService/Provision":             scope(bmc, admin),

		// ---------------------------------------------------------------------
		// Barrier (BarrierService). The barrier lifecycle is go-qrdb's seal
		// family; Init covers both single-key and Shamir initialization.
		// ---------------------------------------------------------------------
		"/platform.v1.BarrierService/GetStatus": scope(seal, status),
		"/platform.v1.BarrierService/Init":      scope(seal, bootstrap),
		"/platform.v1.BarrierService/Unseal":    scope(seal, unseal),
		"/platform.v1.BarrierService/Seal":      scope(seal, sealBarrier),
		"/platform.v1.BarrierService/Rekey":     scope(seal, rekey),

		// ---------------------------------------------------------------------
		// Ceremony (CeremonyService). Init and Status are scoped, not pre-auth:
		// first boot has no token, so it reaches them over the Unix socket
		// (not token-gated) or the pre-auth REST /init route. The scope
		// protects the TCP listener, where an unauthenticated Init would let a
		// remote caller seize an uninitialized platform (#766).
		// ---------------------------------------------------------------------
		"/platform.v1.CeremonyService/Init":               scope(ceremony, initialize),
		"/platform.v1.CeremonyService/Status":             scope(ceremony, status),
		"/platform.v1.CeremonyService/ClaimCertBegin":     scope(ceremony, claimCert),
		"/platform.v1.CeremonyService/ClaimCertComplete":  scope(ceremony, claimCert),
		"/platform.v1.CeremonyService/ClaimShareBegin":    scope(ceremony, claimShareBegin),
		"/platform.v1.CeremonyService/ClaimShareComplete": scope(ceremony, claimShareComplete),
		"/platform.v1.CeremonyService/SignCSR":            scope(ceremony, signCSR),

		// ---------------------------------------------------------------------
		// Cluster (ClusterService)
		// ---------------------------------------------------------------------
		"/platform.v1.ClusterService/GetStatus": scope(cluster, read),
		"/platform.v1.ClusterService/ListNodes": scope(cluster, read),
		"/platform.v1.ClusterService/Bootstrap": scope(cluster, write),
		"/platform.v1.ClusterService/Join":      scope(cluster, write),
		"/platform.v1.ClusterService/Leave":     scope(cluster, write),

		// ---------------------------------------------------------------------
		// Compute (ComputeService). Containers and VMs are separate resources,
		// as in the advertised container:* scopes. Interactive attach, exec
		// and console input act on the workload, so they are writes.
		// ---------------------------------------------------------------------
		"/platform.v1.ComputeService/CreateContainer":     scope(container, write),
		"/platform.v1.ComputeService/StartContainer":      scope(container, write),
		"/platform.v1.ComputeService/StopContainer":       scope(container, write),
		"/platform.v1.ComputeService/DeleteContainer":     scope(container, del),
		"/platform.v1.ComputeService/GetContainer":        scope(container, read),
		"/platform.v1.ComputeService/ListContainers":      scope(container, read),
		"/platform.v1.ComputeService/GetContainerLogs":    scope(container, read),
		"/platform.v1.ComputeService/GetContainerMetrics": scope(container, read),
		"/platform.v1.ComputeService/ExecContainer":       scope(container, write),
		"/platform.v1.ComputeService/AttachContainer":     scope(container, write),
		"/platform.v1.ComputeService/AttestContainer":     scope(container, read),

		"/platform.v1.ComputeService/CreateVM":            scope(vm, write),
		"/platform.v1.ComputeService/StartVM":             scope(vm, write),
		"/platform.v1.ComputeService/StopVM":              scope(vm, write),
		"/platform.v1.ComputeService/RebootVM":            scope(vm, write),
		"/platform.v1.ComputeService/SuspendVM":           scope(vm, write),
		"/platform.v1.ComputeService/ResumeVM":            scope(vm, write),
		"/platform.v1.ComputeService/DeleteVM":            scope(vm, del),
		"/platform.v1.ComputeService/GetVM":               scope(vm, read),
		"/platform.v1.ComputeService/ListVMs":             scope(vm, read),
		"/platform.v1.ComputeService/GetVMLogs":           scope(vm, read),
		"/platform.v1.ComputeService/GetVMMetrics":        scope(vm, read),
		"/platform.v1.ComputeService/AttachDisk":          scope(vm, write),
		"/platform.v1.ComputeService/DetachDisk":          scope(vm, write),
		"/platform.v1.ComputeService/ResizeDisk":          scope(vm, write),
		"/platform.v1.ComputeService/CreateSnapshot":      scope(vm, write),
		"/platform.v1.ComputeService/RestoreSnapshot":     scope(vm, write),
		"/platform.v1.ComputeService/DeleteSnapshot":      scope(vm, del),
		"/platform.v1.ComputeService/ListSnapshots":       scope(vm, read),
		"/platform.v1.ComputeService/GetSnapshot":         scope(vm, read),
		"/platform.v1.ComputeService/MigrateVM":           scope(vm, write),
		"/platform.v1.ComputeService/PrepareMigration":    scope(vm, write),
		"/platform.v1.ComputeService/FinalizeMigration":   scope(vm, write),
		"/platform.v1.ComputeService/AttachVMConsole":     scope(vm, write),
		"/platform.v1.ComputeService/SendVMConsoleInput":  scope(vm, write),
		"/platform.v1.ComputeService/AttestVM":            scope(vm, read),
		"/platform.v1.ComputeService/VerifyVMAttestation": scope(vm, read),

		// ---------------------------------------------------------------------
		// Config delivery, operator half (ConfigDeliveryService). The
		// machine-facing half is pre-auth.
		// ---------------------------------------------------------------------
		"/platform.v1.ConfigDeliveryService/ListSessions":   scope(provisioning, read),
		"/platform.v1.ConfigDeliveryService/GetSession":     scope(provisioning, read),
		"/platform.v1.ConfigDeliveryService/FulfillSession": scope(provisioning, write),

		// ---------------------------------------------------------------------
		// Provisioning gateway (ProvisioningGateway). Generated but not
		// registered by platformd today; classified so registering it later
		// cannot open it.
		// ---------------------------------------------------------------------
		"/platform.v1.ProvisioningGateway/GetBootConfig":         scope(provisioning, read),
		"/platform.v1.ProvisioningGateway/RegisterPXEDevice":     scope(provisioning, write),
		"/platform.v1.ProvisioningGateway/ReportDeviceState":     scope(provisioning, write),
		"/platform.v1.ProvisioningGateway/NotifyInstallComplete": scope(provisioning, write),

		// ---------------------------------------------------------------------
		// EAB credentials (EABService)
		// ---------------------------------------------------------------------
		"/platform.v1.EABService/CreateCredential":          scope(eab, write),
		"/platform.v1.EABService/GetCredential":             scope(eab, read),
		"/platform.v1.EABService/GetCredentialByKeyID":      scope(eab, read),
		"/platform.v1.EABService/GetCredentialQRCode":       scope(eab, read),
		"/platform.v1.EABService/GetEnrollmentURL":          scope(eab, read),
		"/platform.v1.EABService/ListCredentials":           scope(eab, read),
		"/platform.v1.EABService/ValidateCredential":        scope(eab, read),
		"/platform.v1.EABService/MarkCredentialUsed":        scope(eab, write),
		"/platform.v1.EABService/RevokeCredential":          scope(eab, write),
		"/platform.v1.EABService/CleanupExpiredCredentials": scope(eab, write),
		"/platform.v1.EABService/DeleteCredential":          scope(eab, del),

		// ---------------------------------------------------------------------
		// FIDO2 (FIDO2Service)
		// ---------------------------------------------------------------------
		"/platform.v1.FIDO2Service/Info":         scope(fido2, read),
		"/platform.v1.FIDO2Service/ListDevices":  scope(fido2, read),
		"/platform.v1.FIDO2Service/WaitDevice":   scope(fido2, read),
		"/platform.v1.FIDO2Service/Register":     scope(fido2, write),
		"/platform.v1.FIDO2Service/Authenticate": scope(fido2, write),

		// ---------------------------------------------------------------------
		// IDevID / IAK (IDevIDService)
		// ---------------------------------------------------------------------
		"/platform.v1.IDevIDService/GetDeviceAttributes":      scope(idevid, read),
		"/platform.v1.IDevIDService/GetIAKCertificate":        scope(idevid, read),
		"/platform.v1.IDevIDService/GetIAKInfo":               scope(idevid, read),
		"/platform.v1.IDevIDService/GetIDevIDCertificate":     scope(idevid, read),
		"/platform.v1.IDevIDService/GetIDevIDInfo":            scope(idevid, read),
		"/platform.v1.IDevIDService/HasIAK":                   scope(idevid, read),
		"/platform.v1.IDevIDService/HasIDevID":                scope(idevid, read),
		"/platform.v1.IDevIDService/ActivateCredential":       scope(idevid, write),
		"/platform.v1.IDevIDService/CreateIAKCSR":             scope(idevid, write),
		"/platform.v1.IDevIDService/CreateIDevIDCSR":          scope(idevid, write),
		"/platform.v1.IDevIDService/CreateLDevID":             scope(idevid, write),
		"/platform.v1.IDevIDService/FlushTransientContexts":   scope(idevid, write),
		"/platform.v1.IDevIDService/GenerateIAK":              scope(idevid, write),
		"/platform.v1.IDevIDService/GenerateIDevID":           scope(idevid, write),
		"/platform.v1.IDevIDService/InstallIAKCertificate":    scope(idevid, write),
		"/platform.v1.IDevIDService/InstallIDevIDCertificate": scope(idevid, write),
		"/platform.v1.IDevIDService/DeleteIAK":                scope(idevid, del),
		"/platform.v1.IDevIDService/DeleteIAKCertificate":     scope(idevid, del),
		"/platform.v1.IDevIDService/DeleteIDevID":             scope(idevid, del),
		"/platform.v1.IDevIDService/DeleteIDevIDCertificate":  scope(idevid, del),

		// ---------------------------------------------------------------------
		// Invitations, admin half (InvitationService). Same scopes as the MCP
		// platform_invitation_* tools; the invitee half is pre-auth.
		// ---------------------------------------------------------------------
		"/platform.v1.InvitationService/CreateInvitation": scope(invitation, write),
		"/platform.v1.InvitationService/GetInvitation":    scope(invitation, read),
		"/platform.v1.InvitationService/ListInvitations":  scope(invitation, read),
		"/platform.v1.InvitationService/RevokeInvitation": scope(invitation, write),
		"/platform.v1.InvitationService/DeleteInvitation": scope(invitation, del),

		// ---------------------------------------------------------------------
		// LUKS (LUKSService)
		// ---------------------------------------------------------------------
		"/platform.v1.LUKSService/Info":             scope(luks, read),
		"/platform.v1.LUKSService/ListSlots":        scope(luks, read),
		"/platform.v1.LUKSService/Status":           scope(luks, read),
		"/platform.v1.LUKSService/TestUnlock":       scope(luks, read),
		"/platform.v1.LUKSService/ChangePassphrase": scope(luks, write),
		"/platform.v1.LUKSService/EnrollFIDO2":      scope(luks, write),
		"/platform.v1.LUKSService/EnrollPassphrase": scope(luks, write),
		"/platform.v1.LUKSService/EnrollRecovery":   scope(luks, write),
		"/platform.v1.LUKSService/EnrollTPM":        scope(luks, write),
		"/platform.v1.LUKSService/RemoveKey":        scope(luks, del),

		// ---------------------------------------------------------------------
		// PIV (PIVService)
		// ---------------------------------------------------------------------
		"/platform.v1.PIVService/ListDevices": scope(piv, read),
		"/platform.v1.PIVService/ListSlots":   scope(piv, read),
		"/platform.v1.PIVService/SlotInfo":    scope(piv, read),
		"/platform.v1.PIVService/Attest":      scope(piv, read),
		"/platform.v1.PIVService/Generate":    scope(piv, write),
		"/platform.v1.PIVService/Import":      scope(piv, write),
		"/platform.v1.PIVService/Sign":        scope(piv, use),
		"/platform.v1.PIVService/Reset":       scope(piv, del),

		// ---------------------------------------------------------------------
		// PXE (PXEService)
		// ---------------------------------------------------------------------
		"/platform.v1.PXEService/GetDevice":             scope(pxe, read),
		"/platform.v1.PXEService/GetDeviceByMAC":        scope(pxe, read),
		"/platform.v1.PXEService/GetEvents":             scope(pxe, read),
		"/platform.v1.PXEService/GetStatus":             scope(pxe, read),
		"/platform.v1.PXEService/ListDevices":           scope(pxe, read),
		"/platform.v1.PXEService/Authorize":             scope(pxe, write),
		"/platform.v1.PXEService/Quarantine":            scope(pxe, write),
		"/platform.v1.PXEService/RegisterDevice":        scope(pxe, write),
		"/platform.v1.PXEService/Retry":                 scope(pxe, write),
		"/platform.v1.PXEService/SetDeviceEnrolled":     scope(pxe, write),
		"/platform.v1.PXEService/BindDeviceCertificate": scope(pxe, write),
		"/platform.v1.PXEService/StartService":          scope(pxe, write),
		"/platform.v1.PXEService/StopService":           scope(pxe, write),
		"/platform.v1.PXEService/UpdateState":           scope(pxe, write),
		"/platform.v1.PXEService/WebhookComplete":       scope(pxe, write),
		"/platform.v1.PXEService/RemoveDevice":          scope(pxe, del),

		// ---------------------------------------------------------------------
		// OCI registry (RegistryService)
		// ---------------------------------------------------------------------
		"/platform.v1.RegistryService/Inspect": scope(registry, read),
		"/platform.v1.RegistryService/List":    scope(registry, read),
		"/platform.v1.RegistryService/Status":  scope(registry, read),
		"/platform.v1.RegistryService/Pull":    scope(registry, read),
		"/platform.v1.RegistryService/Push":    scope(registry, write),
		"/platform.v1.RegistryService/Delete":  scope(registry, del),

		// ---------------------------------------------------------------------
		// Physical switch ports (SwitchService)
		// ---------------------------------------------------------------------
		"/platform.v1.SwitchService/GetPortStatus": scope(switchPorts, read),
		"/platform.v1.SwitchService/ListPorts":     scope(switchPorts, read),
		"/platform.v1.SwitchService/EnablePort":    scope(switchPorts, write),
		"/platform.v1.SwitchService/DisablePort":   scope(switchPorts, write),
		"/platform.v1.SwitchService/SetPortVLAN":   scope(switchPorts, write),

		// ---------------------------------------------------------------------
		// Host TPM (TPMService). Follows the vTPM split: quote and unseal are
		// reads, seal and NV writes are writes; removing keys or clearing the
		// TPM is a delete.
		// ---------------------------------------------------------------------
		"/platform.v1.TPMService/Info":                  scope(tpm, read),
		"/platform.v1.TPMService/GetCapabilities":       scope(tpm, read),
		"/platform.v1.TPMService/GetPlatformAttributes": scope(tpm, read),
		"/platform.v1.TPMService/ExtendPCR":             scope(tpm, write),
		"/platform.v1.TPMService/GetAK":                 scope(tpm, read),
		"/platform.v1.TPMService/GetEK":                 scope(tpm, read),
		"/platform.v1.TPMService/GetEKCertificate":      scope(tpm, read),
		"/platform.v1.TPMService/GetSRK":                scope(tpm, read),
		"/platform.v1.TPMService/GetEventLog":           scope(tpm, read),
		"/platform.v1.TPMService/GetPCRs":               scope(tpm, read),
		"/platform.v1.TPMService/GetRandom":             scope(tpm, read),
		"/platform.v1.TPMService/Quote":                 scope(tpm, read),
		"/platform.v1.TPMService/VerifyQuote":           scope(tpm, read),
		"/platform.v1.TPMService/Certify":               scope(tpm, read),
		"/platform.v1.TPMService/ReadNVRAM":             scope(tpm, read),
		"/platform.v1.TPMService/Unseal":                scope(tpm, read),
		"/platform.v1.TPMService/MakeCredential":        scope(tpm, read),
		"/platform.v1.TPMService/ActivateCredential":    scope(tpm, write),
		"/platform.v1.TPMService/CreateAK":              scope(tpm, write),
		"/platform.v1.TPMService/CreateEK":              scope(tpm, write),
		"/platform.v1.TPMService/CreateSRK":             scope(tpm, write),
		"/platform.v1.TPMService/DefineNVRAM":           scope(tpm, write),
		"/platform.v1.TPMService/WriteNVRAM":            scope(tpm, write),
		"/platform.v1.TPMService/ImportEKCertificate":   scope(tpm, write),
		"/platform.v1.TPMService/Provision":             scope(tpm, write),
		"/platform.v1.TPMService/Seal":                  scope(tpm, write),
		"/platform.v1.TPMService/DeleteAK":              scope(tpm, del),
		"/platform.v1.TPMService/DeleteEK":              scope(tpm, del),
		"/platform.v1.TPMService/DeleteSRK":             scope(tpm, del),
		"/platform.v1.TPMService/UndefineNVRAM":         scope(tpm, del),
		"/platform.v1.TPMService/Clear":                 scope(tpm, del),

		// ---------------------------------------------------------------------
		// Tenants (TenantService). Per-tenant barrier and DEK operations change
		// tenant state, so they are writes.
		// ---------------------------------------------------------------------
		"/platform.v1.TenantService/GetTenant":              scope(tenant, read),
		"/platform.v1.TenantService/GetTenantByName":        scope(tenant, read),
		"/platform.v1.TenantService/ListTenants":            scope(tenant, read),
		"/platform.v1.TenantService/GetQuotas":              scope(tenant, read),
		"/platform.v1.TenantService/CheckQuota":             scope(tenant, read),
		"/platform.v1.TenantService/GetUsage":               scope(tenant, read),
		"/platform.v1.TenantService/GetTenantBarrierStatus": scope(tenant, read),
		"/platform.v1.TenantService/GetTenantDEKStatus":     scope(tenant, read),
		"/platform.v1.TenantService/CreateTenant":           scope(tenant, write),
		"/platform.v1.TenantService/UpdateTenant":           scope(tenant, write),
		"/platform.v1.TenantService/UpdateQuotas":           scope(tenant, write),
		"/platform.v1.TenantService/SuspendTenant":          scope(tenant, write),
		"/platform.v1.TenantService/ResumeTenant":           scope(tenant, write),
		"/platform.v1.TenantService/Sync":                   scope(tenant, write),
		"/platform.v1.TenantService/InitTenantBarrier":      scope(tenant, write),
		"/platform.v1.TenantService/SealTenantBarrier":      scope(tenant, write),
		"/platform.v1.TenantService/UnsealTenantBarrier":    scope(tenant, write),
		"/platform.v1.TenantService/RotateTenantDEK":        scope(tenant, write),
		"/platform.v1.TenantService/DeleteTenant":           scope(tenant, del),
	}
}
