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

import "strings"

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
// A method that is absent from the map carries no required scope: the
// interceptor allows it once the token is validated. QUIC and MCP instead
// deny an operation missing from their catalogs. This keeps the catalog
// focused on the resource services that participate in scope-based
// authorization (vtpm, dns, device, sdn, kms, iam, ca). Public / health
// methods never reach this point — they are handled by the interceptor's skip list.

// grpcMethodPermissions maps a gRPC FullMethod to its required colon
// "resource:action" scope. It is built once and treated as read-only.
var grpcMethodPermissions = buildGRPCMethodPermissions()

// ScopeForMethod returns the colon "resource:action" scope a gRPC method
// requires, or the empty string when the method is not in the catalog (no scope
// required). The lookup is constant time.
func ScopeForMethod(fullMethod string) string {
	return grpcMethodPermissions[fullMethod]
}

// claimsOnlyResources are the scope resources that only a claims-bearing
// platform token can authorize. A bool-only validator proves a token is valid
// but yields no scopes, so the interceptor refuses these methods on that path
// instead of letting any valid token through. This mirrors QUIC
// AuthorizeSubOpcode, which refuses the same ceremony, PIV and FIDO2
// operations when no AuthorizedContext is attached.
var claimsOnlyResources = map[string]bool{
	"piv":      true,
	"fido2":    true,
	"ceremony": true,
}

// scopeRequiresClaims reports whether a colon "resource:action" scope names a
// resource in claimsOnlyResources.
func scopeRequiresClaims(scope string) bool {
	resource, _, found := strings.Cut(scope, ":")
	return found && claimsOnlyResources[resource]
}

// buildGRPCMethodPermissions constructs the FullMethod -> scope catalog. The
// resource/action pairs mirror the QUIC operation catalog and the MCP
// toolPermissions for the same capabilities; the daemon's QUIC authorization
// contract test pins the parity.
func buildGRPCMethodPermissions() map[string]string {
	const (
		read  = "read"
		write = "write"
		del   = "delete"
		// signCSR certifies an existing KMS key. It is its own action
		// so that ca:write, which issues certificates the CA keys
		// itself, does not reach it; only ca:* or *:* covers it.
		signCSR = "sign-csr"
		vtpm    = "vtpm"
		dns     = "dns"
		device  = "device"
		sdn     = "sdn"
		kms     = "kms"
		iam     = "iam"
		ca      = "ca"
		prox    = "proxy"
		ntp     = "ntp"
		piv     = "piv"
		fido2   = "fido2"
		cer     = "ceremony"
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
		// PIV (PIVService) — smartcard slots. Generate, Import, Sign and Reset
		// change key material or use a private key; enumeration and attestation
		// are reads.
		// ---------------------------------------------------------------------
		"/platform.v1.PIVService/ListDevices": scope(piv, read),
		"/platform.v1.PIVService/ListSlots":   scope(piv, read),
		"/platform.v1.PIVService/SlotInfo":    scope(piv, read),
		"/platform.v1.PIVService/Attest":      scope(piv, read),
		"/platform.v1.PIVService/Generate":    scope(piv, write),
		"/platform.v1.PIVService/Import":      scope(piv, write),
		"/platform.v1.PIVService/Sign":        scope(piv, write),
		"/platform.v1.PIVService/Reset":       scope(piv, write),

		// ---------------------------------------------------------------------
		// FIDO2 (FIDO2Service) — device enumeration is a read; Register and
		// Authenticate drive a user-presence ceremony on the token.
		// ---------------------------------------------------------------------
		"/platform.v1.FIDO2Service/ListDevices":  scope(fido2, read),
		"/platform.v1.FIDO2Service/WaitDevice":   scope(fido2, read),
		"/platform.v1.FIDO2Service/Info":         scope(fido2, read),
		"/platform.v1.FIDO2Service/Register":     scope(fido2, write),
		"/platform.v1.FIDO2Service/Authenticate": scope(fido2, write),

		// ---------------------------------------------------------------------
		// Ceremony (CeremonyService) — Init and Status are scoped like the rest.
		// First boot has no token to present, so it reaches them over the Unix
		// socket (not token-gated) or the pre-auth REST /init route; the scope
		// protects the TCP listener, where an unauthenticated Init would let a
		// remote caller seize an uninitialized platform.
		// ---------------------------------------------------------------------
		"/platform.v1.CeremonyService/Status":             scope(cer, read),
		"/platform.v1.CeremonyService/Init":               scope(cer, write),
		"/platform.v1.CeremonyService/ClaimCertBegin":     scope(cer, write),
		"/platform.v1.CeremonyService/ClaimCertComplete":  scope(cer, write),
		"/platform.v1.CeremonyService/ClaimShareBegin":    scope(cer, write),
		"/platform.v1.CeremonyService/ClaimShareComplete": scope(cer, write),
		"/platform.v1.CeremonyService/SignCSR":            scope(cer, write),

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
		"/platform.v1.DeviceService/CreateProfile":             scope(device, write),
		"/platform.v1.DeviceService/CreateProfileFromTemplate": scope(device, write),
		"/platform.v1.DeviceService/UpdateProfile":             scope(device, write),
		"/platform.v1.DeviceService/DeleteProfile":             scope(device, del),
		"/platform.v1.DeviceService/GetProfile":                scope(device, read),
		"/platform.v1.DeviceService/ListProfiles":              scope(device, read),
		"/platform.v1.DeviceService/CountProfiles":             scope(device, read),
		"/platform.v1.DeviceService/FindMatchingProfile":       scope(device, read),
		"/platform.v1.DeviceService/FindProfileByMACAddress":   scope(device, read),
		"/platform.v1.DeviceService/FindProfileBySerial":       scope(device, read),

		// ---------------------------------------------------------------------
		// SDN (SDNService)
		// ---------------------------------------------------------------------
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
		"/platform.v1.GatewayService/GetGatewaySnapshot":   scope(sdn, read),
		"/platform.v1.GatewayService/ListGatewaySnapshots": scope(sdn, read),

		// -----------------------------------------------------------------
		// Gateway performance verification (GatewayService)
		// -----------------------------------------------------------------
		// GetPerfFlows mutates bridge flow tables (ephemeral install +
		// cookie-scoped delete in table 250), so it requires sdn:write;
		// the datapath / conntrack counters are read-only.
		"/platform.v1.GatewayService/GetPerfFlows":     scope(sdn, write),
		"/platform.v1.GatewayService/GetPerfDatapath":  scope(sdn, read),
		"/platform.v1.GatewayService/GetPerfConntrack": scope(sdn, read),

		"/platform.v1.SDNService/CreateBridge":     scope(sdn, write),
		"/platform.v1.SDNService/DeleteBridge":     scope(sdn, del),
		"/platform.v1.SDNService/GetBridge":        scope(sdn, read),
		"/platform.v1.SDNService/ListBridges":      scope(sdn, read),
		"/platform.v1.SDNService/AddPort":          scope(sdn, write),
		"/platform.v1.SDNService/DeletePort":       scope(sdn, del),
		"/platform.v1.SDNService/GetPort":          scope(sdn, read),
		"/platform.v1.SDNService/ListPorts":        scope(sdn, read),
		"/platform.v1.SDNService/SetPortState":     scope(sdn, write),
		"/platform.v1.SDNService/GetPortStats":     scope(sdn, read),
		"/platform.v1.SDNService/AuthenticatePort": scope(sdn, write),
		"/platform.v1.SDNService/RevokePortAuth":   scope(sdn, write),
		"/platform.v1.SDNService/ApplyPolicy":      scope(sdn, write),
		"/platform.v1.SDNService/GetPolicy":        scope(sdn, read),
		"/platform.v1.SDNService/ListPolicies":     scope(sdn, read),
		"/platform.v1.SDNService/DeletePolicy":     scope(sdn, del),
		"/platform.v1.SDNService/AddFlow":          scope(sdn, write),
		"/platform.v1.SDNService/DeleteFlow":       scope(sdn, del),
		"/platform.v1.SDNService/FlushFlows":       scope(sdn, write),
		"/platform.v1.SDNService/ListFlows":        scope(sdn, read),
		"/platform.v1.SDNService/GetFlowStats":     scope(sdn, read),
		"/platform.v1.SDNService/StreamFlowLogs":   scope(sdn, read),
		"/platform.v1.SDNService/CreateVLAN":       scope(sdn, write),
		"/platform.v1.SDNService/DeleteVLAN":       scope(sdn, del),
		"/platform.v1.SDNService/ListVLANs":        scope(sdn, read),

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
		// CA (CAService)
		// ---------------------------------------------------------------------
		"/platform.v1.CAService/InitCA":                  scope(ca, write),
		"/platform.v1.CAService/IssueCertificate":        scope(ca, write),
		"/platform.v1.CAService/SignCSR":                 scope(ca, signCSR),
		"/platform.v1.CAService/RenewCertificate":        scope(ca, write),
		"/platform.v1.CAService/RevokeCertificate":       scope(ca, write),
		"/platform.v1.CAService/GetCertificate":          scope(ca, read),
		"/platform.v1.CAService/ListCertificates":        scope(ca, read),
		"/platform.v1.CAService/VerifyCertificate":       scope(ca, read),
		"/platform.v1.CAService/GetCAInfo":               scope(ca, read),
		"/platform.v1.CAService/GetCABundle":             scope(ca, read),
		"/platform.v1.CAService/GetCRL":                  scope(ca, read),
		"/platform.v1.CAService/InstallCACertificates":   scope(ca, write),
		"/platform.v1.CAService/UninstallCACertificates": scope(ca, del),
	}
}
