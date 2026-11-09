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

package v1

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restca "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/ca"
)

// DaemonRouteAuthorizer returns the authorization a privileged replayed
// daemon route takes behind the client-certificate gate: the webservice's
// own admin gate, plus scope when scope is not empty.
type DaemonRouteAuthorizer func(scope string) func(http.Handler) http.Handler

// DaemonCallerAuthenticator authenticates the caller of a replayed daemon
// route whose handler authorizes by its caller's role, and publishes that
// caller to the handler (restapi.WithCaller).
type DaemonCallerAuthenticator func(http.Handler) http.Handler

// callerCheckedDaemonMethodRoutes lists, keyed "METHOD template", the
// replayed daemon routes that stay open to every user but whose handler
// decides by its caller: issue-cert serves a user their own certificate and
// an admin anyone's. The certificate on the connection names no role, so
// these take the webservice session's principal.
var callerCheckedDaemonMethodRoutes = map[string]struct{}{
	http.MethodPost + " /api/v1/users/{id}/factors/mtls/issue-cert": {},
}

// privilegedDaemonRoutes maps each daemon CA route that mutates the CA or
// enumerates what it issued to the scope its webservice twin requires on
// top of the admin role (pkg/webservice/v1/rest/ca/router.go); an empty
// scope means the twin takes the admin role alone. Keys are the path
// template the replayed route carries; every method on it is guarded, so a
// route the daemon registers without a method restriction is too. A path the webservice serves
// itself keeps its webservice handler, so these guard what reaches the
// daemon: POST .../revoke always, the rest when the webservice serves no CA.
// The daemon's CA info, CRL and bundle stay on the certificate gate alone,
// as their webservice twins are public.
var privilegedDaemonRoutes = map[string]string{
	// Issue (POST) and list (GET); the webservice twins take the admin role.
	"/api/v1/ca/certificates":                 "",
	"/api/v1/ca/certificates/{serial}":        "",
	"/api/v1/ca/certificates/{serial}/revoke": restca.RevokeScope,
	"/api/v1/ca/certificates/{serial}/renew":  restca.RenewScope,
	"/api/v1/ca/certificates/verify":          restca.VerifyScope,
	"/api/v1/ca/sign-csr":                     restca.SignCSRScope,
}

// The per-operation scopes the replayed daemon routes take, as the MCP and
// gRPC catalogs name them for the same operations (pkg/api/mcp/authz.go,
// pkg/api/mcp/bmc_tools.go).
const (
	bmcReadScope           = "bmc:read"
	bmcWriteScope          = "bmc:write"
	bmcPowerScope          = "bmc:power"
	bmcMediaScope          = "bmc:media"
	bmcAdminScope          = "bmc:admin"
	platformReadScope      = "platform:read"
	platformWriteScope     = "platform:write"
	clusterReadScope       = "cluster:read"
	clusterWriteScope      = "cluster:write"
	ceremonyWriteScope     = "ceremony:write"
	pivReadScope           = "piv:read"
	pivWriteScope          = "piv:write"
	luksReadScope          = "luks:read"
	luksWriteScope         = "luks:write"
	luksDeleteScope        = "luks:delete"
	fido2ReadScope         = "fido2:read"
	fido2WriteScope        = "fido2:write"
	idevidReadScope        = "idevid:read"
	idevidWriteScope       = "idevid:write"
	idevidDeleteScope      = "idevid:delete"
	provisioningReadScope  = "provisioning:read"
	provisioningWriteScope = "provisioning:write"
	deviceReadScope        = "device:read"
	deviceWriteScope       = "device:write"
	deviceDeleteScope      = "device:delete"
	kmsReadScope           = "kms:read"
	kmsWriteScope          = "kms:write"
	kmsDeleteScope         = "kms:delete"
	sdnReadScope           = "sdn:read"
	sdnWriteScope          = "sdn:write"
	sdnDeleteScope         = "sdn:delete"
)

// privilegedDaemonMethodRoutes is privilegedDaemonRoutes keyed by
// "METHOD template", for replayed daemon routes whose methods on one path
// template need different scopes, or of which one method stays open to any
// certificate holder. Each value is the scope the operation takes on the
// MCP and gRPC transports; an empty scope means the admin role alone.
var privilegedDaemonMethodRoutes = map[string]string{
	// Changing a tenant's MFA policy is a tenant-administration act; reading
	// it stays on the certificate gate, as the login flow does. No scope
	// names it. The admin role does not say which tenant the caller
	// administers, so the PUT, and only the PUT, also takes the
	// own-tenant-or-system guard (ownTenantDaemonMethodRoutes).
	http.MethodPut + " /api/v1/tenants/{id}/security/mfa-policy": "",

	// Daemon core. The health report names every component with its failure
	// message, the reconnaissance the platform:read scope gates on gRPC.
	http.MethodGet + " /api/v1/health":                      platformReadScope,
	http.MethodGet + " /api/v1/version":                     platformReadScope,
	http.MethodGet + " /api/v1/protocols":                   platformReadScope,
	http.MethodGet + " /api/v1/services":                    platformReadScope,
	http.MethodGet + " /api/v1/services/{service}":          platformReadScope,
	http.MethodPost + " /api/v1/services/{service}/start":   platformWriteScope,
	http.MethodPost + " /api/v1/services/{service}/stop":    platformWriteScope,
	http.MethodPost + " /api/v1/services/{service}/restart": platformWriteScope,

	// BMC. A power action may switch the host off, so the route takes the
	// power scope the off, reset and cycle tools take.
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/power":                        bmcPowerScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/power":                         bmcReadScope,
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/boot-device":                  bmcWriteScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/boot-device":                   bmcReadScope,
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/virtual-media":                bmcMediaScope,
	http.MethodDelete + " /api/v1/bmc/{profileID:[0-9]+}/virtual-media":              bmcMediaScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/virtual-media":                 bmcReadScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/sensors":                       bmcReadScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/system-info":                   bmcReadScope,
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/provision":                    bmcAdminScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/provision":                     bmcReadScope,
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/enroll":                       bmcAdminScope,
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/cert/restore":                 bmcAdminScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/cert":                          bmcReadScope,
	http.MethodPut + " /api/v1/bmc/{profileID:[0-9]+}/cert":                          bmcAdminScope,
	http.MethodGet + " /api/v1/bmc/{profileID:[0-9]+}/users":                         bmcReadScope,
	http.MethodPost + " /api/v1/bmc/{profileID:[0-9]+}/users":                        bmcAdminScope,
	http.MethodDelete + " /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}":        bmcAdminScope,
	http.MethodPut + " /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/password":  bmcAdminScope,
	http.MethodPut + " /api/v1/bmc/{profileID:[0-9]+}/users/{slot:[0-9]+}/privilege": bmcAdminScope,

	// Cluster membership.
	http.MethodGet + " /api/v1/cluster/status":     clusterReadScope,
	http.MethodGet + " /api/v1/cluster/nodes":      clusterReadScope,
	http.MethodPost + " /api/v1/cluster/bootstrap": clusterWriteScope,
	http.MethodPost + " /api/v1/cluster/join":      clusterWriteScope,
	http.MethodPost + " /api/v1/cluster/leave":     clusterWriteScope,

	// Ceremony. GET /ceremony/status stays on the certificate gate: the
	// custodians follow the ceremony with it, as gRPC serves Status pre-auth.
	http.MethodPost + " /api/v1/ceremony/init":                 ceremonyWriteScope,
	http.MethodPost + " /api/v1/ceremony/claim-cert/begin":     ceremonyWriteScope,
	http.MethodPost + " /api/v1/ceremony/claim-cert/complete":  ceremonyWriteScope,
	http.MethodPost + " /api/v1/ceremony/claim-share/begin":    ceremonyWriteScope,
	http.MethodPost + " /api/v1/ceremony/claim-share/complete": ceremonyWriteScope,
	http.MethodPost + " /api/v1/ceremony/sign-csr":             ceremonyWriteScope,

	// PIV.
	http.MethodGet + " /api/v1/piv/devices":                 pivReadScope,
	http.MethodGet + " /api/v1/piv/devices/{device}/slots":  pivReadScope,
	http.MethodGet + " /api/v1/piv/slots/{slot}":            pivReadScope,
	http.MethodPost + " /api/v1/piv/slots/{slot}/attest":    pivReadScope,
	http.MethodPost + " /api/v1/piv/slots/{slot}/generate":  pivWriteScope,
	http.MethodPost + " /api/v1/piv/slots/{slot}/import":    pivWriteScope,
	http.MethodPost + " /api/v1/piv/slots/{slot}/sign":      pivWriteScope,
	http.MethodPost + " /api/v1/piv/devices/{device}/reset": pivWriteScope,

	// LUKS.
	http.MethodGet + " /api/v1/luks/status":             luksReadScope,
	http.MethodGet + " /api/v1/luks/info":               luksReadScope,
	http.MethodGet + " /api/v1/luks/slots":              luksReadScope,
	http.MethodPost + " /api/v1/luks/keys/test-unlock":  luksReadScope,
	http.MethodPost + " /api/v1/luks/enroll/passphrase": luksWriteScope,
	http.MethodPost + " /api/v1/luks/enroll/fido2":      luksWriteScope,
	http.MethodPost + " /api/v1/luks/enroll/tpm":        luksWriteScope,
	http.MethodPost + " /api/v1/luks/enroll/recovery":   luksWriteScope,
	http.MethodPost + " /api/v1/luks/passphrase/change": luksWriteScope,
	http.MethodPost + " /api/v1/luks/keys/remove":       luksDeleteScope,

	// FIDO2.
	http.MethodGet + " /api/v1/fido2/devices":          fido2ReadScope,
	http.MethodGet + " /api/v1/fido2/devices/wait":     fido2ReadScope,
	http.MethodGet + " /api/v1/fido2/devices/{device}": fido2ReadScope,
	http.MethodPost + " /api/v1/fido2/register":        fido2WriteScope,
	http.MethodPost + " /api/v1/fido2/authenticate":    fido2WriteScope,

	// TPM IAK and IDevID, and the LDevID issued from them.
	http.MethodGet + " /api/v1/tpm/device/attributes": idevidReadScope,
	http.MethodGet + " /api/v1/tpm/iak":               idevidReadScope,
	http.MethodGet + " /api/v1/tpm/iak/exists":        idevidReadScope,
	http.MethodGet + " /api/v1/tpm/iak/cert":          idevidReadScope,
	http.MethodPost + " /api/v1/tpm/iak/generate":     idevidWriteScope,
	http.MethodPost + " /api/v1/tpm/iak/csr":          idevidWriteScope,
	http.MethodPost + " /api/v1/tpm/iak/install":      idevidWriteScope,
	http.MethodDelete + " /api/v1/tpm/iak":            idevidDeleteScope,
	http.MethodDelete + " /api/v1/tpm/iak/cert":       idevidDeleteScope,
	http.MethodGet + " /api/v1/tpm/idevid":            idevidReadScope,
	http.MethodGet + " /api/v1/tpm/idevid/exists":     idevidReadScope,
	http.MethodGet + " /api/v1/tpm/idevid/cert":       idevidReadScope,
	http.MethodPost + " /api/v1/tpm/idevid/generate":  idevidWriteScope,
	http.MethodPost + " /api/v1/tpm/idevid/csr":       idevidWriteScope,
	http.MethodPost + " /api/v1/tpm/idevid/install":   idevidWriteScope,
	http.MethodDelete + " /api/v1/tpm/idevid":         idevidDeleteScope,
	http.MethodDelete + " /api/v1/tpm/idevid/cert":    idevidDeleteScope,
	http.MethodPost + " /api/v1/idevid/ldevid":        idevidWriteScope,

	// Config delivery, operator half. The machine half (config, nonce, sign,
	// poll) stays on the certificate gate: the machine authenticates inside
	// the request (nonce, EAB HMAC, EK binding), as gRPC serves it pre-auth.
	http.MethodGet + " /api/v1/provisioning/sessions":                      provisioningReadScope,
	http.MethodGet + " /api/v1/provisioning/sessions/{sessionID}":          provisioningReadScope,
	http.MethodPost + " /api/v1/provisioning/sessions/{sessionID}/fulfill": provisioningWriteScope,

	// Devices and device profiles.
	http.MethodPost + " /api/v1/devices/profiles":        deviceWriteScope,
	http.MethodGet + " /api/v1/devices/profiles":         deviceReadScope,
	http.MethodGet + " /api/v1/devices/profiles/{id}":    deviceReadScope,
	http.MethodPut + " /api/v1/devices/profiles/{id}":    deviceWriteScope,
	http.MethodDelete + " /api/v1/devices/profiles/{id}": deviceDeleteScope,
	http.MethodGet + " /api/v1/devices/serial/{serial}":  deviceReadScope,
	http.MethodPost + " /api/v1/devices":                 deviceWriteScope,
	http.MethodGet + " /api/v1/devices":                  deviceReadScope,
	http.MethodGet + " /api/v1/devices/{id}":             deviceReadScope,
	http.MethodPut + " /api/v1/devices/{id}":             deviceWriteScope,
	http.MethodDelete + " /api/v1/devices/{id}":          deviceDeleteScope,
	http.MethodPost + " /api/v1/devices/{id}/activate":   deviceWriteScope,
	http.MethodGet + " /api/v1/devices/{id}/state":       deviceReadScope,
	http.MethodPost + " /api/v1/devices/{id}/attest":     deviceWriteScope,

	// KMS.
	http.MethodPost + " /api/v1/kms/keys":              kmsWriteScope,
	http.MethodGet + " /api/v1/kms/keys":               kmsReadScope,
	http.MethodPost + " /api/v1/kms/keys/import":       kmsWriteScope,
	http.MethodGet + " /api/v1/kms/keys/{id}":          kmsReadScope,
	http.MethodDelete + " /api/v1/kms/keys/{id}":       kmsDeleteScope,
	http.MethodPost + " /api/v1/kms/keys/{id}/rotate":  kmsWriteScope,
	http.MethodGet + " /api/v1/kms/keys/{id}/export":   kmsReadScope,
	http.MethodGet + " /api/v1/kms/keys/{id}/versions": kmsReadScope,
	http.MethodPost + " /api/v1/kms/encrypt":           kmsWriteScope,
	http.MethodPost + " /api/v1/kms/decrypt":           kmsReadScope,
	http.MethodPost + " /api/v1/kms/batch-encrypt":     kmsWriteScope,
	http.MethodPost + " /api/v1/kms/batch-decrypt":     kmsReadScope,
	http.MethodPost + " /api/v1/kms/rewrap":            kmsWriteScope,
	http.MethodPost + " /api/v1/kms/sign":              kmsWriteScope,
	http.MethodPost + " /api/v1/kms/verify":            kmsReadScope,
	http.MethodPost + " /api/v1/kms/hash":              kmsReadScope,
	http.MethodPost + " /api/v1/kms/hmac":              kmsWriteScope,
	http.MethodPost + " /api/v1/kms/random":            kmsReadScope,
	http.MethodGet + " /api/v1/kms/status":             kmsReadScope,

	// SDN overlay.
	http.MethodGet + " /api/v1/sdn/overlay/status":          sdnReadScope,
	http.MethodGet + " /api/v1/sdn/overlay/vteps":           sdnReadScope,
	http.MethodGet + " /api/v1/sdn/overlay/vteps/{node_id}": sdnReadScope,
	http.MethodGet + " /api/v1/sdn/overlay/vnis":            sdnReadScope,
	http.MethodPost + " /api/v1/sdn/overlay/vnis":           sdnWriteScope,
	http.MethodDelete + " /api/v1/sdn/overlay/vnis/{vni}":   sdnDeleteScope,
	http.MethodGet + " /api/v1/sdn/overlay/tunnels":         sdnReadScope,
	http.MethodGet + " /api/v1/sdn/overlay/macs":            sdnReadScope,
	http.MethodDelete + " /api/v1/sdn/overlay/macs/{mac}":   sdnWriteScope,

	// Gateway deletes that the MCP catalog scopes as writes: withdrawing a
	// BGP prefix and releasing an IPAM allocation. The rest of the gateway
	// takes the sdn group's method scopes (adminDaemonGroups).
	http.MethodDelete + " /api/v1/sdn/gateway/bgp/prefixes/{prefix:.+}": sdnWriteScope,
	http.MethodDelete + " /api/v1/sdn/gateway/ipam/allocations/{ip}":    sdnWriteScope,
}

// ownTenantDaemonMethodRoutes are the operator routes, by template and
// method, whose {id} path variable names the tenant they act on. Each takes
// the tenant router's RequireOwnTenantOrSystem guard after its admin gate,
// so a tenant-A administrator cannot reach tenant B by changing the path.
// GET on the same template, and every other replayed route, is unchanged.
var ownTenantDaemonMethodRoutes = map[string]map[string]struct{}{
	"/api/v1/tenants/{id}/security/mfa-policy": {http.MethodPut: {}},
}

// certificateOnlyDaemonMethodRoutes lists, keyed "METHOD template", the
// replayed daemon routes the verified client certificate alone admits.
var certificateOnlyDaemonMethodRoutes = map[string]struct{}{
	// The CA's public material; the webservice twins are public
	// (pkg/webservice/v1/rest/ca/router.go).
	http.MethodGet + " /api/v1/ca/info":   {},
	http.MethodGet + " /api/v1/ca/crl":    {},
	http.MethodGet + " /api/v1/ca/bundle": {},

	// Config delivery, machine half: the machine authenticates inside the
	// request (nonce, EAB HMAC, EK binding), as the webservice twins
	// (pkg/webservice/v1/router/device.go) and gRPC serve it pre-auth.
	http.MethodGet + " /api/v1/provisioning/config/nonce":              {},
	http.MethodGet + " /api/v1/provisioning/sessions/{sessionID}/poll": {},
	http.MethodPost + " /api/v1/provisioning/config":                   {},
	http.MethodPost + " /api/v1/provisioning/sign":                     {},

	// Read before a session exists, with no webservice twin. The custodians
	// follow the ceremony with its status before any of them holds a
	// session, as gRPC serves Status pre-auth.
	http.MethodGet + " /api/v1/ceremony/status": {},
	// The login flow reads the tenant's MFA policy to learn which factors to
	// ask for, before the session it issues exists.
	http.MethodGet + " /api/v1/tenants/{id}/security/mfa-policy": {},
	// Enrolment and login name the authenticator from its AAGUID before the
	// session exists.
	http.MethodGet + " /api/v1/auth/factors/aaguid-lookup": {},
	// A client probes whether the daemon accepts its certificate before it
	// logs in; the probe answers with no body.
	http.MethodHead + " /api/v1/auth/mtls/probe": {},
}

// The scopes of the admin daemon groups, as the MCP catalog names them for
// the same operations (pkg/api/mcp/authz.go).
const (
	proxyReadScope   = "proxy:read"
	proxyWriteScope  = "proxy:write"
	proxyDeleteScope = "proxy:delete"
	vtpmReadScope    = "vtpm:read"
	vtpmWriteScope   = "vtpm:write"
	vtpmDeleteScope  = "vtpm:delete"
)

// adminDaemonGroups maps each admin daemon group, by its first path segment
// under /api/v1, to the scope each method takes on top of the admin role:
// <group>:read for GET and HEAD, <group>:write for POST, PUT and PATCH,
// <group>:delete for DELETE. "sdn" covers the gateway (/api/v1/sdn/gateway),
// which no webservice route shadows: the webservice gateway is /gateway.
// A method the group does not name is unclassified, and denied.
var adminDaemonGroups = map[string]map[string]string{
	"proxy": groupMethodScopes(proxyReadScope, proxyWriteScope, proxyDeleteScope),
	"sdn":   groupMethodScopes(sdnReadScope, sdnWriteScope, sdnDeleteScope),
	"vtpm":  groupMethodScopes(vtpmReadScope, vtpmWriteScope, vtpmDeleteScope),
}

// groupMethodScopes maps each HTTP method to the read, write or delete scope
// of an admin daemon group.
func groupMethodScopes(read, write, del string) map[string]string {
	return map[string]string{
		http.MethodGet:    read,
		http.MethodHead:   read,
		http.MethodPost:   write,
		http.MethodPut:    write,
		http.MethodPatch:  write,
		http.MethodDelete: del,
	}
}

// daemonScopedGroups lists the daemon groups whose handlers authorize every
// request themselves; the webservice requires an authenticated session and
// the daemon's own check decides:
//
//	ntp                                          pkg/api/rest/ntp_handlers.go:83-85
//	vpn                                          pkg/api/rest/vpn_handlers.go:108-115
//	cache, scheduler, messaging, object-storage  pkg/api/rest/app_service_handlers.go:380
//	compute                                      pkg/api/rest/compute_handlers.go:89
//	tpm (outside the IAK and IDevID entries)     pkg/api/rest/tpm_handlers.go:98
//	tenants                                      pkg/api/rest/tenant_handlers.go:449-481
var daemonScopedGroups = map[string]struct{}{
	"ntp":            {},
	"vpn":            {},
	"cache":          {},
	"scheduler":      {},
	"messaging":      {},
	"object-storage": {},
	"compute":        {},
	"tpm":            {},
	"tenants":        {},
}

// daemonRouteMethods are the methods a replayed route without a method
// restriction is classified for; any other method on it is denied.
var daemonRouteMethods = []string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodPatch,
	http.MethodDelete,
}

// daemonRouteKind is the gate a replayed daemon route method takes on the
// webservice listener, behind the client-certificate gate.
type daemonRouteKind int

const (
	// daemonRouteUnclassified is a method no table names: it is denied.
	daemonRouteUnclassified daemonRouteKind = iota
	// daemonRouteOperator takes the admin role and the route's scope.
	daemonRouteOperator
	// daemonRouteSession takes an authenticated session, published to the
	// daemon handler as its caller.
	daemonRouteSession
	// daemonRouteCertificate takes the client certificate alone.
	daemonRouteCertificate
)

// daemonRouteAccess is the classification of one replayed daemon route
// method: its gate and, for an operator route, its scope (empty for the
// admin role alone).
type daemonRouteAccess struct {
	kind  daemonRouteKind
	scope string
}

// DaemonRESTRoutes is the daemon's REST route table: the route groups only
// the daemon serves (health, version, services, protocols, BMC, ceremony,
// PIV, LUKS, FIDO2 and cluster). When a webservices: section replaces the
// daemon REST listener, platformd mounts them on this listener instead
// (docs/daemon/architecture.md). *daemon.Daemon implements it.
type DaemonRESTRoutes interface {
	// MountRESTRoutes registers the daemon-owned groups on api, a router
	// rooted at /api/v1.
	MountRESTRoutes(api *mux.Router) error
	// ClientCAs is the pool the daemon's own listeners verify client
	// certificates against: the platform anchor. Nil when the daemon has
	// no provisioned TLS identity.
	ClientCAs() *x509.CertPool
}

// ErrDaemonRouteClientCertRequired is the 401 a daemon-owned route answers
// a request that presented no verified client certificate.
type ErrDaemonRouteClientCertRequired struct{}

func (ErrDaemonRouteClientCertRequired) Error() string {
	return "daemon route requires a verified client certificate"
}

// ErrDaemonRouteClientCertUntrusted is the 403 a daemon-owned route answers
// a client certificate the webservice handshake verified but that does not
// chain to the daemon's own client roots — for example one issued by an
// attestation caller-admission anchor.
type ErrDaemonRouteClientCertUntrusted struct {
	Cause error
}

func (e ErrDaemonRouteClientCertUntrusted) Error() string {
	return "daemon route refuses a client certificate outside the daemon's client roots: " + e.Cause.Error()
}

func (e ErrDaemonRouteClientCertUntrusted) Unwrap() error { return e.Cause }

// ErrDaemonRouteNoClientRoots is returned by MountDaemonRESTRoutes when the
// daemon has no client roots: no caller could be admitted, so the routes
// are not mounted at all.
type ErrDaemonRouteNoClientRoots struct{}

func (ErrDaemonRouteNoClientRoots) Error() string {
	return "daemon routes not mounted: the daemon has no client certificate roots"
}

// ErrDaemonRouteNoAuthorizer is returned by MountDaemonRESTRoutes when no
// authorizer is given: the privileged daemon routes would sit behind the
// client-certificate gate alone, so no route is mounted.
type ErrDaemonRouteNoAuthorizer struct{}

func (ErrDaemonRouteNoAuthorizer) Error() string {
	return "daemon routes not mounted: no authorizer for the privileged daemon routes"
}

// ErrDaemonRouteNoCallerAuthenticator is returned by MountDaemonRESTRoutes
// when no caller authenticator is given: the daemon handlers that decide from
// their caller's role would have no caller to decide from, so no route is
// mounted.
type ErrDaemonRouteNoCallerAuthenticator struct{}

func (ErrDaemonRouteNoCallerAuthenticator) Error() string {
	return "daemon routes not mounted: no caller authenticator for the caller-checked daemon routes"
}

// ErrDaemonRouteNoSession is returned by a caller-checked replayed daemon
// route when the authentication seam ran but published no session.
type ErrDaemonRouteNoSession struct{}

func (ErrDaemonRouteNoSession) Error() string {
	return "no authenticated session for the replayed daemon route"
}

// MountDaemonRESTRoutes mounts the daemon-owned route groups on api behind
// a client-certificate gate. On the daemon's own REST listener these
// routes are reached only over mTLS against the daemon's client roots,
// with no JWT. The webservice listener verifies a client certificate when
// one is given (tls.VerifyClientCertIfGiven) against a wider pool — it
// also trusts the attestation caller-admission anchors — so the gate
// re-verifies the chain against routes.ClientCAs() and nothing else.
//
// The platform anchor also issues users' client certificates, so the
// certificate alone does not make the caller an operator here as it does
// on the daemon listener, whose client pool admits operator certificates
// only. Every method of every replayed route is therefore classified
// (classifyDaemonRoute): the CA routes take the authorization their
// webservice twins apply, the other operator routes and the admin groups
// the admin gate and the scope their MCP and gRPC operation takes, the
// caller-checked routes and the daemon-scoped groups an authenticated
// session (caller), and the certificate-only routes nothing more. A method
// no table classifies is denied with ErrDaemonRouteUnclassified.
// ErrDaemonRouteUnclassified is the 403 a replayed daemon route answers a
// method no authorization table classifies (classifyDaemonRoute): a route
// the daemon adds is denied on the webservice listener until it is
// classified.
type ErrDaemonRouteUnclassified struct {
	Method   string
	Template string
}

func (e ErrDaemonRouteUnclassified) Error() string {
	return "replayed daemon route " + e.Method + " " + e.Template + " has no authorization classification"
}

func MountDaemonRESTRoutes(api *mux.Router, routes DaemonRESTRoutes, writer response.HttpWriter, authorize DaemonRouteAuthorizer, caller DaemonCallerAuthenticator) error {
	roots := routes.ClientCAs()
	if roots == nil {
		return ErrDaemonRouteNoClientRoots{}
	}
	if authorize == nil {
		return ErrDaemonRouteNoAuthorizer{}
	}
	if caller == nil {
		return ErrDaemonRouteNoCallerAuthenticator{}
	}
	group := api.NewRoute().Subrouter()
	group.Use(requireDaemonClientCert(writer, roots))
	if err := routes.MountRESTRoutes(group); err != nil {
		return err
	}
	return guardPrivilegedDaemonRoutes(group, writer, authorize, caller)
}

// guardPrivilegedDaemonRoutes gates every method of every replayed route by
// its classification (classifyDaemonRoute): an operator route takes
// authorize with its scope, a session route takes caller, a certificate-only
// route takes nothing more, and an unclassified method answers 403
// ErrDaemonRouteUnclassified without reaching the daemon handler. The guard
// runs after the client-certificate gate, so a gated route needs both
// credentials. It is middleware on group, so it also runs before any
// middleware the daemon mounted its own groups behind (the daemon's own
// scope guard), and a caller the webservice refuses is refused with the
// webservice's status.
func guardPrivilegedDaemonRoutes(group *mux.Router, writer response.HttpWriter, authorize DaemonRouteAuthorizer, caller DaemonCallerAuthenticator) error {
	gates := map[daemonRouteKind]func(scope string) func(http.Handler) http.Handler{
		daemonRouteOperator:    authorize,
		daemonRouteSession:     func(string) func(http.Handler) http.Handler { return caller },
		daemonRouteCertificate: func(string) func(http.Handler) http.Handler { return certificateOnly },
	}
	guarded := make(map[*mux.Route]methodGatedDaemonRoute)
	err := group.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		// A group prefix carries no handler; the routes under it are each
		// walked, and classified, on their own.
		if route.GetHandler() == nil {
			return nil
		}
		// A handler route without a path template is classified under the
		// empty template, which no table names, so it is denied.
		template, err := route.GetPathTemplate()
		if err != nil {
			template = ""
		}
		// A route without a method restriction answers every method; each
		// is classified, and any other method is denied.
		methods, err := route.GetMethods()
		if err != nil {
			methods = daemonRouteMethods
		}
		gated := methodGatedDaemonRoute{gates: make(map[string]func(http.Handler) http.Handler, len(methods)), template: template, writer: writer}
		// Methods that share a classification share one gate.
		built := make(map[daemonRouteAccess]func(http.Handler) http.Handler, len(methods))
		for _, method := range methods {
			access := classifyDaemonRoute(method, template)
			gate, ok := gates[access.kind]
			if !ok {
				continue
			}
			scoped, ok := built[access]
			if !ok {
				scoped = gate(access.scope)
				built[access] = scoped
			}
			gated.gates[method] = scoped
		}
		guarded[route] = gated
		return nil
	})
	if err != nil {
		return err
	}
	group.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A route the walk did not see was added after the guard was
			// mounted; it is unclassified, and denied.
			gated, ok := guarded[mux.CurrentRoute(r)]
			if !ok {
				writer.Error403(w, r, ErrDaemonRouteUnclassified{Method: r.Method}, nil)
				return
			}
			gated.serve(w, r, next)
		})
	})
	return nil
}

// certificateOnly is the gate of a certificate-only route: the client
// certificate gate in front of it is the whole check.
func certificateOnly(next http.Handler) http.Handler { return next }

// methodGatedDaemonRoute serves each request to next through the gate its
// method was classified to, and refuses a method that was classified to none.
type methodGatedDaemonRoute struct {
	gates    map[string]func(http.Handler) http.Handler
	template string
	writer   response.HttpWriter
}

func (m methodGatedDaemonRoute) serve(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if gate, ok := m.gates[r.Method]; ok {
		gate(next).ServeHTTP(w, r)
		return
	}
	m.writer.Error403(w, r, ErrDaemonRouteUnclassified{Method: r.Method, Template: m.template}, nil)
}

// classifyDaemonRoute returns how the webservice gates method on a replayed
// daemon route with template, checking in order: the CA template table
// (privilegedDaemonRoutes), the per-method operator table
// (privilegedDaemonMethodRoutes), the caller-checked routes, the
// certificate-only routes, the admin groups and the daemon-scoped groups.
// A method none of them names is unclassified, and denied.
func classifyDaemonRoute(method, template string) daemonRouteAccess {
	if scope, ok := privilegedDaemonRoutes[template]; ok {
		return daemonRouteAccess{kind: daemonRouteOperator, scope: scope}
	}
	key := method + " " + template
	if scope, ok := privilegedDaemonMethodRoutes[key]; ok {
		return daemonRouteAccess{kind: daemonRouteOperator, scope: scope}
	}
	if _, ok := callerCheckedDaemonMethodRoutes[key]; ok {
		return daemonRouteAccess{kind: daemonRouteSession}
	}
	if _, ok := certificateOnlyDaemonMethodRoutes[key]; ok {
		return daemonRouteAccess{kind: daemonRouteCertificate}
	}
	group := daemonRouteGroup(template)
	if scope, ok := adminDaemonGroups[group][method]; ok {
		return daemonRouteAccess{kind: daemonRouteOperator, scope: scope}
	}
	if _, ok := daemonScopedGroups[group]; ok {
		return daemonRouteAccess{kind: daemonRouteSession}
	}
	return daemonRouteAccess{kind: daemonRouteUnclassified}
}

// daemonRouteGroup returns the group a replayed daemon route belongs to: the
// first path segment under /api/v1 ("sdn" for /api/v1/sdn/gateway/mode), or
// "" for a template outside /api/v1.
func daemonRouteGroup(template string) string {
	rest, ok := strings.CutPrefix(template, "/api/v1/")
	if !ok {
		return ""
	}
	group, _, _ := strings.Cut(rest, "/")
	return group
}

// requireDaemonClientCert refuses, with 401, a request whose TLS handshake
// verified no client certificate chain, and, with 403, a verified
// certificate that does not chain to roots. VerifiedChains, not
// PeerCertificates, decides "presented": only a chain the TLS stack built
// authenticates the caller at all.
func requireDaemonClientCert(writer response.HttpWriter, roots *x509.CertPool) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
				writer.Error401(w, r, ErrDaemonRouteClientCertRequired{})
				return
			}
			if err := verifyDaemonClient(r.TLS, roots); err != nil {
				writer.Error403(w, r, err, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// verifyDaemonClient verifies the peer's leaf, with the peer's other
// certificates as intermediates, against roots for client authentication.
func verifyDaemonClient(state *tls.ConnectionState, roots *x509.CertPool) error {
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return ErrDaemonRouteClientCertUntrusted{Cause: err}
	}
	return nil
}

// daemonRoutes mounts the daemon-owned REST route groups when the registry
// carries the daemon's route table. Without one (the daemon runs its own
// REST listener, or no daemon is wired) nothing is mounted here.
func (v1Router *Router) daemonRoutes() {
	routes := v1Router.restHandlerRegistry.DaemonRESTRoutes()
	if routes == nil {
		return
	}
	// The tenant-bound routes take the tenant router's own guard; when it
	// cannot be built they are denied rather than left on the admin gate.
	var ownTenant func(http.Handler) http.Handler
	if _, guard, err := v1Router.authorization(); err != nil {
		ownTenant = v1Router.denyAll(err)
	} else {
		ownTenant = guard.RequireOwnTenantOrSystem(
			v1Router.restHandlerRegistry.TenantID(),
			func(r *http.Request) string { return mux.Vars(r)["id"] })
	}
	routes = tenantBoundDaemonRoutes{DaemonRESTRoutes: routes, ownTenant: ownTenant}
	if err := MountDaemonRESTRoutes(v1Router.router, routes, v1Router.responseWriter, v1Router.daemonRouteAuthorizer(), v1Router.daemonCallerAuthenticator()); err != nil {
		v1Router.logger.Error(err, "Daemon REST routes not mounted")
	}
}

// tenantBoundDaemonRoutes mounts the daemon's routes and puts ownTenant on
// the handler of each ownTenantDaemonMethodRoutes route. A route handler
// runs inside the group's middleware, so the guard runs after the admin
// gate and sees the session it verified.
type tenantBoundDaemonRoutes struct {
	DaemonRESTRoutes
	ownTenant func(http.Handler) http.Handler
}

// MountRESTRoutes mounts the daemon's routes on api, then binds the
// tenant-bound ones to the caller's tenant.
func (t tenantBoundDaemonRoutes) MountRESTRoutes(api *mux.Router) error {
	if err := t.DaemonRESTRoutes.MountRESTRoutes(api); err != nil {
		return err
	}
	return api.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		next := route.GetHandler()
		if next == nil {
			return nil
		}
		template, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, ok := ownTenantDaemonMethodRoutes[template]
		if !ok {
			return nil
		}
		guarded := t.ownTenant(next)
		route.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, bound := methods[r.Method]; bound {
				guarded.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		}))
		return nil
	})
}

// daemonRouteAuthorizer is the authorization the webservice's own CA routes
// take: the admin role gate, then the route's scope when the inbound
// authentication checks scopes (the same rule as restca.CARouter).
func (v1Router *Router) daemonRouteAuthorizer() DaemonRouteAuthorizer {
	operator := v1Router.operatorChain(common.ROLE_ADMIN)
	scoped, checksScopes := v1Router.authMiddleware().(middleware.ScopeAuthorizer)
	return func(scope string) func(http.Handler) http.Handler {
		if scope == "" || !checksScopes {
			// No scope check here: the admin session this gate admits is
			// granted the route's scope, and only that one, so the
			// daemon's own scope check still runs on it.
			var granted []string
			if scope != "" {
				granted = []string{scope}
			}
			return func(next http.Handler) http.Handler {
				return operator(v1Router.publishSessionCaller(granted, next))
			}
		}
		requireScope := scoped.RequireScope(scope)
		return func(next http.Handler) http.Handler {
			return operator(requireScope(v1Router.publishSessionCaller(nil, next)))
		}
	}
}

// daemonCallerAuthenticator authenticates a caller-checked replayed daemon
// route through the webservice's own seam, with no role gate, and publishes
// the session's principal to the daemon handler, which decides by its role.
func (v1Router *Router) daemonCallerAuthenticator() DaemonCallerAuthenticator {
	authenticate, _, err := v1Router.authorization()
	if err != nil {
		v1Router.logger.Error(err, "caller-checked daemon routes will deny every request")
		return DaemonCallerAuthenticator(v1Router.denyAll(err))
	}
	return func(next http.Handler) http.Handler {
		return authenticate(v1Router.publishSessionCaller(nil, next))
	}
}

// publishSessionCaller serves next with the authenticated session published
// as the replayed daemon caller, so the daemon's scope guard decides on the
// session and never re-reads the request's credential.
//
// Scopes come only from the platform token that authenticated the session.
// A session without one holds none, so a scoped daemon handler refuses it;
// it never borrows the operator scope of the transport's client
// certificate. granted is the exception: the scopes an operator gate has
// already authorized for this route on a session that carries no token.
func (v1Router *Router) publishSessionCaller(granted []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := iammw.GetSessionFromContext(r.Context())
		if !ok {
			v1Router.responseWriter.Error401(w, r, ErrDaemonRouteNoSession{})
			return
		}
		caller := &platformtoken.AuthorizedContext{
			Subject:  session.UserID(),
			TenantID: session.TenantID(),
			Roles:    session.Roles(),
			Scopes:   granted,
		}
		if user := session.User(); user != nil {
			caller.Username = user.Username
		}
		if authCtx, scoped := iammw.AuthorizedContextFromContext(r.Context()); scoped && authCtx != nil {
			caller.Scopes = authCtx.Scopes
		}
		next.ServeHTTP(w, r.WithContext(restapi.WithCaller(r.Context(), caller)))
	})
}
