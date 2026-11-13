package daemon

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// restMethodActions maps an HTTP method to the action it performs on a
// daemon REST resource, matching the gRPC method permissions. A method that
// is not listed is refused, never defaulted.
var restMethodActions = map[string]string{
	http.MethodGet:    "read",
	http.MethodPost:   "write",
	http.MethodPut:    "write",
	http.MethodPatch:  "write",
	http.MethodDelete: "delete",
}

// restScopeAction returns the action a request on resource performs: read,
// write or delete. A POST whose route template ends in one of readOnlyPosts
// only evaluates its body, so it is a read, as its gRPC method is.
func restScopeAction(resource string, readOnlyPosts []string, method, route string) (string, error) {
	action, ok := restMethodActions[method]
	if !ok {
		return "", restapi.ErrRouteForbidden{Scope: resource + ":*", Reason: "method " + method + " is not served"}
	}
	if method == http.MethodPost {
		for _, suffix := range readOnlyPosts {
			if strings.HasSuffix(route, suffix) {
				return "read", nil
			}
		}
	}
	return action, nil
}

// restRouteTemplate is the path template of the matched route, or the
// request path when no route matched.
func restRouteTemplate(r *http.Request) string {
	if route := mux.CurrentRoute(r); route != nil {
		if template, err := route.GetPathTemplate(); err == nil {
			return template
		}
	}
	return r.URL.Path
}

// sdnScopeResource is the scope resource of every SDN route: sdn:read,
// sdn:write or sdn:delete. No SDN POST is read-only.
const sdnScopeResource = "sdn"

// sdnPortAuthRoute is RevokePortAuth's route. Its DELETE revokes a port's
// authorization, which the gRPC catalog gives sdn:write, not sdn:delete.
const sdnPortAuthRoute = "/api/v1/sdn/bridges/{bridge_id}/ports/{port_id}/auth"

// sdnRouteScope is the scope an SDN request needs.
func sdnRouteScope(method, route string) (string, error) {
	if method == http.MethodDelete && route == sdnPortAuthRoute {
		return sdnScopeResource + ":write", nil
	}
	action, err := restScopeAction(sdnScopeResource, nil, method, route)
	if err != nil {
		return "", err
	}
	return sdnScopeResource + ":" + action, nil
}

// catalogRouteRPCs maps each ceremony, PIV, LUKS, FIDO2, vTPM, proxy and
// cluster route on the daemon
// REST listener, as "METHOD route-template", to the gRPC method it serves. The
// route needs the scope the gRPC catalog gives that method: several of these
// POSTs read, delete or use a key, and every ceremony step has its own
// action, so the HTTP method cannot name the action.
var catalogRouteRPCs = map[string]string{
	"POST /api/v1/ceremony/init":                 "/platform.v1.CeremonyService/Init",
	"GET /api/v1/ceremony/status":                "/platform.v1.CeremonyService/Status",
	"POST /api/v1/ceremony/claim-cert/begin":     "/platform.v1.CeremonyService/ClaimCertBegin",
	"POST /api/v1/ceremony/claim-cert/complete":  "/platform.v1.CeremonyService/ClaimCertComplete",
	"POST /api/v1/ceremony/claim-share/begin":    "/platform.v1.CeremonyService/ClaimShareBegin",
	"POST /api/v1/ceremony/claim-share/complete": "/platform.v1.CeremonyService/ClaimShareComplete",
	"POST /api/v1/ceremony/sign-csr":             "/platform.v1.CeremonyService/SignCSR",

	"GET /api/v1/piv/devices":                 "/platform.v1.PIVService/ListDevices",
	"GET /api/v1/piv/devices/{device}/slots":  "/platform.v1.PIVService/ListSlots",
	"GET /api/v1/piv/slots/{slot}":            "/platform.v1.PIVService/SlotInfo",
	"POST /api/v1/piv/slots/{slot}/attest":    "/platform.v1.PIVService/Attest",
	"POST /api/v1/piv/slots/{slot}/generate":  "/platform.v1.PIVService/Generate",
	"POST /api/v1/piv/slots/{slot}/import":    "/platform.v1.PIVService/Import",
	"POST /api/v1/piv/slots/{slot}/sign":      "/platform.v1.PIVService/Sign",
	"POST /api/v1/piv/devices/{device}/reset": "/platform.v1.PIVService/Reset",

	"GET /api/v1/luks/status":             "/platform.v1.LUKSService/Status",
	"GET /api/v1/luks/slots":              "/platform.v1.LUKSService/ListSlots",
	"GET /api/v1/luks/info":               "/platform.v1.LUKSService/Info",
	"POST /api/v1/luks/keys/test-unlock":  "/platform.v1.LUKSService/TestUnlock",
	"POST /api/v1/luks/enroll/passphrase": "/platform.v1.LUKSService/EnrollPassphrase",
	"POST /api/v1/luks/enroll/fido2":      "/platform.v1.LUKSService/EnrollFIDO2",
	"POST /api/v1/luks/enroll/tpm":        "/platform.v1.LUKSService/EnrollTPM",
	"POST /api/v1/luks/enroll/recovery":   "/platform.v1.LUKSService/EnrollRecovery",
	"POST /api/v1/luks/passphrase/change": "/platform.v1.LUKSService/ChangePassphrase",
	"POST /api/v1/luks/keys/remove":       "/platform.v1.LUKSService/RemoveKey",

	"GET /api/v1/fido2/devices":          "/platform.v1.FIDO2Service/ListDevices",
	"GET /api/v1/fido2/devices/wait":     "/platform.v1.FIDO2Service/WaitDevice",
	"GET /api/v1/fido2/devices/{device}": "/platform.v1.FIDO2Service/Info",
	"POST /api/v1/fido2/register":        "/platform.v1.FIDO2Service/Register",
	"POST /api/v1/fido2/authenticate":    "/platform.v1.FIDO2Service/Authenticate",

	"POST /api/v1/vtpm/bundles":                         "/platform.v1.VTPMService/CreateBundle",
	"GET /api/v1/vtpm/bundles":                          "/platform.v1.VTPMService/ListBundles",
	"GET /api/v1/vtpm/bundles/{id}":                     "/platform.v1.VTPMService/GetBundle",
	"DELETE /api/v1/vtpm/bundles/{id}":                  "/platform.v1.VTPMService/DeleteBundle",
	"POST /api/v1/vtpm/bundles/{id}/start":              "/platform.v1.VTPMService/StartVTPM",
	"POST /api/v1/vtpm/bundles/{id}/stop":               "/platform.v1.VTPMService/StopVTPM",
	"GET /api/v1/vtpm/bundles/{id}/state":               "/platform.v1.VTPMService/IsVTPMRunning",
	"POST /api/v1/vtpm/bundles/{id}/validate":           "/platform.v1.VTPMService/ValidateBundle",
	"GET /api/v1/vtpm/bundles/{id}/path":                "/platform.v1.VTPMService/GetBundlePath",
	"GET /api/v1/vtpm/bundles/{id}/tpm-socket":          "/platform.v1.VTPMService/GetTPMSocketPath",
	"GET /api/v1/vtpm/bundles/{id}/nvram":               "/platform.v1.VTPMService/GetNVRAMPath",
	"POST /api/v1/vtpm/bundles/{id}/quote":              "/platform.v1.VTPMService/QuoteVTPM",
	"GET /api/v1/vtpm/bundles/{id}/pcr/{index}":         "/platform.v1.VTPMService/ReadVTPMPCR",
	"POST /api/v1/vtpm/bundles/{id}/pcr/{index}/extend": "/platform.v1.VTPMService/ExtendVTPMPCR",
	"POST /api/v1/vtpm/bundles/{id}/seal":               "/platform.v1.VTPMService/SealVTPM",
	"POST /api/v1/vtpm/bundles/{id}/unseal":             "/platform.v1.VTPMService/UnsealVTPM",
	"GET /api/v1/vtpm/bundles/{id}/export":              "/platform.v1.VTPMService/ExportBundle",
	"POST /api/v1/vtpm/bundles/import":                  "/platform.v1.VTPMService/ImportBundle",
	"POST /api/v1/vtpm/templates":                       "/platform.v1.VTPMService/CreateTemplate",
	"GET /api/v1/vtpm/templates":                        "/platform.v1.VTPMService/ListTemplates",
	"GET /api/v1/vtpm/templates/{id}":                   "/platform.v1.VTPMService/GetTemplate",
	"DELETE /api/v1/vtpm/templates/{id}":                "/platform.v1.VTPMService/DeleteTemplate",
	"POST /api/v1/vtpm/templates/{id}/clone":            "/platform.v1.VTPMService/CloneTemplate",

	"POST /api/v1/proxy/routes":        "/platform.v1.ProxyService/CreateRoute",
	"GET /api/v1/proxy/routes":         "/platform.v1.ProxyService/ListRoutes",
	"GET /api/v1/proxy/routes/{id}":    "/platform.v1.ProxyService/GetRoute",
	"PUT /api/v1/proxy/routes/{id}":    "/platform.v1.ProxyService/UpdateRoute",
	"DELETE /api/v1/proxy/routes/{id}": "/platform.v1.ProxyService/DeleteRoute",
	"POST /api/v1/proxy/pools":         "/platform.v1.ProxyService/CreatePool",
	"GET /api/v1/proxy/pools":          "/platform.v1.ProxyService/ListPools",
	"GET /api/v1/proxy/pools/{id}":     "/platform.v1.ProxyService/GetPool",
	"PUT /api/v1/proxy/pools/{id}":     "/platform.v1.ProxyService/UpdatePool",
	"DELETE /api/v1/proxy/pools/{id}":  "/platform.v1.ProxyService/DeletePool",
	"GET /api/v1/proxy/config":         "/platform.v1.ProxyService/GetProxyConfig",
	"GET /api/v1/proxy/status":         "/platform.v1.ProxyService/GetProxyStatus",
	"POST /api/v1/proxy/reload":        "/platform.v1.ProxyService/ReloadProxyConfig",
	"GET /api/v1/proxy/zone-matrix":    "/platform.v1.ProxyService/GetZoneMatrix",

	"GET /api/v1/cluster/status":     "/platform.v1.ClusterService/GetStatus",
	"GET /api/v1/cluster/nodes":      "/platform.v1.ClusterService/ListNodes",
	"POST /api/v1/cluster/bootstrap": "/platform.v1.ClusterService/Bootstrap",
	"POST /api/v1/cluster/join":      "/platform.v1.ClusterService/Join",
	"POST /api/v1/cluster/leave":     "/platform.v1.ClusterService/Leave",

	"GET /api/v1/sdn/overlay/status":          "/platform.v1.OverlayService/GetOverlayStatus",
	"GET /api/v1/sdn/overlay/vteps":           "/platform.v1.OverlayService/ListVTEPs",
	"GET /api/v1/sdn/overlay/vteps/{node_id}": "/platform.v1.OverlayService/GetVTEP",
	"GET /api/v1/sdn/overlay/vnis":            "/platform.v1.OverlayService/ListVNIs",
	"POST /api/v1/sdn/overlay/vnis":           "/platform.v1.OverlayService/CreateVNI",
	"DELETE /api/v1/sdn/overlay/vnis/{vni}":   "/platform.v1.OverlayService/DeleteVNI",
	"GET /api/v1/sdn/overlay/tunnels":         "/platform.v1.OverlayService/ListTunnels",
	"GET /api/v1/sdn/overlay/macs":            "/platform.v1.OverlayService/ListRemoteMACs",
	"DELETE /api/v1/sdn/overlay/macs/{mac}":   "/platform.v1.OverlayService/ForgetMAC",

	"GET /api/v1/sdn/gateway/status":                                       "/platform.v1.GatewayService/GetGatewayStatus",
	"PUT /api/v1/sdn/gateway/mode":                                         "/platform.v1.GatewayService/SetGatewayMode",
	"GET /api/v1/sdn/gateway/bgp/status":                                   "/platform.v1.GatewayService/GetBGPStatus",
	"GET /api/v1/sdn/gateway/bgp/peers":                                    "/platform.v1.GatewayService/ListBGPPeers",
	"POST /api/v1/sdn/gateway/bgp/prefixes":                                "/platform.v1.GatewayService/AnnouncePrefix",
	"GET /api/v1/sdn/gateway/bgp/prefixes":                                 "/platform.v1.GatewayService/ListAnnouncedPrefixes",
	"DELETE /api/v1/sdn/gateway/bgp/prefixes/{prefix:.+}":                  "/platform.v1.GatewayService/WithdrawPrefix",
	"POST /api/v1/sdn/gateway/ipam/pools":                                  "/platform.v1.GatewayService/CreateIPAMPool",
	"GET /api/v1/sdn/gateway/ipam/pools":                                   "/platform.v1.GatewayService/ListIPAMPools",
	"GET /api/v1/sdn/gateway/ipam/pools/{id}":                              "/platform.v1.GatewayService/GetIPAMPool",
	"PUT /api/v1/sdn/gateway/ipam/pools/{id}":                              "/platform.v1.GatewayService/UpdateIPAMPool",
	"DELETE /api/v1/sdn/gateway/ipam/pools/{id}":                           "/platform.v1.GatewayService/DeleteIPAMPool",
	"POST /api/v1/sdn/gateway/ipam/allocations":                            "/platform.v1.GatewayService/AllocateIP",
	"GET /api/v1/sdn/gateway/ipam/allocations":                             "/platform.v1.GatewayService/ListAllocations",
	"DELETE /api/v1/sdn/gateway/ipam/allocations/{ip}":                     "/platform.v1.GatewayService/ReleaseIP",
	"GET /api/v1/sdn/gateway/overlay/vteps":                                "/platform.v1.GatewayService/ListGatewayAdmittedVTEPs",
	"GET /api/v1/sdn/gateway/overlay/vteps/{vtep}":                         "/platform.v1.GatewayService/GetGatewayAdmittedVTEP",
	"POST /api/v1/sdn/gateway/lb/vips":                                     "/platform.v1.GatewayService/AddVIP",
	"GET /api/v1/sdn/gateway/lb/vips":                                      "/platform.v1.GatewayService/ListVIPs",
	"GET /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}":          "/platform.v1.GatewayService/GetVIP",
	"DELETE /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}":       "/platform.v1.GatewayService/RemoveVIP",
	"PUT /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends": "/platform.v1.GatewayService/SetVIPBackends",
	"GET /api/v1/sdn/gateway/lb/status":                                    "/platform.v1.GatewayService/GetLBStatus",
	"GET /api/v1/sdn/gateway/nat64/status":                                 "/platform.v1.GatewayService/GetNAT64Status",
	"POST /api/v1/sdn/gateway/perf/flows":                                  "/platform.v1.GatewayService/GetPerfFlows",
	"GET /api/v1/sdn/gateway/perf/datapath":                                "/platform.v1.GatewayService/GetPerfDatapath",
	"GET /api/v1/sdn/gateway/perf/conntrack":                               "/platform.v1.GatewayService/GetPerfConntrack",
}

// catalogRouteScope returns the scope the gRPC catalog gives the method a
// route serves. A route missing from catalogRouteRPCs, or a method the
// catalog gives no scope, fails closed.
func catalogRouteScope(method, route string) (string, error) {
	rpc, ok := catalogRouteRPCs[method+" "+route]
	if !ok {
		return "", ErrRESTRouteUnscoped{Method: method, Route: route, Reason: "the route has no gRPC method"}
	}
	scope := grpcapi.ScopeForMethod(rpc)
	if scope == "" {
		return "", ErrRESTRouteUnscoped{Method: method, Route: route, Reason: "the gRPC catalog gives " + rpc + " no scope"}
	}
	return scope, nil
}

// catalogGuardedAPI returns a restBasePath subrouter whose routes each run
// behind guard and need the scope catalogRouteScope gives them.
func (s *RESTServer) catalogGuardedAPI(guard *restapi.ScopeGuard) *mux.Router {
	api := s.router.PathPrefix(restBasePath).Subrouter()
	api.Use(s.catalogAuthorization(guard).authorize)
	return api
}

// catalogGuardedRoot returns a matcher-less subrouter of the root router for
// registrars that mount absolute /api/v1 paths. Its routes run behind guard
// like catalogGuardedAPI's; gorilla/mux runs its middleware only when one of
// its own routes matched, so it guards no other path.
func (s *RESTServer) catalogGuardedRoot(guard *restapi.ScopeGuard) *mux.Router {
	root := s.router.NewRoute().Subrouter()
	root.Use(s.catalogAuthorization(guard).authorize)
	return root
}

func (s *RESTServer) catalogAuthorization(guard *restapi.ScopeGuard) restScopeAuthorization {
	return restScopeAuthorization{
		guard:      guard,
		respWriter: response.NewResponseWriter(logging.NewFromSlog(s.logger), nil),
		routeScope: catalogRouteScope,
	}
}

// restScopeAuthorization authenticates a daemon REST request through the
// REST scope guard and requires the scope routeScope gives its method and
// route template.
type restScopeAuthorization struct {
	guard      *restapi.ScopeGuard
	respWriter response.HttpWriter
	routeScope func(method, route string) (string, error)
}

// authorize answers 401 for a missing or invalid credential and 403 for a
// caller without the route's scope.
func (a restScopeAuthorization) authorize(next http.Handler) http.Handler {
	return a.guard.Authenticate(func(w http.ResponseWriter, r *http.Request, caller *platformtoken.AuthorizedContext) {
		scope, err := a.routeScope(r.Method, restRouteTemplate(r))
		if err != nil {
			a.respWriter.Error403(w, r, err, nil)
			return
		}
		if err := caller.RequireScope(scope); err != nil {
			a.respWriter.Error403(w, r, restapi.ErrRouteForbidden{Scope: scope, Reason: err.Error()}, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}
