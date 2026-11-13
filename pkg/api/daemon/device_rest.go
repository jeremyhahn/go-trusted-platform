package daemon

import (
	"net/http"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// deviceScopeResource is the scope resource of every device operator route:
// device:read, device:write or device:delete.
const deviceScopeResource = "device"

// deviceReadOnlyPosts are the device POST routes that only evaluate a request
// body, so they need device:read, as gRPC FindMatchingProfile does.
var deviceReadOnlyPosts = []string{
	"/device/profiles/match",
}

// restScopeAuthorizer is the device router's per-route scope check over the
// daemon's REST scope guard.
type restScopeAuthorizer struct {
	guard *restapi.ScopeGuard
}

// RequireScope admits a request whose credential carries scope; the guard
// answers 401 without a credential and 403 without the scope.
func (a restScopeAuthorizer) RequireScope(scope string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return a.guard.Require(scope, next.ServeHTTP)
	}
}

// SetDeviceRouterHandlers mounts the device operator routes (devices,
// profiles, templates, lifecycle and attestation) at /api/v1 on the daemon
// REST listener. Every route authenticates through guard and needs the
// device:* scope the gRPC catalog gives its rpc. The machine-facing routes
// and the provisioning routes are not mounted here: SetConfigDeliveryHandler
// serves provisioning. Without the device, profile and template services the
// router has no handlers, so nothing is mounted. Register it before
// SetDeviceHandlers: the first matching route wins.
func (s *RESTServer) SetDeviceRouterHandlers(logger *logging.Logger, deviceSvc device.DeviceService, profileSvc device.DeviceProfileService, templateSvc device.DeviceTemplateService, attestSvc platformv1.DeviceServiceServer, guard *restapi.ScopeGuard) error {
	switch {
	case logger == nil:
		return ErrDeviceRESTUnavailable{Reason: "no logger"}
	case guard == nil:
		return ErrDeviceRESTUnavailable{Reason: "no REST scope guard"}
	case deviceSvc == nil || profileSvc == nil || templateSvc == nil:
		return nil
	}
	respWriter := response.NewResponseWriter(logger, nil)
	crudHandler := wsdevice.NewCRUDHandler(logger, respWriter, deviceSvc, profileSvc)
	templateHandler := wsdevice.NewTemplateHandler(logger, respWriter, templateSvc, profileSvc, deviceSvc)
	deviceRouter, err := router.NewDeviceRouter(nil, nil, crudHandler, templateHandler, nil,
		wsdevice.NewAttestHandler(logger, respWriter, attestSvc))
	if err != nil {
		return ErrDeviceRESTUnavailable{Reason: err.Error()}
	}
	deviceRouter.SetAttestCertHandler(wsdevice.NewAttestCertHandler(logger, respWriter, attestSvc))
	deviceRouter.SetLifecycleHandler(wsdevice.NewLifecycleHandler(logger, respWriter, attestSvc))
	deviceRouter.SetScopeAuthorizer(restScopeAuthorizer{guard: guard})
	authz := restScopeAuthorization{guard: guard, respWriter: respWriter, routeScope: deviceRouteScope}
	parent := s.router.PathPrefix(iamRESTParentPath).Subrouter()
	parent.Use(authz.authorize)
	// The device router's paths are relative to the /api/v1 parent.
	deviceRouter.RegisterRoutes(parent)
	s.logger.Info("Device router REST routes registered", "attestation", attestSvc != nil)
	return nil
}

// deviceRouteScope is the scope a device operator request needs.
func deviceRouteScope(method, route string) (string, error) {
	action, err := restScopeAction(deviceScopeResource, deviceReadOnlyPosts, method, route)
	if err != nil {
		return "", err
	}
	return deviceScopeResource + ":" + action, nil
}
