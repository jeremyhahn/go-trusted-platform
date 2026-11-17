package rest

import (
	"net/http"
	"strconv"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The IAM app methods are served on the tenant-scoped app tree of the
// webservice (pkg/webservice/v1/rest/iam/router.go, registerAppRoutes):
//
//	POST   /api/v1/iam/tenants/{tenant}/apps
//	GET    /api/v1/iam/tenants/{tenant}/apps
//	GET    /api/v1/iam/tenants/{tenant}/apps/{id}
//	PUT    /api/v1/iam/tenants/{tenant}/apps/{id}
//	DELETE /api/v1/iam/tenants/{tenant}/apps/{id}
//	POST   /api/v1/iam/tenants/{tenant}/apps/{id}/rotate
//
// The request's tenant_id fills {tenant} and its client_id fills {id}.
//
// Register, Get and Update answer a bare AppResponse whose field names match
// IAMApp; it is put under IAMAppResponse.app. List and Delete answer the
// proto reply as protojson and decode generically. Rotate answers a bare
// RotateSecretResponse whose field names match RotateIAMAppSecretResponse.
func init() {
	const (
		apps = "/api/v1/iam/tenants/{tenant}/apps"
		app  = apps + "/{id}"
	)
	clientID := pathParam{placeholder: "{id}", field: "client_id"}

	templatedRouteTable[platformv1.PlatformIAMService_RegisterApp_FullMethodName] =
		tenantItemRoute(apps, http.MethodPost)
	listApps := tenantItemRoute(apps, http.MethodGet)
	listApps.queryParams = []queryParam{
		{name: "limit", field: "pagination.page_size"},
		{name: "offset", field: "pagination", encode: paginationOffset},
	}
	templatedRouteTable[platformv1.PlatformIAMService_ListApps_FullMethodName] = listApps
	templatedRouteTable[platformv1.PlatformIAMService_GetApp_FullMethodName] =
		tenantItemRoute(app, http.MethodGet, clientID)
	templatedRouteTable[platformv1.PlatformIAMService_UpdateApp_FullMethodName] =
		tenantItemRoute(app, http.MethodPut, clientID)
	templatedRouteTable[platformv1.PlatformIAMService_DeleteApp_FullMethodName] =
		tenantItemRoute(app, http.MethodDelete, clientID)
	templatedRouteTable[platformv1.PlatformIAMService_RotateAppSecret_FullMethodName] =
		tenantItemRoute(app+"/rotate", http.MethodPost, clientID)

	decodeApp := iamResourceDecoder(func() proto.Message { return &platformv1.IAMApp{} })
	for _, method := range []string{
		platformv1.PlatformIAMService_RegisterApp_FullMethodName,
		platformv1.PlatformIAMService_GetApp_FullMethodName,
		platformv1.PlatformIAMService_UpdateApp_FullMethodName,
	} {
		restResponseDecoders[method] = resourceReplyDecoder(method, "app", decodeApp)
	}

	restResponseDecoders[platformv1.PlatformIAMService_RotateAppSecret_FullMethodName] =
		wireDecoder(platformv1.PlatformIAMService_RotateAppSecret_FullMethodName, decodeIAMRotateAppSecret)
}

// decodeIAMRotateAppSecret reads the bare rotate reply into its proto reply.
func decodeIAMRotateAppSecret(raw []byte) (*platformv1.RotateIAMAppSecretResponse, error) {
	out := &platformv1.RotateIAMAppSecretResponse{}
	if err := reportJSON.Unmarshal(raw, out); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return out, nil
}

// paginationOffset renders a 1-based PaginationRequest page as the
// zero-based row offset the IAM handlers read (getPaginationParams):
// (page-1)*page_size. The first page, or no page size, sends no offset.
func paginationOffset(v protoreflect.Value) string {
	m := v.Message()
	fields := m.Descriptor().Fields()
	page := paginationInt(m.Get(fields.ByName("page")))
	size := paginationInt(m.Get(fields.ByName("page_size")))
	if page <= 1 || size <= 0 {
		return ""
	}
	return strconv.FormatInt((page-1)*size, 10)
}
