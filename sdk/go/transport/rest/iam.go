package rest

import (
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The IAM REST handlers answer a single user, role or tenant as the
// bare resource (pkg/webservice/v1/rest/iam/types.go UserResponse, ...),
// while the gRPC reply wraps it in a field (IAMUserResponse.user, ...). The
// JSON field names of the two match, so the resource decodes as-is; without
// these decoders protojson discarded every field and the SDK's Create, Get
// and Update returned a nil resource over REST (#401).
// iamTokensViaOIDC is why the platform serves the IAM token RPCs on no REST
// route (docs/iam/api.md §6): its gRPC and QUIC servers answer them
// Unimplemented, and REST token issuance is the authentication router's
// login and refresh endpoints.
const iamTokensViaOIDC = "IAM token issuance, verification and revocation are OIDC flows; " +
	"log in or refresh through /api/v1/login and /api/v1/login/refresh"

// restRefusedMethods are the gRPC methods the platform deliberately serves no
// REST route for, each with the reason. route() refuses them with
// ErrNoRESTRoute instead of deriving a /api/v1/platformiam/... path that
// does not exist, so the call never reaches the network.
var restRefusedMethods = map[string]string{
	platformv1.PlatformIAMService_CreateToken_FullMethodName: iamTokensViaOIDC,
	platformv1.PlatformIAMService_RevokeToken_FullMethodName: iamTokensViaOIDC,
	platformv1.PlatformIAMService_VerifyToken_FullMethodName: iamTokensViaOIDC,
}

func init() {
	iamResources := []struct {
		field   protoreflect.Name
		decode  resourceDecoder
		methods []string
	}{
		{"user", iamResourceDecoder(func() proto.Message { return &platformv1.IAMUser{} }), []string{
			platformv1.PlatformIAMService_CreateUser_FullMethodName,
			platformv1.PlatformIAMService_GetUser_FullMethodName,
			platformv1.PlatformIAMService_UpdateUser_FullMethodName,
		}},
		{"role", iamResourceDecoder(func() proto.Message { return &platformv1.IAMRole{} }), []string{
			platformv1.PlatformIAMService_CreateRole_FullMethodName,
			platformv1.PlatformIAMService_GetRole_FullMethodName,
			platformv1.PlatformIAMService_UpdateRole_FullMethodName,
		}},
		{"tenant", iamResourceDecoder(func() proto.Message { return &platformv1.IAMTenant{} }), []string{
			platformv1.PlatformIAMService_CreateTenant_FullMethodName,
			platformv1.PlatformIAMService_GetTenant_FullMethodName,
			platformv1.PlatformIAMService_UpdateTenant_FullMethodName,
		}},
	}
	for _, resource := range iamResources {
		for _, method := range resource.methods {
			restResponseDecoders[method] = resourceReplyDecoder(method, resource.field, resource.decode)
		}
	}
}

// iamResourceDecoder decodes one bare IAM resource into a new message.
func iamResourceDecoder(newResource func() proto.Message) resourceDecoder {
	return func(raw []byte) (proto.Message, error) {
		resource := newResource()
		if err := reportJSON.Unmarshal(raw, resource); err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		return resource, nil
	}
}
