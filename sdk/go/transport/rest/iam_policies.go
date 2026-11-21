package rest

import (
	"encoding/json"
	"net/http"
	"strconv"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// IAM policy routes (#1958). The webservice serves policies tenant-scoped
// (pkg/webservice/v1/rest/iam/router.go registerPolicyRoutes) and carries
// spec_yaml as YAML text, while the proto carries bytes, which encoding/json
// would send as base64. The request encoders write spec_yaml as a string;
// the bare PolicyResponse of Create, Get and Update is placed under the
// reply's policy; List and Delete reply with protojson.

const (
	iamPoliciesPath = "/api/v1/iam/tenants/{tenant}/policies"
	iamPolicyPath   = iamPoliciesPath + "/{id}"
)

var iamPolicyNameParam = pathParam{placeholder: "{id}", field: "policy_name"}

func init() {
	templatedRouteTable[platformv1.PlatformIAMService_CreatePolicy_FullMethodName] =
		tenantItemRoute(iamPoliciesPath, http.MethodPost)
	// The server reads paging only from ?limit= and ?offset=
	// (pkg/webservice/v1/rest/iam getPaginationParams); pages are 1-based.
	listPolicies := tenantItemRoute(iamPoliciesPath, http.MethodGet)
	listPolicies.queryParams = append(listPolicies.queryParams,
		queryParam{name: "limit", field: "pagination", encode: encodePageLimit},
		queryParam{name: "offset", field: "pagination", encode: encodePageOffset},
	)
	templatedRouteTable[platformv1.PlatformIAMService_ListPolicies_FullMethodName] = listPolicies
	templatedRouteTable[platformv1.PlatformIAMService_GetPolicy_FullMethodName] =
		tenantItemRoute(iamPolicyPath, http.MethodGet, iamPolicyNameParam)
	templatedRouteTable[platformv1.PlatformIAMService_UpdatePolicy_FullMethodName] =
		tenantItemRoute(iamPolicyPath, http.MethodPut, iamPolicyNameParam)
	templatedRouteTable[platformv1.PlatformIAMService_DeletePolicy_FullMethodName] =
		tenantItemRoute(iamPolicyPath, http.MethodDelete, iamPolicyNameParam)
	templatedRouteTable[platformv1.PlatformIAMService_ValidatePolicy_FullMethodName] =
		tenantItemRoute(iamPoliciesPath+"/validate", http.MethodPost)
	templatedRouteTable[platformv1.PlatformIAMService_TestPolicy_FullMethodName] =
		tenantItemRoute(iamPoliciesPath+"/test", http.MethodPost)

	restRequestEncoders[platformv1.PlatformIAMService_CreatePolicy_FullMethodName] = encodeCreateIAMPolicy
	restRequestEncoders[platformv1.PlatformIAMService_UpdatePolicy_FullMethodName] = encodeUpdateIAMPolicy
	restRequestEncoders[platformv1.PlatformIAMService_ValidatePolicy_FullMethodName] = encodeValidateIAMPolicy

	for _, method := range []string{
		platformv1.PlatformIAMService_CreatePolicy_FullMethodName,
		platformv1.PlatformIAMService_GetPolicy_FullMethodName,
		platformv1.PlatformIAMService_UpdatePolicy_FullMethodName,
	} {
		restResponseDecoders[method] = resourceReplyDecoder(method, "policy", decodeIAMPolicy)
	}
	restResponseDecoders[platformv1.PlatformIAMService_ListPolicies_FullMethodName] =
		wireDecoder(platformv1.PlatformIAMService_ListPolicies_FullMethodName, protoJSONReply[platformv1.ListIAMPoliciesResponse])
	restResponseDecoders[platformv1.PlatformIAMService_DeletePolicy_FullMethodName] =
		wireDecoder(platformv1.PlatformIAMService_DeletePolicy_FullMethodName, protoJSONReply[platformv1.DeleteIAMPolicyResponse])
	restResponseDecoders[platformv1.PlatformIAMService_ValidatePolicy_FullMethodName] =
		wireDecoder(platformv1.PlatformIAMService_ValidatePolicy_FullMethodName, protoJSONReply[platformv1.ValidateIAMPolicyResponse])
	restResponseDecoders[platformv1.PlatformIAMService_TestPolicy_FullMethodName] =
		wireDecoder(platformv1.PlatformIAMService_TestPolicy_FullMethodName, protoJSONReply[platformv1.TestIAMPolicyResponse])
}

// encodePageOffset renders a PaginationRequest as the server's row offset,
// (page-1)*size with the server's effective size; the first page has none.
func encodePageOffset(v protoreflect.Value) string {
	page, size, ok := effectivePage(v)
	if !ok || page <= 1 {
		return ""
	}
	return strconv.FormatUint((page-1)*size, 10)
}

// The server's IAM list paging (pkg/webservice/v1/rest/iam getPaginationParams):
// an omitted or non-positive limit means 50 rows, and a limit above 1000 is
// clamped to 1000.
const (
	iamServerDefaultPageSize uint64 = 50
	iamServerMaxPageSize     uint64 = 1000
)

// encodePageLimit renders a PaginationRequest as the server's row limit, the
// effective page size; a first page without a size sends none and takes the
// server's default.
func encodePageLimit(v protoreflect.Value) string {
	page, size, ok := effectivePage(v)
	if !ok {
		return ""
	}
	if page <= 1 && rawPageSize(v) == 0 {
		return ""
	}
	return strconv.FormatUint(size, 10)
}

// effectivePage reads page and page_size from a PaginationRequest and
// normalizes the size to the one the server applies, so that the limit and
// the offset agree with the rows the server returns.
func effectivePage(v protoreflect.Value) (page, size uint64, ok bool) {
	if !v.IsValid() {
		return 0, 0, false
	}
	msg := v.Message()
	if !msg.IsValid() {
		return 0, 0, false
	}
	page = msg.Get(msg.Descriptor().Fields().ByName("page")).Uint()
	size = rawPageSize(v)
	switch {
	case size == 0:
		size = iamServerDefaultPageSize
	case size > iamServerMaxPageSize:
		size = iamServerMaxPageSize
	}
	return page, size, true
}

func rawPageSize(v protoreflect.Value) uint64 {
	msg := v.Message()
	return msg.Get(msg.Descriptor().Fields().ByName("page_size")).Uint()
}

// iamPolicyWriteBody is the server's CreatePolicyRequest / UpdatePolicyRequest
// body: spec_yaml as text, the tenant and policy name in the path.
type iamPolicyWriteBody struct {
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	Priority    int32             `json:"priority,omitempty"`
	SpecYAML    string            `json:"spec_yaml,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

func encodeCreateIAMPolicy(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.CreateIAMPolicyRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformIAMService_CreatePolicy_FullMethodName}
	}
	return iamPolicyWriteBody{
		Name:        in.GetName(),
		Description: in.GetDescription(),
		Priority:    in.GetPriority(),
		SpecYAML:    string(in.GetSpecYaml()),
		Labels:      in.GetLabels(),
	}, nil
}

func encodeUpdateIAMPolicy(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.UpdateIAMPolicyRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformIAMService_UpdatePolicy_FullMethodName}
	}
	return iamPolicyWriteBody{
		Description: in.GetDescription(),
		Priority:    in.GetPriority(),
		SpecYAML:    string(in.GetSpecYaml()),
		Labels:      in.GetLabels(),
	}, nil
}

func encodeValidateIAMPolicy(body interface{}) (interface{}, error) {
	in, ok := body.(*platformv1.ValidateIAMPolicyRequest)
	if !ok {
		return nil, ErrUnexpectedRequestType{Method: platformv1.PlatformIAMService_ValidatePolicy_FullMethodName}
	}
	return struct {
		SpecYAML string `json:"spec_yaml"`
	}{SpecYAML: string(in.GetSpecYaml())}, nil
}

// decodeIAMPolicy decodes a bare PolicyResponse, whose spec_yaml is YAML
// text rather than the base64 protojson expects for bytes.
func decodeIAMPolicy(raw []byte) (proto.Message, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	var spec string
	if text, ok := fields["spec_yaml"]; ok {
		if err := json.Unmarshal(text, &spec); err != nil {
			return nil, ErrUnmarshalFailed{Err: err}
		}
		delete(fields, "spec_yaml")
	}
	rest, err := json.Marshal(fields)
	if err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	policy := &platformv1.IAMPolicy{}
	if err := reportJSON.Unmarshal(rest, policy); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	if spec != "" {
		policy.SpecYaml = []byte(spec)
	}
	return policy, nil
}

// protoJSONReply decodes a reply the server writes as protojson.
func protoJSONReply[R any, P interface {
	*R
	proto.Message
}](raw []byte) (P, error) {
	out := P(new(R))
	if err := reportJSON.Unmarshal(raw, out); err != nil {
		return nil, ErrUnmarshalFailed{Err: err}
	}
	return out, nil
}
