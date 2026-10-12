// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package rest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// deviceServerRoute is one DeviceService method's server route, written
// exactly as pkg/webservice/v1/router/device.go registers it under /api/v1,
// plus a populated request and the concrete request line it must produce.
type deviceServerRoute struct {
	// template is "METHOD /api/v1/path" with the server's placeholder regex.
	template string
	// req is a request with every path and query field populated.
	req proto.Message
	// wire is "METHOD path?query" as the server receives it for req.
	wire string
}

// deviceServerRoutes is the checked-in route list for #321. The SDK module
// cannot import the server router, so this list is compared against the SDK
// here, and pkg/webservice/v1 resolves the SDK's DeviceService claims against
// the router it builds in-process. A route change on either side fails one of
// the two.
var deviceServerRoutes = map[protoreflect.Name]deviceServerRoute{
	"CreateDevice": {
		template: "POST /api/v1/devices",
		req:      &platformv1.CreateDeviceRequest{},
		wire:     "POST /api/v1/devices",
	},
	"GetDevice": {
		template: "GET /api/v1/devices/{id:[0-9]+}",
		req:      &platformv1.GetDeviceRequest{Id: 42},
		wire:     "GET /api/v1/devices/42",
	},
	"UpdateDevice": {
		template: "PUT /api/v1/devices/{id:[0-9]+}",
		req:      &platformv1.UpdateDeviceRequest{Device: &platformv1.Device{Id: 7}},
		wire:     "PUT /api/v1/devices/7",
	},
	"DeleteDevice": {
		template: "DELETE /api/v1/devices/{id:[0-9]+}",
		req:      &platformv1.DeleteDeviceRequest{Id: 7},
		wire:     "DELETE /api/v1/devices/7",
	},
	"ListDevices": {
		template: "GET /api/v1/devices",
		req:      &platformv1.ListDevicesRequest{},
		wire:     "GET /api/v1/devices",
	},
	"FindDeviceBySerial": {
		template: "GET /api/v1/devices/serial/{serial}",
		req:      &platformv1.FindDeviceBySerialRequest{Serial: "SN-1"},
		wire:     "GET /api/v1/devices/serial/SN-1",
	},
	"CountDevices": {
		template: "GET /api/v1/devices/count",
		req:      &platformv1.CountDevicesRequest{},
		wire:     "GET /api/v1/devices/count",
	},
	"CreateProfile": {
		template: "POST /api/v1/device/profiles",
		req:      &platformv1.CreateProfileRequest{},
		wire:     "POST /api/v1/device/profiles",
	},
	"GetProfile": {
		template: "GET /api/v1/device/profiles/{id:[0-9]+}",
		req:      &platformv1.GetProfileRequest{Id: 3},
		wire:     "GET /api/v1/device/profiles/3",
	},
	"UpdateProfile": {
		template: "PUT /api/v1/device/profiles/{id:[0-9]+}",
		req:      &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{Id: 3}},
		wire:     "PUT /api/v1/device/profiles/3",
	},
	"DeleteProfile": {
		template: "DELETE /api/v1/device/profiles/{id:[0-9]+}",
		req:      &platformv1.DeleteProfileRequest{Id: 3},
		wire:     "DELETE /api/v1/device/profiles/3",
	},
	"ListProfiles": {
		template: "GET /api/v1/device/profiles",
		req:      &platformv1.ListProfilesRequest{},
		wire:     "GET /api/v1/device/profiles",
	},
	"FindProfileByMACAddress": {
		template: "GET /api/v1/device/profiles/mac/{mac}",
		req:      &platformv1.FindProfileByMACAddressRequest{MacAddress: "aa:bb:cc:dd:ee:ff"},
		wire:     "GET /api/v1/device/profiles/mac/aa:bb:cc:dd:ee:ff",
	},
	"FindProfileBySerial": {
		template: "GET /api/v1/device/profiles/serial/{serial}",
		req:      &platformv1.FindProfileBySerialRequest{Serial: "SN-1"},
		wire:     "GET /api/v1/device/profiles/serial/SN-1",
	},
	"FindMatchingProfile": {
		template: "POST /api/v1/device/profiles/match",
		req:      &platformv1.FindMatchingProfileRequest{},
		wire:     "POST /api/v1/device/profiles/match",
	},
	"CountProfiles": {
		template: "GET /api/v1/device/profiles/count",
		req:      &platformv1.CountProfilesRequest{},
		wire:     "GET /api/v1/device/profiles/count",
	},
	"ActivateDevice": {
		template: "POST /api/v1/device/activate-json",
		req:      &platformv1.ActivateDeviceRequest{},
		wire:     "POST /api/v1/device/activate-json",
	},
	"AttestDevice": {
		template: "POST /api/v1/devices/{id}/attest",
		req:      &platformv1.AttestDeviceRequest{DeviceId: "dev-1"},
		wire:     "POST /api/v1/devices/dev-1/attest",
	},
	"RecordAttestationCertificate": {
		template: "POST /api/v1/devices/{id:[0-9]+}/attest-cert/record",
		req:      &platformv1.RecordAttestationCertificateRequest{DeviceId: "9"},
		wire:     "POST /api/v1/devices/9/attest-cert/record",
	},
	"CreateProfileFromTemplate": {
		template: "POST /api/v1/device/templates/{id:[0-9]+}/create-profile",
		req:      &platformv1.CreateProfileFromTemplateRequest{TemplateId: 5},
		wire:     "POST /api/v1/device/templates/5/create-profile",
	},
	"FindConfigForDevice": {
		template: "GET /api/v1/device/profiles/find-config",
		req:      &platformv1.FindConfigForDeviceRequest{EkSerial: "EK-1", MacAddress: "aa:bb"},
		wire:     "GET /api/v1/device/profiles/find-config?ek_serial=EK-1&mac=aa%3Abb",
	},
	"AssignProfileToDevice": {
		template: "POST /api/v1/device/profiles/{id:[0-9]+}/assign",
		req:      &platformv1.AssignProfileToDeviceRequest{ProfileId: 3},
		wire:     "POST /api/v1/device/profiles/3/assign",
	},
	"UnassignProfileFromDevice": {
		template: "POST /api/v1/device/profiles/{id:[0-9]+}/unassign",
		req:      &platformv1.UnassignProfileFromDeviceRequest{ProfileId: 3},
		wire:     "POST /api/v1/device/profiles/3/unassign",
	},
}

// deviceServiceMethods returns every method of DeviceService from the
// generated descriptor, so a method added to the proto is covered here
// without anyone remembering to add it.
func deviceServiceMethods(t *testing.T) protoreflect.MethodDescriptors {
	t.Helper()
	svc := platformv1.File_device_proto.Services().ByName("DeviceService")
	require.NotNil(t, svc, "DeviceService is missing from the generated descriptor")
	require.NotZero(t, svc.Methods().Len(), "DeviceService has no methods")
	return svc.Methods()
}

// sdkClaims indexes RouteClaims by gRPC method.
func sdkClaims() map[string]RouteClaim {
	claims := map[string]RouteClaim{}
	for _, c := range RouteClaims() {
		claims[c.GRPCMethod] = c
	}
	return claims
}

// TestDeviceServiceRoutes_MatchTheServerRouter checks every DeviceService
// method in the generated descriptor: the SDK must claim a route, and the
// claimed method and template must equal the server's. A method missing from
// deviceServerRoutes fails, and so does one left to the heuristic
// /api/v1/<service>/<method> fallback, which the server never serves.
func TestDeviceServiceRoutes_MatchTheServerRouter(t *testing.T) {
	claims := sdkClaims()
	methods := deviceServiceMethods(t)

	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		grpcMethod := "/platform.v1.DeviceService/" + string(m.Name())
		t.Run(string(m.Name()), func(t *testing.T) {
			want, ok := deviceServerRoutes[m.Name()]
			require.Truef(t, ok, "%s has no row in deviceServerRoutes; add the route "+
				"pkg/webservice/v1/router/device.go serves for it", grpcMethod)

			claim, ok := claims[grpcMethod]
			require.Truef(t, ok, "%s has no SDK route claim, so it falls back to the "+
				"heuristic path, which the server does not serve", grpcMethod)
			require.Equal(t, want.template, claim.Method+" "+claim.Path)
		})
	}
	require.Len(t, deviceServerRoutes, methods.Len(),
		"deviceServerRoutes names a method DeviceService does not have")
}

// TestDeviceServiceRoutes_SendTheConcreteServerPath invokes every
// DeviceService method through the adapter and checks the request line the
// server receives: placeholders filled from the request, nothing else.
func TestDeviceServiceRoutes_SendTheConcreteServerPath(t *testing.T) {
	var got string
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Method + " " + r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	methods := deviceServiceMethods(t)
	for i := 0; i < methods.Len(); i++ {
		m := methods.Get(i)
		t.Run(string(m.Name()), func(t *testing.T) {
			want, ok := deviceServerRoutes[m.Name()]
			require.Truef(t, ok, "%s has no row in deviceServerRoutes", m.Name())

			respType, err := protoregistry.GlobalTypes.FindMessageByName(m.Output().FullName())
			require.NoError(t, err)

			got = ""
			err = a.Connection().Invoke(context.Background(),
				"/platform.v1.DeviceService/"+string(m.Name()), want.req, respType.New().Interface())
			require.NoError(t, err)
			require.Equal(t, want.wire, got)
		})
	}
}

// TestGetDevice_WithIDNeverHitsTheListEndpoint pins the #321 failure mode:
// a lookup by id must reach the item route, never the collection route that
// ListDevices uses, which would answer 200 with the wrong resource.
func TestGetDevice_WithIDNeverHitsTheListEndpoint(t *testing.T) {
	var method, path string
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	err := a.Connection().Invoke(context.Background(), "/platform.v1.DeviceService/GetDevice",
		&platformv1.GetDeviceRequest{Id: 42}, &platformv1.GetDeviceResponse{})
	require.NoError(t, err)

	list := sdkClaims()["/platform.v1.DeviceService/ListDevices"]
	require.Equal(t, http.MethodGet, method)
	require.NotEqual(t, list.Path, path, "GetDevice reached the ListDevices endpoint")
	require.Equal(t, "/api/v1/devices/42", path)
}

// TestUpdateRoutes_IdentifierLeavesTheBody checks the nested path parameter:
// the resource id travels in the path and is cleared from the body, while the
// rest of the resource is still sent.
func TestUpdateRoutes_IdentifierLeavesTheBody(t *testing.T) {
	var body map[string]map[string]any
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			// Connect's reachability probe.
			w.WriteHeader(http.StatusOK)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			err = json.Unmarshal(raw, &body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"payload":{}}`))
	})

	err := a.Connection().Invoke(context.Background(), "/platform.v1.DeviceService/UpdateDevice",
		&platformv1.UpdateDeviceRequest{Device: &platformv1.Device{Id: 7, AttestPub: "pub"}},
		&platformv1.UpdateDeviceResponse{})
	require.NoError(t, err)
	require.Contains(t, body, "device")
	require.NotContains(t, body["device"], "id")
	require.Equal(t, "pub", body["device"]["attest_pub"])
}

// TestUpdateRoutes_RejectAMissingIdentifierBeforeTheWire covers the error
// path of the nested path parameter: an absent resource or a zero id is
// InvalidArgument, and no request is sent.
func TestUpdateRoutes_RejectAMissingIdentifierBeforeTheWire(t *testing.T) {
	sent := false
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		sent = true
		w.WriteHeader(http.StatusOK)
	})

	cases := map[string]struct {
		method string
		req    proto.Message
		resp   proto.Message
	}{
		"UpdateDevice without device": {
			method: "/platform.v1.DeviceService/UpdateDevice",
			req:    &platformv1.UpdateDeviceRequest{},
			resp:   &platformv1.UpdateDeviceResponse{},
		},
		"UpdateProfile with zero id": {
			method: "/platform.v1.DeviceService/UpdateProfile",
			req:    &platformv1.UpdateProfileRequest{Profile: &platformv1.DeviceProfile{Name: "p"}},
			resp:   &platformv1.UpdateProfileResponse{},
		},
		"AttestDevice without device id": {
			method: "/platform.v1.DeviceService/AttestDevice",
			req:    &platformv1.AttestDeviceRequest{Evidence: []byte{1}},
			resp:   &platformv1.AttestDeviceResponse{},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sent = false
			err := a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.resp)
			require.Equal(t, codes.InvalidArgument, status.Code(err), "err: %v", err)
			require.False(t, sent, "a request without an identifier reached the server")
		})
	}
}

func TestFieldPathDescriptor_ResolvesTopLevelAndNestedFields(t *testing.T) {
	md := (&platformv1.UpdateDeviceRequest{}).ProtoReflect().Descriptor()

	fd, ok := fieldPathDescriptor(md, "device.id")
	require.True(t, ok)
	require.Equal(t, protoreflect.FullName("platform.v1.Device.id"), fd.FullName())

	fd, ok = fieldPathDescriptor(md, "device")
	require.True(t, ok)
	require.Equal(t, protoreflect.MessageKind, fd.Kind())
}

func TestFieldPathDescriptor_RejectsPathsThatDoNotResolve(t *testing.T) {
	cases := map[string]struct {
		md   protoreflect.MessageDescriptor
		path string
	}{
		"unknown leaf":             {(&platformv1.UpdateDeviceRequest{}).ProtoReflect().Descriptor(), "device.nope"},
		"unknown segment":          {(&platformv1.UpdateDeviceRequest{}).ProtoReflect().Descriptor(), "nope.id"},
		"scalar segment":           {(&platformv1.GetDeviceRequest{}).ProtoReflect().Descriptor(), "id.value"},
		"repeated message segment": {(&platformv1.ListDevicesResponse{}).ProtoReflect().Descriptor(), "devices.id"},
		"empty path":               {(&platformv1.GetDeviceRequest{}).ProtoReflect().Descriptor(), ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, ok := fieldPathDescriptor(tc.md, tc.path)
			require.False(t, ok)
		})
	}
}

func TestFieldPathValue_ReadsNestedValues(t *testing.T) {
	rm := (&platformv1.UpdateDeviceRequest{Device: &platformv1.Device{Id: 7}}).ProtoReflect()
	v, fd, ok := fieldPathValue(rm, "device.id")
	require.True(t, ok)
	require.Equal(t, protoreflect.Name("id"), fd.Name())
	require.Equal(t, uint64(7), v.Uint())

	// An unset intermediate message reads as empty: the leaf is zero, which
	// encodePathField then rejects as a missing identifier.
	v, _, ok = fieldPathValue((&platformv1.UpdateDeviceRequest{}).ProtoReflect(), "device.id")
	require.True(t, ok)
	require.Zero(t, v.Uint())
}

func TestFieldPathValue_RejectsPathsThatDoNotResolve(t *testing.T) {
	rm := (&platformv1.UpdateDeviceRequest{Device: &platformv1.Device{Id: 7}}).ProtoReflect()
	_, fd, ok := fieldPathValue(rm, "device.nope")
	require.False(t, ok)
	require.Nil(t, fd)
}
