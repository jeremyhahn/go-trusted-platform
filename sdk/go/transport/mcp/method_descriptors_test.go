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

package mcp

import (
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// The generated platform services register their descriptors.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestMethodTools_NameOnlyGeneratedMethods keeps the dispatch table honest:
// every gRPC method it maps must exist in the generated service
// descriptors, or the SDK carries a mapping no client can ever call.
func TestMethodTools_NameOnlyGeneratedMethods(t *testing.T) {
	for _, m := range ungeneratedMethods(MethodTools(), protoregistry.GlobalFiles) {
		t.Errorf("the MCP dispatch table maps %s, which no generated service declares", m)
	}
}

// TestMethodTools_UngeneratedMethodIsDetected proves the check above can
// fail: an unknown method, an unknown service and a malformed name are all
// reported, and a generated method is not.
func TestMethodTools_UngeneratedMethodIsDetected(t *testing.T) {
	mapped := map[string]string{
		"/platform.v1.PlatformIAMService/CheckPermission": "iam_check_permission",
		"/platform.v1.PlatformIAMService/Authenticate":    "iam_authenticate",
		"/platform.v1.NoSuchService/Get":                  "no_such_get",
		"platform.v1.PlatformIAMService.VerifyToken":      "iam_verify_token",
	}

	got := ungeneratedMethods(mapped, protoregistry.GlobalFiles)
	want := []string{
		"/platform.v1.NoSuchService/Get",
		"/platform.v1.PlatformIAMService/Authenticate",
		"platform.v1.PlatformIAMService.VerifyToken",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ungeneratedMethods = %v, want %v", got, want)
	}
}

// ungeneratedMethods returns the mapped full method names ("/pkg.Service/Method")
// that name no method of a service in files, sorted for stable output.
func ungeneratedMethods(mapped map[string]string, files *protoregistry.Files) []string {
	var missing []string
	for method := range mapped {
		if !generatedMethod(method, files) {
			missing = append(missing, method)
		}
	}
	sort.Strings(missing)
	return missing
}

func generatedMethod(fullMethod string, files *protoregistry.Files) bool {
	service, method, ok := strings.Cut(strings.TrimPrefix(fullMethod, "/"), "/")
	if !ok || !strings.HasPrefix(fullMethod, "/") {
		return false
	}
	desc, err := files.FindDescriptorByName(protoreflect.FullName(service))
	if err != nil {
		return false
	}
	sd, ok := desc.(protoreflect.ServiceDescriptor)
	return ok && sd.Methods().ByName(protoreflect.Name(method)) != nil
}
