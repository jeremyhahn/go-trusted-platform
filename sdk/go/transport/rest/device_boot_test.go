// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package rest

import (
	"net/http"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceBootRESTMapping verifies the two diskless-boot RPCs map to the
// machine-facing routes the daemon registers.
func TestDeviceBootRESTMapping(t *testing.T) {
	want := map[string]string{
		platformv1.DeviceService_BootCertificate_FullMethodName: "/api/v1/device/boot/certificate",
		platformv1.DeviceService_BootDelivery_FullMethodName:    "/api/v1/device/boot",
	}
	for method, path := range want {
		entry, ok := grpcMethodToRESTMap[method]
		if !ok {
			t.Errorf("%s is not mapped to a REST route", method)
			continue
		}
		if entry.path != path || entry.method != http.MethodPost {
			t.Errorf("%s = %s %s, want POST %s", method, entry.method, entry.path, path)
		}
	}
}
