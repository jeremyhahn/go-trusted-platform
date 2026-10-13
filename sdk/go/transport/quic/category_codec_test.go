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

package quic

import (
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestCategoryCodecTables_HoldEveryServicesTranslators proves each service's
// init registered its whole translation table into the shared maps. A method
// left out would encode the pb request by name and decode its reply as zero
// values without any error.
func TestCategoryCodecTables_HoldEveryServicesTranslators(t *testing.T) {
	services := []struct {
		name     string
		encoders map[string]categoryRequestEncoder
		decoders map[string]categoryResponseDecoder
	}{
		{"gateway admitted-VTEP", gatewayAdmittedVTEPRequestEncoders, gatewayAdmittedVTEPResponseDecoders},
		{"PIV", pivRequestEncoders, pivResponseDecoders},
		{"FIDO2", fido2RequestEncoders, fido2ResponseDecoders},
		{"ceremony", ceremonyRequestEncoders, ceremonyResponseDecoders},
	}
	for _, svc := range services {
		if len(svc.encoders) == 0 || len(svc.decoders) == 0 {
			t.Errorf("%s: empty translation table (%d encoders, %d decoders)", svc.name, len(svc.encoders), len(svc.decoders))
		}
		for method := range svc.encoders {
			if _, ok := categoryRequestEncoders[method]; !ok {
				t.Errorf("%s: %s has no shared request encoder", svc.name, method)
			}
		}
		for method := range svc.decoders {
			if _, ok := categoryResponseDecoders[method]; !ok {
				t.Errorf("%s: %s has no shared response decoder", svc.name, method)
			}
		}
	}

	// The gateway reads translate in both directions; name them so an entry
	// dropped from the per-service table itself is caught too.
	for _, method := range []string{
		platformv1.GatewayService_GetGatewayAdmittedVTEP_FullMethodName,
		platformv1.GatewayService_ListGatewayAdmittedVTEPs_FullMethodName,
	} {
		if _, ok := categoryRequestEncoders[method]; !ok {
			t.Errorf("%s has no request encoder", method)
		}
		if _, ok := categoryResponseDecoders[method]; !ok {
			t.Errorf("%s has no response decoder", method)
		}
	}
}

func TestRegisterCategoryCodecs_AddsBothDirections(t *testing.T) {
	const method = "/platform.v1.TestService/Translate"
	t.Cleanup(func() {
		delete(categoryRequestEncoders, method)
		delete(categoryResponseDecoders, method)
	})

	registerCategoryCodecs(
		map[string]categoryRequestEncoder{method: requestEncoder(method,
			func(r *platformv1.GetGatewayAdmittedVTEPRequest) (interface{}, error) { return r, nil })},
		map[string]categoryResponseDecoder{method: responseDecoder(method,
			func(w *platformv1.GetGatewayAdmittedVTEPResponse, out *platformv1.GetGatewayAdmittedVTEPResponse) error {
				return nil
			})},
	)

	if _, ok := categoryRequestEncoders[method]; !ok {
		t.Error("request encoder not registered")
	}
	if _, ok := categoryResponseDecoders[method]; !ok {
		t.Error("response decoder not registered")
	}
}

type errConvertRefused struct{}

func (errConvertRefused) Error() string { return "convert refused" }

func TestRequestEncoder_ReturnsConvertError(t *testing.T) {
	const method = "/platform.v1.TestService/Translate"
	encode := requestEncoder(method, func(*platformv1.GetGatewayAdmittedVTEPRequest) (interface{}, error) {
		return nil, errConvertRefused{}
	})

	if _, err := encode(&platformv1.GetGatewayAdmittedVTEPRequest{}); !errors.As(err, new(errConvertRefused)) {
		t.Errorf("encode error = %v, want the converter's errConvertRefused", err)
	}
	var mistyped ErrInvalidArgsType
	if _, err := encode(&platformv1.ListGatewayAdmittedVTEPsRequest{}); !errors.As(err, &mistyped) || mistyped.Method != method {
		t.Errorf("mistyped encode error = %v, want ErrInvalidArgsType for %s", err, method)
	}
}
