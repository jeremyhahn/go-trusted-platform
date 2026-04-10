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
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
)

func TestHandlerRegistry_TPM_ReturnsNil(t *testing.T) {
	registry := &HandlerRegistry{
		params: RegistryParams{},
	}
	assert.Nil(t, registry.TPM())
}

func TestHandlerRegistry_VTPMService_ReturnsNil(t *testing.T) {
	registry := &HandlerRegistry{
		params: RegistryParams{},
	}
	assert.Nil(t, registry.VTPMService())
}

func TestHandlerRegistry_ResponseWriter_ReturnsWriter(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &HandlerRegistry{
		params: RegistryParams{
			HTTPWriter: respWriter,
		},
	}
	assert.Equal(t, respWriter, registry.ResponseWriter())
}

func TestHandlerRegistry_SDNService_ReturnsNil(t *testing.T) {
	registry := &HandlerRegistry{
		params: RegistryParams{},
	}
	assert.Nil(t, registry.SDNService())
}

func TestHandlerRegistry_KMSClients_ReturnsNil(t *testing.T) {
	registry := &HandlerRegistry{
		params: RegistryParams{},
	}
	key, crypto, dek, secrets := registry.KMSClients()
	assert.Nil(t, key)
	assert.Nil(t, crypto)
	assert.Nil(t, dek)
	assert.Nil(t, secrets)
}

func TestHandlerRegistry_IAMClients_ReturnsNil(t *testing.T) {
	registry := &HandlerRegistry{
		params: RegistryParams{},
	}
	iam, pep := registry.IAMClients()
	assert.Nil(t, iam)
	assert.Nil(t, pep)
}

func TestHandlerRegistry_SystemRestService_WithNilCA(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &HandlerRegistry{
		params: RegistryParams{
			Logger:     logger,
			HTTPWriter: respWriter,
		},
	}
	handler := registry.SystemRestService()
	assert.NotNil(t, handler)
}

func TestHandlerRegistry_PlatformRestRouter_ReturnsRouter(t *testing.T) {
	logger := testLogger()
	respWriter := response.NewResponseWriter(logger, nil)

	registry := &HandlerRegistry{
		params: RegistryParams{
			Logger:     logger,
			HTTPWriter: respWriter,
		},
	}
	router := registry.PlatformRestRouter()
	assert.NotNil(t, router)
}

func TestHandlerRegistry_DeviceRestHandler_NilHook(t *testing.T) {
	logger := testLogger()
	registry := &HandlerRegistry{
		params: RegistryParams{
			Logger:            logger,
			SDNEnrollmentHook: nil,
		},
	}
	handler := registry.DeviceRestHandler()
	assert.Nil(t, handler)
}

func TestHandlerRegistry_ACMERestService_NilConfig(t *testing.T) {
	logger := testLogger()
	registry := &HandlerRegistry{
		params: RegistryParams{
			Logger:           logger,
			ACMEServerConfig: nil,
		},
	}
	svc := registry.ACMERestService()
	assert.Nil(t, svc)
}

func TestHandlerRegistry_ACMERestService_Disabled(t *testing.T) {
	logger := testLogger()
	registry := &HandlerRegistry{
		params: RegistryParams{
			Logger: logger,
			ACMEServerConfig: &ACMEServerConfig{
				Enabled: false,
			},
		},
	}
	svc := registry.ACMERestService()
	assert.Nil(t, svc)
}
