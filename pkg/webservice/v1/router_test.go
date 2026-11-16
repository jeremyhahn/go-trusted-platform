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
	"io"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, io.Discard)
}

func TestNewRouter_WithNilComponents(t *testing.T) {
	logger := testLogger()
	responseWriter := response.NewResponseWriter(logger, nil)

	t.Run("creates router with nil CA", func(t *testing.T) {
		router := NewRouter(
			logger,
			nil, // CA
			nil, // caConfig
			nil, // serverKeyAttributes
			nil, // registry
			responseWriter,
		)

		require.NotNil(t, router)

		// Type assert to check internal fields
		v1Router, ok := router.(*Router)
		require.True(t, ok)
		assert.Equal(t, logger, v1Router.logger)
		assert.Nil(t, v1Router.ca)
		assert.Nil(t, v1Router.caConfig)
		assert.Nil(t, v1Router.serverKeyAttributes)
		assert.Nil(t, v1Router.restHandlerRegistry)
		assert.Equal(t, responseWriter, v1Router.responseWriter)
	})

	t.Run("creates router without registry", func(t *testing.T) {
		router := NewRouter(
			logger,
			nil,
			nil,
			nil,
			nil, // nil registry
			responseWriter,
		)

		require.NotNil(t, router)
		v1Router := router.(*Router)
		assert.Nil(t, v1Router.restHandlerRegistry)
	})
}

func TestRouterInterface(t *testing.T) {
	t.Run("implements WebServiceRouter interface", func(t *testing.T) {
		logger := testLogger()
		responseWriter := response.NewResponseWriter(logger, nil)

		router := NewRouter(
			logger,
			nil,
			nil,
			nil,
			nil,
			responseWriter,
		)

		// Verify the interface is implemented
		require.NotNil(t, router)
	})
}
