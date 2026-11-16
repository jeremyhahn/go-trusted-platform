package router

import (
	"sort"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/system"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCov964NewSystemRouter_WiresMiddlewareAndRoutes(t *testing.T) {
	mockAuth := &MockAuthMiddleware{}
	mockJWT := &MockJsonWebTokenMiddleware{}

	got := NewSystemRouter(nil, nil, nil, nil, mockJWT, mockAuth, mux.NewRouter(), nil, nil)

	sysRouter, ok := got.(*SystemRouter)
	require.True(t, ok)
	assert.Same(t, mockAuth, sysRouter.authMiddleware)
	assert.Same(t, mockJWT, sysRouter.jwtMiddleware)
	assert.IsType(t, &system.Handler{}, sysRouter.systemRestHandler)

	muxRouter := mux.NewRouter()
	got.RegisterRoutes(muxRouter)

	var paths []string
	err := muxRouter.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tmpl, tmplErr := route.GetPathTemplate()
		if tmplErr != nil {
			return tmplErr
		}
		paths = append(paths, tmpl)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(paths)
	assert.Equal(t, []string{"/certificate", "/config", "/events/{page}", "/pubkey", "/status"}, paths)
	mockAuth.AssertExpectations(t)
	mockJWT.AssertExpectations(t)
}
