//go:build integration

package restroutes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLooksLikeRouteInventory(t *testing.T) {
	assert.True(t, looksLikeRouteInventory([]byte(`["/api/v1/devices","/v2"]`)))
	assert.False(t, looksLikeRouteInventory([]byte(`<!doctype html><html></html>`)))
	assert.False(t, looksLikeRouteInventory([]byte(`{"message":"endpoint does not exist"}`)))
	assert.False(t, looksLikeRouteInventory([]byte(`["not-a-path"]`)))
	assert.False(t, looksLikeRouteInventory(nil))
}
