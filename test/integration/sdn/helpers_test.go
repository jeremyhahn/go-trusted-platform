//go:build integration

package sdn

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDefaultBridgeOptions_NamesTheBridgeByItsID guards the cross-transport
// matrix: the server names a bridge from Name, and the tests read and delete
// it by BridgeID, so the two must be the same unique string.
func TestDefaultBridgeOptions_NamesTheBridgeByItsID(t *testing.T) {
	opts := DefaultBridgeOptions("mx-br")

	assert.Equal(t, opts.BridgeID, opts.Name)
	assert.Contains(t, opts.Name, "mx-br-")
}

// TestDefaultBridgeOptions_EachCallIsUnique ensures two transports running
// the same test never ask for the same bridge name.
func TestDefaultBridgeOptions_EachCallIsUnique(t *testing.T) {
	first := DefaultBridgeOptions("mx-get")
	second := DefaultBridgeOptions("mx-get")

	assert.NotEqual(t, first.Name, second.Name)
}
