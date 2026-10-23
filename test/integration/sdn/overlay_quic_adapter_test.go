//go:build integration

package sdn

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestQUICGatewayModeMask(t *testing.T) {
	t.Run("maps known names to wire bits", func(t *testing.T) {
		mask := quicGatewayModeMask([]string{"overlay", "transit"})
		assert.Equal(t, quicwire.GatewayModeOverlay|quicwire.GatewayModeTransit, mask)
	})

	t.Run("unknown names add no bit", func(t *testing.T) {
		assert.Zero(t, quicGatewayModeMask([]string{"invalid-mode-xyz"}))
		assert.Zero(t, quicGatewayModeMask(nil))
	})
}

func TestQUICGatewayModeNames(t *testing.T) {
	t.Run("names every set bit in bit order", func(t *testing.T) {
		names := quicGatewayModeNames(quicwire.GatewayModeTransit | quicwire.GatewayModeOverlay)
		assert.Equal(t, []string{"overlay", "transit"}, names)
	})

	t.Run("empty and unknown bits name nothing", func(t *testing.T) {
		assert.Empty(t, quicGatewayModeNames(0))
		assert.Empty(t, quicGatewayModeNames(1<<31))
	})
}
