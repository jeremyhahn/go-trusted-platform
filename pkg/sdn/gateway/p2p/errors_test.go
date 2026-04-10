//go:build platform_p2p

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

package p2p

import (
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"ErrNodeNotStarted", ErrNodeNotStarted, "p2p node not started"},
		{"ErrNodeAlreadyStarted", ErrNodeAlreadyStarted, "p2p node already started"},
		{"ErrAlreadyRunning", ErrAlreadyRunning, "node already running"},
		{"ErrNotRunning", ErrNotRunning, "node not running"},
		{"ErrConfigNil", ErrConfigNil, "configuration is nil"},
		{"ErrDHTNotReady", ErrDHTNotReady, "DHT not ready"},
		{"ErrPeerNotFound", ErrPeerNotFound, "peer not found"},
		{"ErrProvidersNotFound", ErrProvidersNotFound, "no providers found"},
		{"ErrPrivateKeyNil", ErrPrivateKeyNil, "private key is nil"},
		{"ErrLoggerNil", ErrLoggerNil, "logger is nil"},
		{"ErrMDNSNotEnabled", ErrMDNSNotEnabled, "mDNS is not enabled"},
		{"ErrShutdownInProgress", ErrShutdownInProgress, "shutdown in progress"},
		{"ErrDeviceIDRequired", ErrDeviceIDRequired, "device ID required"},
		{"ErrNodeIDRequired", ErrNodeIDRequired, "node ID required"},
		{"ErrPeerIDRequired", ErrPeerIDRequired, "peer ID required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrInvalidConfigField(t *testing.T) {
	t.Run("error message", func(t *testing.T) {
		err := &ErrInvalidConfigField{Field: "ListenAddr", Reason: "must be a valid multiaddr"}
		assert.Equal(t, `invalid configuration field "ListenAddr": must be a valid multiaddr`, err.Error())
	})
}

func TestErrNodeInitFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := &ErrNodeInitFailed{Component: "host", Cause: cause}
		assert.Equal(t, "failed to initialize host: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrNodeInitFailed{Component: "host"}
		assert.Equal(t, "failed to initialize host", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrNodeStopFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("close error")
		err := &ErrNodeStopFailed{Component: "dht", Cause: cause}
		assert.Equal(t, "failed to stop dht: close error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrNodeStopFailed{Component: "dht"}
		assert.Equal(t, "failed to stop dht", err.Error())
		assert.Nil(t, err.Unwrap())
	})
}

func TestErrBootstrapFailed(t *testing.T) {
	t.Run("with peer and cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := &ErrBootstrapFailed{Peer: "12D3KooWABC", Cause: cause}
		assert.Equal(t, "bootstrap failed for peer 12D3KooWABC: connection refused", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("with peer only", func(t *testing.T) {
		err := &ErrBootstrapFailed{Peer: "12D3KooWABC"}
		assert.Equal(t, "bootstrap failed for peer 12D3KooWABC", err.Error())
	})

	t.Run("with cause only", func(t *testing.T) {
		cause := errors.New("network error")
		err := &ErrBootstrapFailed{Cause: cause}
		assert.Equal(t, "DHT bootstrap failed: network error", err.Error())
	})

	t.Run("without peer or cause", func(t *testing.T) {
		err := &ErrBootstrapFailed{}
		assert.Equal(t, "DHT bootstrap failed", err.Error())
	})
}

func TestErrConnectionFailed(t *testing.T) {
	peerID := peer.ID("12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN")

	t.Run("with peer, addr and cause", func(t *testing.T) {
		cause := errors.New("dial timeout")
		err := &ErrConnectionFailed{PeerID: peerID, Addr: "/ip4/127.0.0.1/tcp/4001", Cause: cause}
		assert.Contains(t, err.Error(), "connection failed to peer")
		assert.Contains(t, err.Error(), "/ip4/127.0.0.1/tcp/4001")
		assert.Contains(t, err.Error(), "dial timeout")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("with peer and cause only", func(t *testing.T) {
		cause := errors.New("dial timeout")
		err := &ErrConnectionFailed{PeerID: peerID, Cause: cause}
		assert.Contains(t, err.Error(), "connection failed to peer")
		assert.Contains(t, err.Error(), "dial timeout")
	})

	t.Run("with peer and addr only", func(t *testing.T) {
		err := &ErrConnectionFailed{PeerID: peerID, Addr: "/ip4/127.0.0.1/tcp/4001"}
		assert.Contains(t, err.Error(), "connection failed to peer")
		assert.Contains(t, err.Error(), "/ip4/127.0.0.1/tcp/4001")
	})

	t.Run("with peer only", func(t *testing.T) {
		err := &ErrConnectionFailed{PeerID: peerID}
		assert.Contains(t, err.Error(), "connection failed to peer")
	})
}

func TestErrInvalidMultiaddr(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("parse error")
		err := &ErrInvalidMultiaddr{Addr: "invalid", Cause: cause}
		assert.Equal(t, `invalid multiaddr "invalid": parse error`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrInvalidMultiaddr{Addr: "invalid"}
		assert.Equal(t, `invalid multiaddr "invalid"`, err.Error())
	})
}

func TestErrMultipleFailures(t *testing.T) {
	t.Run("no errors", func(t *testing.T) {
		err := &ErrMultipleFailures{}
		assert.Equal(t, "multiple failures occurred", err.Error())
	})

	t.Run("single error", func(t *testing.T) {
		cause := errors.New("single error")
		err := &ErrMultipleFailures{Errors: []error{cause}}
		assert.Equal(t, "single error", err.Error())
	})

	t.Run("multiple errors", func(t *testing.T) {
		err1 := errors.New("error 1")
		err2 := errors.New("error 2")
		err := &ErrMultipleFailures{Errors: []error{err1, err2}}
		assert.Contains(t, err.Error(), "multiple failures")
		assert.Contains(t, err.Error(), "error 1")
		assert.Contains(t, err.Error(), "error 2")
	})
}

func TestErrDHTOperationFailed(t *testing.T) {
	t.Run("with operation, key and cause", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrDHTOperationFailed{Operation: "FindPeer", Key: "test-key", Cause: cause}
		assert.Equal(t, `DHT operation "FindPeer" failed for key test-key: timeout`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("with operation and cause", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrDHTOperationFailed{Operation: "Bootstrap", Cause: cause}
		assert.Equal(t, `DHT operation "Bootstrap" failed: timeout`, err.Error())
	})

	t.Run("with operation and key", func(t *testing.T) {
		err := &ErrDHTOperationFailed{Operation: "FindPeer", Key: "test-key"}
		assert.Equal(t, `DHT operation "FindPeer" failed for key test-key`, err.Error())
	})

	t.Run("with operation only", func(t *testing.T) {
		err := &ErrDHTOperationFailed{Operation: "Bootstrap"}
		assert.Equal(t, `DHT operation "Bootstrap" failed`, err.Error())
	})
}

func TestErrHostCreationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("port in use")
		err := &ErrHostCreationFailed{Cause: cause}
		assert.Equal(t, "failed to create libp2p host: port in use", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrHostCreationFailed{}
		assert.Equal(t, "failed to create libp2p host", err.Error())
	})
}

func TestErrDHTCreationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("invalid config")
		err := &ErrDHTCreationFailed{Cause: cause}
		assert.Equal(t, "failed to create DHT: invalid config", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrDHTCreationFailed{}
		assert.Equal(t, "failed to create DHT", err.Error())
	})
}

func TestErrMultiaddrParseFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("invalid format")
		err := &ErrMultiaddrParseFailed{Addr: "/bad/addr", Cause: cause}
		assert.Equal(t, `failed to parse multiaddr "/bad/addr": invalid format`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrMultiaddrParseFailed{Addr: "/bad/addr"}
		assert.Equal(t, `failed to parse multiaddr "/bad/addr"`, err.Error())
	})
}

func TestErrPeerInfoParseFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("missing peer ID")
		err := &ErrPeerInfoParseFailed{Addr: "/ip4/127.0.0.1/tcp/4001", Cause: cause}
		assert.Equal(t, `failed to parse peer info from "/ip4/127.0.0.1/tcp/4001": missing peer ID`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrPeerInfoParseFailed{Addr: "/ip4/127.0.0.1/tcp/4001"}
		assert.Equal(t, `failed to parse peer info from "/ip4/127.0.0.1/tcp/4001"`, err.Error())
	})
}

func TestErrTimeout(t *testing.T) {
	err := &ErrTimeout{Operation: "connect", Duration: 30 * time.Second}
	assert.Equal(t, `operation "connect" timed out after 30s`, err.Error())
}

func TestErrContextCanceled(t *testing.T) {
	err := &ErrContextCanceled{Operation: "bootstrap"}
	assert.Equal(t, `operation "bootstrap" canceled`, err.Error())
}

func TestErrMDNSSetupFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("interface not found")
		err := &ErrMDNSSetupFailed{Cause: cause}
		assert.Equal(t, "failed to setup mDNS: interface not found", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrMDNSSetupFailed{}
		assert.Equal(t, "failed to setup mDNS", err.Error())
	})
}

func TestErrIdentityCreationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("invalid key")
		err := &ErrIdentityCreationFailed{Cause: cause}
		assert.Equal(t, "failed to create identity: invalid key", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrIdentityCreationFailed{}
		assert.Equal(t, "failed to create identity", err.Error())
	})
}

func TestErrProvideOperationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("DHT error")
		err := &ErrProvideOperationFailed{Key: "content-key", Cause: cause}
		assert.Equal(t, `failed to provide key "content-key": DHT error`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrProvideOperationFailed{Key: "content-key"}
		assert.Equal(t, `failed to provide key "content-key"`, err.Error())
	})
}

func TestErrFindProvidersOperationFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("timeout")
		err := &ErrFindProvidersOperationFailed{Key: "content-key", Cause: cause}
		assert.Equal(t, `failed to find providers for key "content-key": timeout`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrFindProvidersOperationFailed{Key: "content-key"}
		assert.Equal(t, `failed to find providers for key "content-key"`, err.Error())
	})
}

func TestErrKeyConversionFailed(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := errors.New("hash error")
		err := &ErrKeyConversionFailed{Key: "test-key", Cause: cause}
		assert.Equal(t, `failed to convert key "test-key": hash error`, err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("without cause", func(t *testing.T) {
		err := &ErrKeyConversionFailed{Key: "test-key"}
		assert.Equal(t, `failed to convert key "test-key"`, err.Error())
	})
}
