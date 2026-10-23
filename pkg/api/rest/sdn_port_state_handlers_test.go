// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-only

package rest

import (
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	portStatePath = "/api/v1/sdn/bridges/br-test/ports/eth0/state"
	portStatsPath = "/api/v1/sdn/bridges/br-test/ports/eth0/stats"
)

// portStateRouter mounts the SDN routes over a mock OVS service whose eth0
// interface reports a distinct value in every field.
func portStateRouter() (*mockSDNService, *mux.Router) {
	svc := newMockSDNService()
	svc.interfaces["eth0"] = &ovs.Interface{
		Name:       "eth0",
		OFPort:     7,
		AdminState: "up",
		LinkState:  "down",
		Speed:      1000000000,
		Duplex:     "full",
		Statistics: map[string]int64{
			"rx_packets": 1, "tx_packets": 2, "rx_bytes": 3, "tx_bytes": 4,
			"rx_dropped": 5, "tx_dropped": 6, "rx_errors": 7, "tx_errors": 8,
			"rx_frame_err": 9, "rx_over_err": 10, "rx_crc_err": 11, "collisions": 12,
		},
	}
	_, router := setupSDNTestHandler(svc)
	return svc, router
}

func nilServiceRouter() *mux.Router {
	router := mux.NewRouter()
	NewSDNHandlers(nil, slog.Default()).RegisterRoutes(router)
	return router
}

func TestGetPortState(t *testing.T) {
	t.Run("reports the interface's state", func(t *testing.T) {
		_, router := portStateRouter()

		w := serveSDN(router, http.MethodGet, portStatePath, nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp PortStateResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "br-test", resp.BridgeID)
		assert.Equal(t, "eth0", resp.PortID)
		assert.Equal(t, int32(7), resp.PortNumber)
		assert.Equal(t, "up", resp.AdminState)
		assert.Equal(t, "down", resp.OperState)
		assert.Equal(t, "down", resp.LinkState)
		assert.Equal(t, int64(1000000000), resp.Speed)
		assert.Equal(t, "full", resp.Duplex)
		assert.False(t, resp.UpdatedAt.IsZero())
	})

	t.Run("reports unknown for a state Open vSwitch has not recorded", func(t *testing.T) {
		// ovs-vswitchd leaves admin_state and link_state unset on an
		// interface whose network device it could not open.
		svc, router := portStateRouter()
		svc.interfaces["nodev"] = &ovs.Interface{Name: "nodev", OFPort: -1}

		w := serveSDN(router, http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/nodev/state", nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp PortStateResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "nodev", resp.PortID)
		assert.Equal(t, "unknown", resp.AdminState)
		assert.Equal(t, "unknown", resp.OperState)
		assert.Equal(t, "unknown", resp.LinkState)
	})

	t.Run("answers 404 for an unknown port", func(t *testing.T) {
		_, router := portStateRouter()

		w := serveSDN(router, http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/missing/state", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("answers 503 when OVS is unreachable", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.getInterfaceErr = ovs.ErrNotConnected

		w := serveSDN(router, http.MethodGet, portStatePath, nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("answers 503 without the SDN service", func(t *testing.T) {
		w := serveSDN(nilServiceRouter(), http.MethodGet, portStatePath, nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSetPortState(t *testing.T) {
	setCases := []struct {
		requested string
		want      ovs.PortState
	}{
		{"down", ovs.PortStateDown},
		{"DOWN", ovs.PortStateDown},
		{"up", ovs.PortStateUp},
	}
	for _, tc := range setCases {
		t.Run("sets admin state "+tc.requested, func(t *testing.T) {
			svc, router := portStateRouter()

			w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"`+tc.requested+`"}`))

			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			want := tc.want
			assert.Equal(t, want, svc.portStates["eth0"], "the state reaches OVS")

			var resp PortStateResponse
			decodeSDNResponse(t, w.Body, &resp)
			assert.Equal(t, string(want), resp.AdminState, "the reply reads the state back from OVS")
			assert.Equal(t, "down", resp.OperState)
		})
	}

	t.Run("rejects a malformed body without calling OVS", func(t *testing.T) {
		svc, router := portStateRouter()

		w := serveSDN(router, http.MethodPut, portStatePath, []byte("bad"))

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Empty(t, svc.portStates)
	})

	for _, state := range []string{"", "disabled"} {
		t.Run("rejects admin state "+state+" without calling OVS", func(t *testing.T) {
			svc, router := portStateRouter()

			w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"`+state+`"}`))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Contains(t, w.Body.String(), "admin_state")
			assert.Empty(t, svc.portStates)
		})
	}

	t.Run("answers 404 for an unknown port", func(t *testing.T) {
		_, router := portStateRouter()

		w := serveSDN(router, http.MethodPut, "/api/v1/sdn/bridges/br-test/ports/missing/state", []byte(`{"admin_state":"up"}`))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("answers 500 when OVS refuses the state", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.setPortStateErr = ovs.ErrTransactionFailed

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up"}`))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("reports a failed read-back", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.getInterfaceErr = errors.New("ovsdb select failed")

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up"}`))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Equal(t, ovs.PortStateUp, svc.portStates["eth0"])
	})

	t.Run("answers 503 without the SDN service", func(t *testing.T) {
		w := serveSDN(nilServiceRouter(), http.MethodPut, portStatePath, []byte(`{"admin_state":"up"}`))

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSetPortState_IngressPolicing(t *testing.T) {
	t.Run("applies the ingress rate and burst", func(t *testing.T) {
		svc, router := portStateRouter()

		w := serveSDN(router, http.MethodPut, portStatePath,
			[]byte(`{"admin_state":"up","ingress_rate":10000000,"ingress_burst":1000000}`))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, [2]uint64{10_000_000, 1_000_000}, svc.policing["eth0"])
	})

	t.Run("leaves policing alone without a rate", func(t *testing.T) {
		svc, router := portStateRouter()

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up"}`))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Empty(t, svc.policing)
		assert.Empty(t, svc.shaping)
	})

	t.Run("applies the egress rate and burst", func(t *testing.T) {
		svc, router := portStateRouter()

		w := serveSDN(router, http.MethodPut, portStatePath,
			[]byte(`{"admin_state":"up","egress_rate":20000000,"egress_burst":2000000}`))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, [2]uint64{20_000_000, 2_000_000}, svc.shaping["eth0"])
		assert.Empty(t, svc.policing, "an egress rate is not an ingress rate")
	})

	invalid := map[string]string{
		"rate not a whole kbps":       `{"admin_state":"up","ingress_rate":1500}`,
		"burst without a rate":        `{"admin_state":"up","ingress_burst":1000}`,
		"burst not a whole kb":        `{"admin_state":"up","ingress_rate":1000,"ingress_burst":1}`,
		"negative rate in JSON":       `{"admin_state":"up","ingress_rate":-1000}`,
		"egress burst without a rate": `{"admin_state":"up","egress_burst":1000}`,
	}
	for name, body := range invalid {
		t.Run("rejects "+name+" without calling OVS", func(t *testing.T) {
			svc, router := portStateRouter()

			w := serveSDN(router, http.MethodPut, portStatePath, []byte(body))

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.Empty(t, svc.portStates, "nothing is applied")
			assert.Empty(t, svc.policing)
			assert.Empty(t, svc.shaping)
		})
	}

	t.Run("answers 404 when the interface is gone", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.setPolicingErr = ovs.ErrInterfaceNotFound

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up","ingress_rate":1000}`))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("answers 500 when OVS refuses the policing", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.setPolicingErr = ovs.ErrTransactionFailed

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up","ingress_rate":1000}`))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "set_ingress_policing")
	})

	t.Run("answers 404 when the port is gone before shaping", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.setShapingErr = ovs.ErrPortNotFound

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up","egress_rate":1000}`))

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("answers 500 when OVS refuses the shaping", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.setShapingErr = ovs.ErrTransactionFailed

		w := serveSDN(router, http.MethodPut, portStatePath, []byte(`{"admin_state":"up","egress_rate":1000}`))

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.Contains(t, w.Body.String(), "set_egress_shaping")
	})
}

func TestGetPortStats(t *testing.T) {
	t.Run("reports the interface's counters", func(t *testing.T) {
		_, router := portStateRouter()

		w := serveSDN(router, http.MethodGet, portStatsPath, nil)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var resp PortStatsResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.False(t, resp.RetrievedAt.IsZero())
		assert.Equal(t, PortStatsResponse{
			BridgeID: "br-test", PortID: "eth0", PortNumber: 7,
			RxPackets: 1, TxPackets: 2, RxBytes: 3, TxBytes: 4,
			RxDropped: 5, TxDropped: 6, RxErrors: 7, TxErrors: 8,
			RxFrameErr: 9, RxOverErr: 10, RxCRCErr: 11, Collisions: 12,
			RetrievedAt: resp.RetrievedAt,
		}, resp)
	})

	t.Run("answers 404 for an unknown port", func(t *testing.T) {
		_, router := portStateRouter()

		w := serveSDN(router, http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/missing/stats", nil)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("answers 500 when OVS fails", func(t *testing.T) {
		svc, router := portStateRouter()
		svc.getInterfaceErr = errors.New("ovsdb select failed")

		w := serveSDN(router, http.MethodGet, portStatsPath, nil)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("answers 503 without the SDN service", func(t *testing.T) {
		w := serveSDN(nilServiceRouter(), http.MethodGet, portStatsPath, nil)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestErrInvalidPortState(t *testing.T) {
	assert.Equal(t, `invalid admin_state "disabled": must be 'up' or 'down'`, ErrInvalidPortState{Value: "disabled"}.Error())
	assert.Equal(t, `invalid admin_state "": must be 'up' or 'down'`, ErrInvalidPortState{}.Error())
}
