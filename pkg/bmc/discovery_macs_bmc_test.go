package bmc

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"
)

var errFakeTrustStoreDown = errors.New("fake TLS provider: trust store unavailable")

// interceptMux serves overrides by exact path and everything else from
// inner, so one interface of a multi-NIC fake can be reshaped or failed.
func interceptMux(inner *http.ServeMux, overrides map[string]http.HandlerFunc) *http.ServeMux {
	outer := http.NewServeMux()
	outer.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if h, ok := overrides[r.URL.Path]; ok {
			h(w, r)
			return
		}
		inner.ServeHTTP(w, r)
	})
	return outer
}

func failWith(status int) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forced failure", status)
	}
}

func TestDiscoverMACs_EthernetInterfaceWalk(t *testing.T) {
	const ifacePath = "/redfish/v1/Systems/1/EthernetInterfaces/"
	tests := []struct {
		name      string
		macs      []string
		overrides map[string]http.HandlerFunc
		protocol  Protocol
		want      []string
		wantErr   bool
	}{
		{
			// Regression: the default was applied to a local only, and the
			// Redfish client rejected the caller's unset protocol.
			name:     "empty protocol walks Redfish",
			macs:     []string{"AA:BB:CC:00:00:01"},
			protocol: "",
			want:     []string{"AA:BB:CC:00:00:01"},
		},
		{
			name:     "same MAC in another case is reported once",
			protocol: ProtocolRedfish,
			macs:     []string{"AA:BB:CC:00:00:01", "aa:bb:cc:00:00:01", "AA:BB:CC:00:00:02"},
			want:     []string{"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"},
		},
		{
			name:      "an unreadable interface is skipped",
			protocol:  ProtocolRedfish,
			macs:      []string{"AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"},
			overrides: map[string]http.HandlerFunc{ifacePath + "1": failWith(http.StatusNotFound)},
			want:      []string{"AA:BB:CC:00:00:02"},
		},
		{
			name:      "interface collection fails",
			protocol:  ProtocolRedfish,
			macs:      []string{"AA:BB:CC:00:00:01"},
			overrides: map[string]http.HandlerFunc{"/redfish/v1/Systems/1/EthernetInterfaces": failWith(http.StatusInternalServerError)},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, ts := startTLSMux(t, interceptMux(multiNICRedfishMux(tt.macs), tt.overrides))
			defer ts.Close()

			got, err := DiscoverMACs(context.Background(), &Config{
				Address:  host,
				Port:     port,
				Protocol: tt.protocol,
				Username: "admin",
				Password: "pass",
				TLS:      tlsProviderFromTLSServer(ts),
			}, newTestLogger())
			if tt.wantErr {
				var notFound ErrMACNotFound
				if !errors.As(err, &notFound) || notFound.Address != host {
					t.Fatalf("error = %v, want ErrMACNotFound for %s", err, host)
				}
				return
			}
			if err != nil {
				t.Fatalf("DiscoverMACs: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("MACs = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDiscoverMACs_TLSProviderFailure(t *testing.T) {
	t.Run("Redfish reports the MAC as not found", func(t *testing.T) {
		_, err := DiscoverMACs(context.Background(), &Config{
			Address:  "bmc.example.test",
			Port:     443,
			Protocol: ProtocolRedfish,
			TLS:      &fakeTLSProvider{err: errFakeTrustStoreDown},
		}, newTestLogger())
		var notFound ErrMACNotFound
		if !errors.As(err, &notFound) || notFound.Address != "bmc.example.test" {
			t.Fatalf("error = %v, want ErrMACNotFound for bmc.example.test", err)
		}
	})
	t.Run("IPMI fallthrough reports discovery unsupported", func(t *testing.T) {
		stubIPMIOEMHostMACUnsupported(t)
		_, err := DiscoverMACs(context.Background(), &Config{
			Address:  "bmc.example.test",
			Port:     623,
			Protocol: ProtocolIPMI,
			TLS:      &fakeTLSProvider{err: errFakeTrustStoreDown},
		}, newTestLogger())
		var unsupported ErrMACDiscoveryUnsupported
		if !errors.As(err, &unsupported) || unsupported.Protocol != ProtocolIPMI {
			t.Fatalf("error = %v, want ErrMACDiscoveryUnsupported for IPMI", err)
		}
	})
}
