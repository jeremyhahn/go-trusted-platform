package bmc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
)

const uefiResetTarget = "/redfish/v1/Systems/1/Bios/Actions/Bios.ResetBios"

// uefiBMC is a Redfish service shaped for ClearUEFIBootEntries: a
// service root, one System with an optional Bios link, one Manager, the
// Bios resource and its ResetBios action.
type uefiBMC struct {
	rootStatus   int    // non-zero fails the service root (discovery)
	biosLink     string // System.Bios link; "" leaves it out
	biosStatus   int    // non-zero fails GET Bios
	resetTarget  string // Bios.ResetBios target; "" leaves it out
	failSystemAt int32  // fail the Nth GET of the System (1-based); 0 never
	resetStatus  []int  // status per ResetBios POST, in order; missing = 200

	systemGETs atomic.Int32
	mu         sync.Mutex
	resetBody  []string
}

func (b *uefiBMC) serve(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/redfish/v1/", func(w http.ResponseWriter, r *http.Request) {
		if b.rootStatus != 0 {
			http.Error(w, "service unavailable", b.rootStatus)
			return
		}
		writeJSON(w, redfishServiceRoot{
			Systems:  redfishRef{ODataID: "/redfish/v1/Systems"},
			Managers: redfishRef{ODataID: "/redfish/v1/Managers"},
		})
	})
	mux.HandleFunc("/redfish/v1/Systems", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Systems/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Systems/1", func(w http.ResponseWriter, _ *http.Request) {
		if n := b.systemGETs.Add(1); n == b.failSystemAt {
			http.Error(w, "system busy", http.StatusServiceUnavailable)
			return
		}
		sys := map[string]any{"Manufacturer": "Dell Inc.", "Model": "PowerEdge R640"}
		if b.biosLink != "" {
			sys["Bios"] = map[string]string{"@odata.id": b.biosLink}
		}
		writeJSON(w, sys)
	})
	mux.HandleFunc("/redfish/v1/Managers", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, redfishCollection{Members: []redfishRef{{ODataID: "/redfish/v1/Managers/1"}}})
	})
	mux.HandleFunc("/redfish/v1/Managers/1", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{})
	})
	mux.HandleFunc("/redfish/v1/Systems/1/Bios", func(w http.ResponseWriter, _ *http.Request) {
		if b.biosStatus != 0 {
			http.Error(w, "bios unavailable", b.biosStatus)
			return
		}
		bios := map[string]any{}
		if b.resetTarget != "" {
			bios["Actions"] = map[string]any{"#Bios.ResetBios": map[string]string{"target": b.resetTarget}}
		}
		writeJSON(w, bios)
	})
	mux.HandleFunc(uefiResetTarget, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.resetBody = append(b.resetBody, string(body))
		n := len(b.resetBody)
		b.mu.Unlock()
		if n <= len(b.resetStatus) && b.resetStatus[n-1] != http.StatusOK {
			w.WriteHeader(b.resetStatus[n-1])
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	return server
}

func (b *uefiBMC) resets() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.resetBody...)
}

func TestRedfishClient_ClearUEFIBootEntries_ResetBios(t *testing.T) {
	tests := []struct {
		name        string
		resetStatus []int
		wantBodies  []string
	}{
		{
			name:       "empty body accepted",
			wantBodies: []string{`{}`},
		},
		{
			name:        "retries with ResetAll when the empty body is rejected",
			resetStatus: []int{http.StatusBadRequest},
			wantBodies:  []string{`{}`, `{"ResetType":"ResetAll"}`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bmc := &uefiBMC{biosLink: "/redfish/v1/Systems/1/Bios", resetTarget: uefiResetTarget, resetStatus: tt.resetStatus}
			c := newTestRedfishClient(t, bmc.serve(t))

			if err := c.ClearUEFIBootEntries(context.Background()); err != nil {
				t.Fatalf("ClearUEFIBootEntries: %v", err)
			}
			got := bmc.resets()
			if len(got) != len(tt.wantBodies) {
				t.Fatalf("ResetBios POST bodies = %q, want %q", got, tt.wantBodies)
			}
			for i, want := range tt.wantBodies {
				if !jsonEqual(t, got[i], want) {
					t.Errorf("POST %d body = %s, want %s", i, got[i], want)
				}
			}
		})
	}
}

func TestRedfishClient_ClearUEFIBootEntries_Unsupported(t *testing.T) {
	biosLink := "/redfish/v1/Systems/1/Bios"
	tests := []struct {
		name      string
		bmc       *uefiBMC
		wantCause bool
		wantModel string
		wantPosts int
	}{
		{
			name:      "discovery fails",
			bmc:       &uefiBMC{rootStatus: http.StatusServiceUnavailable},
			wantCause: true,
		},
		{
			name:      "system read fails after discovery",
			bmc:       &uefiBMC{biosLink: biosLink, resetTarget: uefiResetTarget, failSystemAt: 2},
			wantCause: true,
			// The identity cached by discovery is reported.
			wantModel: "PowerEdge R640",
		},
		{
			name:      "system has no Bios link",
			bmc:       &uefiBMC{},
			wantModel: "PowerEdge R640",
		},
		{
			name:      "Bios read fails",
			bmc:       &uefiBMC{biosLink: biosLink, biosStatus: http.StatusInternalServerError},
			wantCause: true,
			wantModel: "PowerEdge R640",
		},
		{
			name:      "Bios has no ResetBios action",
			bmc:       &uefiBMC{biosLink: biosLink},
			wantModel: "PowerEdge R640",
		},
		{
			name: "both ResetBios bodies rejected",
			bmc: &uefiBMC{biosLink: biosLink, resetTarget: uefiResetTarget,
				resetStatus: []int{http.StatusBadRequest, http.StatusBadRequest}},
			wantCause: true,
			wantModel: "PowerEdge R640",
			wantPosts: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newTestRedfishClient(t, tt.bmc.serve(t))

			err := c.ClearUEFIBootEntries(context.Background())
			var unsupported ErrUEFIBootClearUnsupported
			if !errors.As(err, &unsupported) {
				t.Fatalf("error = %v, want ErrUEFIBootClearUnsupported", err)
			}
			if (unsupported.Cause != nil) != tt.wantCause {
				t.Errorf("cause = %v, want cause present = %v", unsupported.Cause, tt.wantCause)
			}
			if unsupported.Model != tt.wantModel {
				t.Errorf("model = %q, want %q", unsupported.Model, tt.wantModel)
			}
			if got := len(tt.bmc.resets()); got != tt.wantPosts {
				t.Errorf("ResetBios POSTs = %d, want %d", got, tt.wantPosts)
			}
		})
	}
}

// jsonEqual reports whether two JSON documents decode to the same value.
func jsonEqual(t *testing.T, a, b string) bool {
	t.Helper()
	var va, vb any
	if err := json.Unmarshal([]byte(a), &va); err != nil {
		t.Fatalf("decode %q: %v", a, err)
	}
	if err := json.Unmarshal([]byte(b), &vb); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	ja, errA := json.Marshal(va)
	jb, errB := json.Marshal(vb)
	if errA != nil || errB != nil {
		t.Fatalf("re-encode: %v %v", errA, errB)
	}
	return string(ja) == string(jb)
}
