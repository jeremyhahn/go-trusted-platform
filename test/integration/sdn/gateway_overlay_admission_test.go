//go:build integration

package sdn

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"testing"
	"time"

	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const gatewayOverlayAdmittedVTEP = "198.51.100.10"

func TestGatewayOverlayAdmittedVTEPMultiProtocol(t *testing.T) {
	ctx, cancel := LongRunningTestContext()
	t.Cleanup(cancel)

	gatewayID := gatewayTelemetryPrincipal(t)
	adapters := getOverlayAdapters()

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				t.Fatalf("%s setup failed: %v", adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(); err != nil {
					t.Fatalf("%s teardown failed: %v", adapter.Name(), err)
				}
			})

			seedGatewayOverlayTelemetry(t, ctx, gatewayID, []gwstate.AdmittedVTEPState{admittedVTEPFixture()})

			list, err := adapter.GatewayAdmittedVTEPList(ctx, gatewayID)
			if err != nil {
				t.Fatalf("%s admitted VTEP list failed: %v", adapter.Name(), err)
			}
			if !gatewayVTEPListContains(list, gatewayOverlayAdmittedVTEP) {
				t.Fatalf("%s admitted VTEP list does not include %s: %#v", adapter.Name(), gatewayOverlayAdmittedVTEP, list)
			}

			got, err := adapter.GatewayAdmittedVTEPGet(ctx, gatewayID, gatewayOverlayAdmittedVTEP)
			if err != nil {
				t.Fatalf("%s admitted VTEP get failed: %v", adapter.Name(), err)
			}
			assertAdmittedVTEP(t, got.VTEP)

			seedGatewayOverlayTelemetry(t, ctx, gatewayID, nil)

			withdrawn, err := adapter.GatewayAdmittedVTEPList(ctx, gatewayID)
			if err != nil {
				t.Fatalf("%s admitted VTEP list after withdrawal failed: %v", adapter.Name(), err)
			}
			if gatewayVTEPListContains(withdrawn, gatewayOverlayAdmittedVTEP) {
				t.Fatalf("%s admitted VTEP list still includes withdrawn VTEP %s: %#v", adapter.Name(), gatewayOverlayAdmittedVTEP, withdrawn)
			}
			if _, err := adapter.GatewayAdmittedVTEPGet(ctx, gatewayID, gatewayOverlayAdmittedVTEP); err == nil {
				t.Fatalf("%s admitted VTEP get succeeded after withdrawal", adapter.Name())
			}
		})
	}
}

func seedGatewayOverlayTelemetry(t *testing.T, ctx context.Context, gatewayID string, vteps []gwstate.AdmittedVTEPState) {
	t.Helper()

	snapshot := gatewayOverlayTelemetrySnapshot(gatewayID, vteps)
	body, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal gateway overlay telemetry: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.GetRESTEndpoint()+"/api/v1/gateway/telemetry", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build gateway telemetry request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := helpers.NewHTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("post gateway overlay telemetry: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		t.Fatalf("post gateway overlay telemetry status = %d", resp.StatusCode)
	}
}

func gatewayOverlayTelemetrySnapshot(gatewayID string, vteps []gwstate.AdmittedVTEPState) *gwstate.Snapshot {
	now := time.Now().UTC()
	return &gwstate.Snapshot{
		GatewayID:  gatewayID,
		Hostname:   gatewayID,
		Mode:       "overlay",
		ReportedAt: now,
		ReceivedAt: now,
		Health: gwstate.HealthState{
			Status: "healthy",
			Components: map[string]string{
				"overlay": "healthy",
			},
		},
		Services: []gwstate.ServiceState{{
			Name:    "overlay",
			Active:  true,
			Healthy: true,
		}},
		Overlay: &gwstate.OverlayState{
			Running:         true,
			LocalVTEP:       "198.51.100.1",
			VNICount:        1,
			RemoteVTEPCount: len(vteps),
			AdmittedVTEPs:   vteps,
			NDCounters: gwstate.OverlayNDCounterState{
				Punted:       7,
				Answered:     6,
				MeterDropped: 5,
				QueueDropped: 4,
				FellThrough:  3,
			},
		},
	}
}

func admittedVTEPFixture() gwstate.AdmittedVTEPState {
	return gwstate.AdmittedVTEPState{
		VTEP:           gatewayOverlayAdmittedVTEP,
		DeviceID:       709,
		HostID:         "host-709",
		Serial:         "serial-709",
		Hostname:       "overlay-node-709",
		AllocationID:   "alloc-709",
		BaselineSource: "signed",
		ProfileID:      1709,
	}
}

func gatewayTelemetryPrincipal(t *testing.T) string {
	t.Helper()

	certPath := os.Getenv(helpers.EnvClientCert)
	if certPath == "" {
		certPath = helpers.GetCertPath()
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read integration client certificate: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatalf("decode integration client certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse integration client certificate: %v", err)
	}
	if cert.Subject.CommonName == "" {
		t.Fatalf("integration client certificate has no Common Name")
	}
	return cert.Subject.CommonName
}

func gatewayVTEPListContains(list *GatewayAdmittedVTEPListResult, vtep string) bool {
	if list == nil {
		return false
	}
	for _, item := range list.VTEPs {
		if item.VTEP == vtep {
			return true
		}
	}
	return false
}

func assertAdmittedVTEP(t *testing.T, got GatewayAdmittedVTEPInfo) {
	t.Helper()
	if got.VTEP != gatewayOverlayAdmittedVTEP {
		t.Fatalf("admitted VTEP = %q, want %q", got.VTEP, gatewayOverlayAdmittedVTEP)
	}
	if got.DeviceID != 709 {
		t.Fatalf("admitted VTEP device id = %d, want 709", got.DeviceID)
	}
	if got.BaselineSource != "signed" {
		t.Fatalf("admitted VTEP baseline source = %q, want signed", got.BaselineSource)
	}
}
