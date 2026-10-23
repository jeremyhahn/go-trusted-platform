//go:build integration

package sdn

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	gwcommands "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/commands"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkdevice "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/device"
	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	gatewayOverlayAdmittedVTEP = "198.51.100.10"

	// gatewayOverlayVNI is the VNI the admission requests name.
	gatewayOverlayVNI = 10709

	// gatewayOverlayReattest bounds how long one verdict may take to reach
	// the gateway before the test records another. The platformd event
	// stream does not replay, so a verdict recorded before the gateway's
	// subscription is open never reaches it.
	gatewayOverlayReattest = 2 * time.Second
)

// TestGatewayOverlayAdmissionFollowsPlatformdVerdicts drives gatewayd's
// overlay admission with a verdict platformd's own quote verifier reaches.
// gatewayd's platformd inputs are wired exactly as the serve command wires
// them, over each transport gatewayd dials. A device with a fabric allocation
// is denied while it has no passing verdict, and a failed verdict recorded by
// platformd reaches the gateway over the event stream and withdraws the
// device's VTEP.
//
// The admit half needs a passing verdict against a signed PCR baseline, and
// platformd's verifier records only trust-on-first-use baselines; the admit
// path is covered by TestGatewayOverlayWithdrawalRemovesDecapFlows, which
// serves a signed verdict alongside platformd's allocation and device record.
func TestGatewayOverlayAdmissionFollowsPlatformdVerdicts(t *testing.T) {
	ctx, cancel := LongRunningTestContext()
	t.Cleanup(cancel)

	transports := map[string][]platform.Option{
		"Unix": {
			platform.WithOnlyProtocol(platform.ProtocolUnix),
			platform.WithUnixSocket(helpers.GetSocketPath()),
		},
		"gRPC": {
			platform.WithOnlyProtocol(platform.ProtocolGRPC),
			platform.WithGRPCAddr(helpers.GetGRPCEndpoint()),
			platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
		},
	}
	for name, opts := range transports {
		t.Run(name, func(t *testing.T) {
			client, err := platform.Connect(ctx, platform.NewOptions(opts...))
			if err != nil {
				t.Fatalf("connect to platformd over %s: %v", name, err)
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Errorf("close platformd client: %v", err)
				}
			})
			testOverlayAdmissionFollowsVerdicts(t, ctx, client)
		})
	}
}

func testOverlayAdmissionFollowsVerdicts(t *testing.T, ctx context.Context, client platform.Client) {
	deviceID, vtep := enrollFabricDevice(t, ctx, client)

	runtime := &gateway.GatewayRuntime{}
	gwcommands.WireOverlayPlatform(runtime, client)
	withdrawals := &vtepWithdrawals{watched: vtep, withdrawn: make(chan struct{}, 1)}
	admitter, err := gateway.NewVTEPAdmitter(gateway.VTEPAdmissionConfig{
		IPAM:     runtime.OverlayIPAM,
		Devices:  runtime.OverlayDevices,
		Verdicts: runtime.OverlayVerdicts,
		Revoker:  withdrawals,
		Replayer: withdrawals,
	})
	if err != nil {
		t.Fatalf("NewVTEPAdmitter: %v", err)
	}

	t.Run("UnallocatedVTEPIsDenied", func(t *testing.T) {
		err := admitter.AdmitVTEP(ctx, gatewayOverlayVNI, netip.MustParseAddr("192.0.2.254"))
		var refused gateway.ErrOverlayVTEPRegistry
		if !errors.As(err, &refused) {
			t.Fatalf("a VTEP with no fabric allocation must be refused by the registry, got %v", err)
		}
	})

	t.Run("DeviceWithoutPassingVerdictIsDenied", func(t *testing.T) {
		assertVerdictDenied(t, ctx, admitter, vtep, deviceID)
	})

	t.Run("FailedVerdictWithdrawsTheVTEP", func(t *testing.T) {
		followCtx, stopFollowing := context.WithCancel(ctx)
		followed := make(chan error, 1)
		go func() { followed <- runtime.OverlayVerdictStream.Follow(followCtx, admitter.OnDeviceVerdict) }()
		t.Cleanup(func() {
			stopFollowing()
			if err := <-followed; err != nil && !errors.Is(err, context.Canceled) && status.Code(err) != codes.Canceled {
				t.Errorf("verdict stream ended with %v", err)
			}
		})

		for {
			recordFailedVerdict(t, ctx, client, deviceID)
			retry := time.NewTimer(gatewayOverlayReattest)
			select {
			case <-withdrawals.withdrawn:
				retry.Stop()
				assertVerdictDenied(t, ctx, admitter, vtep, deviceID)
				return
			case err := <-followed:
				retry.Stop()
				t.Fatalf("the verdict stream ended before the failed verdict arrived: %v", err)
			case <-ctx.Done():
				retry.Stop()
				t.Fatalf("no failed verdict for device %d reached the gateway: %v", deviceID, ctx.Err())
			case <-retry.C:
			}
		}
	})
}

// vtepWithdrawals stands in for the overlay datapath, recording the
// withdrawal of one VTEP. Other suites' devices may be revoked on the same
// stream; their VTEPs are ignored.
type vtepWithdrawals struct {
	watched   netip.Addr
	withdrawn chan struct{}
}

func (w *vtepWithdrawals) RevokeVTEP(_ context.Context, vtep netip.Addr) error {
	if vtep != w.watched {
		return nil
	}
	select {
	case w.withdrawn <- struct{}{}:
	default:
	}
	return nil
}

// RefusedVTEPs reports nothing: the stand-in holds no routes to refuse.
func (w *vtepWithdrawals) RefusedVTEPs() []netip.Addr { return nil }

// ReplayVTEP replays nothing: the stand-in holds no routes to replay.
func (w *vtepWithdrawals) ReplayVTEP(context.Context, netip.Addr) error { return nil }

// enrollFabricDevice registers a device with no attestation certificate and
// allocates it an address in a new fabric-zone pool, returning the device ID
// and that address. Everything is removed when the test ends.
func enrollFabricDevice(t *testing.T, ctx context.Context, client platform.Client) (uint64, netip.Addr) {
	t.Helper()
	devices := sdkdevice.NewClientFromGRPC(client.Device())
	ipam := sdkgateway.NewClientFromGRPC(client.Gateway())
	suffix := strconv.FormatUint(rand.Uint64(), 36)

	device, err := devices.Create(ctx, &platformv1.Device{
		Serial:   "overlay-admission-" + suffix,
		Model:    "overlay-admission",
		Hostname: "overlay-admission-" + suffix,
	})
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	t.Cleanup(func() {
		if err := devices.Delete(context.Background(), device.GetId()); err != nil {
			t.Errorf("delete device %d: %v", device.GetId(), err)
		}
	})

	pool, err := ipam.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{
		Name: "overlay-admission-" + suffix,
		Cidr: fmt.Sprintf("198.18.%d.%d/29", rand.IntN(256), rand.IntN(32)*8),
		Zone: string(zone.ZoneFabric),
	})
	if err != nil {
		t.Fatalf("create fabric pool: %v", err)
	}
	allocation, err := ipam.AllocateIP(ctx, pool.GetId(), strconv.FormatUint(device.GetId(), 10), device.GetHostname())
	if err != nil {
		t.Fatalf("allocate fabric address: %v", err)
	}
	t.Cleanup(func() {
		if err := ipam.ReleaseIP(context.Background(), allocation.GetIp()); err != nil {
			t.Errorf("release %s: %v", allocation.GetIp(), err)
		}
		if err := ipam.DeleteIPAMPool(context.Background(), pool.GetId()); err != nil {
			t.Errorf("delete pool %s: %v", pool.GetId(), err)
		}
	})

	vtep, err := netip.ParseAddr(allocation.GetIp())
	if err != nil {
		t.Fatalf("fabric allocation address %q: %v", allocation.GetIp(), err)
	}
	return device.GetId(), vtep
}

// recordFailedVerdict submits a quote for deviceID that platformd's verifier
// evaluates and refuses: the device has no attestation certificate, so the
// verdict is a failure for absence of evidence, which must still revoke.
func recordFailedVerdict(t *testing.T, ctx context.Context, client platform.Client, deviceID uint64) {
	t.Helper()
	evidence, err := json.Marshal(struct {
		Quote     []byte         `json:"quote"`
		Signature []byte         `json:"signature"`
		Nonce     []byte         `json:"nonce"`
		PCRs      map[int][]byte `json:"pcrs"`
	}{
		Quote:     []byte("not-a-tpms-attest-structure"),
		Signature: []byte("not-a-signature"),
		Nonce:     []byte("overlay-admission-nonce"),
		PCRs:      map[int][]byte{0: make([]byte, 32)},
	})
	if err != nil {
		t.Fatalf("marshal evidence: %v", err)
	}
	resp, err := client.Device().AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId: strconv.FormatUint(deviceID, 10),
		Evidence: evidence,
	})
	if err != nil {
		t.Fatalf("attest device %d: %v", deviceID, err)
	}
	if resp.GetVerified() {
		t.Fatalf("platformd verified a quote that is not a TPM quote: %+v", resp)
	}
}

func assertVerdictDenied(t *testing.T, ctx context.Context, admitter *gateway.VTEPAdmitter, vtep netip.Addr, deviceID uint64) {
	t.Helper()
	err := admitter.AdmitVTEP(ctx, gatewayOverlayVNI, vtep)
	var refused gateway.ErrOverlayVTEPVerdict
	if !errors.As(err, &refused) {
		t.Fatalf("VTEP %s of device %d must be refused for its verdict, got %v", vtep, deviceID, err)
	}
	if refused.DeviceID != deviceID {
		t.Fatalf("refusal names device %d, want %d", refused.DeviceID, deviceID)
	}
}

// TestGatewayOverlayAdmittedVTEPMultiProtocol covers the reporting surface:
// the admitted VTEPs a gateway reports in its telemetry are listed and read
// back on every transport, and a VTEP the gateway stops reporting disappears.
// Admission itself is covered by TestGatewayOverlayAdmissionFollowsPlatformdVerdicts.
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
