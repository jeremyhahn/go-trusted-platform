//go:build integration

package device

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// unreachableTransportIssue reports the open issue that explains why an
// adapter error is the transport failing to reach a device handler at
// all, rather than the daemon answering. It returns "" when the daemon
// did answer, which is the only case that says anything about the
// create verb.
//
// A 404 on a route the server does not serve, a TLS handshake against a
// plaintext socket, or an endpoint replying with a non-JSON body all
// mean the request never arrived. Naming the issue in the failure
// message is the point: the next reader learns in one line that the red
// cell is an adapter defect with an owner, not #525 regressing.
//
// The entries below are the state of the suite as measured since 2026-09-06,
// and neither is relaxed to a skip — this repository documents a known
// defect with a test that fails loudly, never with one that opts out.
//
//   - #531 — the REST adapter addressed a tenant-scoped route family
//     (/api/v1/tenants/{tenant}/devices) the server does not serve. #493
//     moved it to the routes the daemon registers (POST /api/v1/devices);
//     a 404 now means the adapter and the router drifted apart again.
//   - #532 — the Unix adapter dials the plaintext gRPC UDS with TLS
//     credentials, so it fails at connect.
//   - #493 — the CLI adapter shelled verbs and flags platformctl does not
//     have (--tenant-id among them). Since #534 `platformctl device
//     register` creates a device rather than a profile, so the CLI is a
//     case here; "unknown command" or "unknown flag" means the adapter
//     and the CLI drifted apart again.
//
// MCP left this list with #533: the adapter posts to the /mcp path, and
// the device_* tools it calls all dispatch and take its argument names.
func unreachableTransportIssue(adapter string, err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	signatures := map[string][]string{
		"REST": {"404 page not found", "status: 404"},
		"Unix": {"does not look like a TLS handshake"},
		"CLI":  {"unknown command", "unknown flag"},
	}
	issues := map[string]string{
		"REST": "#531 (the adapter addresses routes the server does not serve)",
		"Unix": "#532 (the adapter dials the plaintext UDS with TLS credentials)",
		"CLI":  "#493 (the adapter shells a verb or flag platformctl does not have)",
	}
	for _, sig := range signatures[adapter] {
		if strings.Contains(msg, sig) {
			return issues[adapter]
		}
	}
	// A transport with no known signature can still fail to arrive.
	// Report it without an issue number rather than blaming create.
	for _, sig := range []string{"connection refused", "no such host", "context deadline exceeded"} {
		if strings.Contains(msg, sig) {
			return "no issue filed yet"
		}
	}
	return ""
}

// TestDeviceCreateThenReadAcrossTransports is the acceptance test for
// #525: a device created over each service transport comes back with an
// identity and is readable afterwards under it.
//
// Before the fix, none of them could. Every transport's create verb
// reached DeviceService.Save, which requires a non-zero ID, and a caller
// creating a device has none — that is what creation means. The daemon
// answered InvalidArgument "invalid device ID", measured at 67 refusals
// in one run of this suite. Identity assignment now lives in
// DeviceService.Create, behind the service boundary, so all five reach
// it rather than each remembering to mint an ID of its own.
//
// Setup failure is fatal here rather than a skip. A create path that
// cannot be exercised is exactly the condition this test exists to
// detect, and reporting it as a pass is the disagreement #523 settles.
func TestDeviceCreateThenReadAcrossTransports(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	adapters := []DeviceCommands{
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
		NewCLIAdapter(),
	}

	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			if err := adapter.Setup(ctx); err != nil {
				if issue := unreachableTransportIssue(adapter.Name(), err); issue != "" {
					t.Fatalf("%s: the request never reached a device handler, so this is "+
						"a transport-adapter defect tracked by %s and NOT #525 regressing. "+
						"The create path on this transport is unproven either way: %v",
						adapter.Name(), issue, err)
				}
				t.Fatalf("%s: setup failed, so the create path cannot be exercised: %v",
					adapter.Name(), err)
			}
			t.Cleanup(func() {
				if err := adapter.Teardown(context.Background()); err != nil {
					t.Logf("teardown: %v", err)
				}
			})

			serial := GenerateTestSerial("create-525-" + uuid.New().String()[:8])
			created, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
				TenantID: DefaultTenantID(),
				Serial:   serial,
				Model:    "test-model-create-525",
			})
			if err != nil {
				if issue := unreachableTransportIssue(adapter.Name(), err); issue != "" {
					t.Fatalf("%s: the create request never reached a device handler, so this "+
						"is a transport-adapter defect tracked by %s and NOT #525 regressing. "+
						"The create path on this transport is unproven either way: %v",
						adapter.Name(), issue, err)
				}
				t.Fatalf("%s: the daemon refused to create a device — this IS a #525 "+
					"regression if it says \"invalid device ID\": %v", adapter.Name(), err)
			}
			if created == nil || created.Device == nil {
				t.Fatalf("%s: create returned no device", adapter.Name())
			}

			deviceID := created.Device.ID
			if deviceID == 0 {
				t.Fatalf("%s: create returned a device with no ID, so nothing can read it back",
					adapter.Name())
			}
			t.Cleanup(func() {
				if _, err := adapter.DeleteDevice(context.Background(), DeleteDeviceOptions{
					TenantID: DefaultTenantID(),
					DeviceID: strconv.FormatUint(deviceID, 10),
				}); err != nil {
					t.Logf("cleanup: delete device %d: %v", deviceID, err)
				}
			})

			read, err := adapter.GetDevice(ctx, GetDeviceOptions{
				TenantID: DefaultTenantID(),
				DeviceID: strconv.FormatUint(deviceID, 10),
			})
			if err != nil {
				if issue := unreachableTransportIssue(adapter.Name(), err); issue != "" {
					t.Fatalf("%s: the read-back never reached a device handler, so this is a "+
						"transport-adapter defect tracked by %s and NOT #525 regressing. The "+
						"device was created with ID %d: %v", adapter.Name(), issue, deviceID, err)
				}
				t.Fatalf("%s: the created device could not be read back by its assigned ID %d: %v",
					adapter.Name(), deviceID, err)
			}
			if read == nil || read.Device == nil {
				t.Fatalf("%s: reading back device %d returned nothing", adapter.Name(), deviceID)
			}
			if read.Device.ID != deviceID {
				t.Errorf("%s: read back device %d, want %d", adapter.Name(), read.Device.ID, deviceID)
			}

			// What the caller sent must reach the record on every transport;
			// MCP once stored its arguments under the wrong fields (#533).
			if read.Device.Serial != serial {
				t.Errorf("%s: read back serial %q, want %q",
					adapter.Name(), read.Device.Serial, serial)
			}
		})
	}
}

// TestDeviceCreateAssignsDistinctIdentities guards the other half of an
// assigned identity: two creates on one transport must not collide, or
// the second silently replaces the first.
func TestDeviceCreateAssignsDistinctIdentities(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// gRPC is the transport this asserts on because it reaches the same
	// DeviceGRPCService.CreateDevice that Unix and QUIC OpDeviceRegister
	// do, and it is reachable today.
	adapter := NewGRPCAdapter()
	if err := adapter.Setup(ctx); err != nil {
		t.Fatalf("gRPC setup failed, so the create path cannot be exercised: %v", err)
	}
	t.Cleanup(func() {
		if err := adapter.Teardown(context.Background()); err != nil {
			t.Logf("teardown: %v", err)
		}
	})

	ids := make(map[uint64]struct{}, 2)
	for i := 0; i < 2; i++ {
		created, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
			TenantID: DefaultTenantID(),
			Serial:   GenerateTestSerial("distinct-525-" + uuid.New().String()[:8]),
			Model:    "test-model-create-525",
		})
		if err != nil {
			t.Fatalf("the daemon refused to create device %d: %v", i, err)
		}
		id := created.Device.ID
		if id == 0 {
			t.Fatalf("create %d returned a device with no ID", i)
		}
		if _, seen := ids[id]; seen {
			t.Fatalf("create %d reused device ID %d", i, id)
		}
		ids[id] = struct{}{}
		t.Cleanup(func() {
			if _, err := adapter.DeleteDevice(context.Background(), DeleteDeviceOptions{
				TenantID: DefaultTenantID(),
				DeviceID: strconv.FormatUint(id, 10),
			}); err != nil {
				t.Logf("cleanup: delete device %d: %v", id, err)
			}
		})
	}
}
