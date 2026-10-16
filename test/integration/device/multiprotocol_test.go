//go:build integration

package device

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// TestDeviceMultiProtocol runs all device tests across multiple protocols
func TestDeviceMultiProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Define protocol adapters to test
	adapters := []DeviceCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewGRPCAdapter(),
		NewQUICAdapter(),
		NewMCPAdapter(),
		NewUnixAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "device", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter // capture range variable
		t.Run(adapter.Name(), func(t *testing.T) {
			// Setup adapter
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				if err := adapter.Teardown(ctx); err != nil {
					t.Logf("Warning: teardown failed: %v", err)
				}
			}()

			// Run all test suites
			t.Run("DeviceCRUD", func(t *testing.T) {
				testDeviceCRUD(t, ctx, adapter)
			})
			t.Run("DeviceLookups", func(t *testing.T) {
				testDeviceLookups(t, ctx, adapter)
			})
			t.Run("ProfileCRUD", func(t *testing.T) {
				testProfileCRUD(t, ctx, adapter)
			})
			t.Run("ProfileLookups", func(t *testing.T) {
				testProfileLookups(t, ctx, adapter)
			})
			t.Run("Attestation", func(t *testing.T) {
				testAttestation(t, ctx, adapter)
			})
			t.Run("TemplateCRUD", func(t *testing.T) {
				testTemplateCRUD(t, ctx, adapter)
			})
			t.Run("TemplateToProfile", func(t *testing.T) {
				testTemplateToProfile(t, ctx, adapter)
			})
			t.Run("ConfigForDevice", func(t *testing.T) {
				testConfigForDevice(t, ctx, adapter)
			})
			t.Run("ProfileAssignment", func(t *testing.T) {
				testProfileAssignment(t, ctx, adapter)
			})
			t.Run("OperatorLifecycle", func(t *testing.T) {
				testOperatorLifecycle(t, ctx, adapter)
			})
		})
	}
}

// lifecycleRefusal prefixes every refusal the device lifecycle service
// answers for a device it cannot enforce: no SDN policy engine on this
// control plane, or no switch port on record for the device.
const lifecycleRefusal = "device lifecycle:"

// testOperatorLifecycle drives the operator Disable/Enable Device (#250) on
// this transport. A freshly registered device has no switch port on record,
// so the control plane cannot cut it off and must refuse the disable, and it
// must refuse the enable of a device that was never disabled. The refusal is
// asserted by its text so a missing route or opcode cannot pass for one, and
// the stored device must be left exactly as it was.
func testOperatorLifecycle(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	registered, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
		TenantID: tenantID,
		Serial:   GenerateTestSerial(uuid.New().String()[:8] + "-lifecycle"),
		Model:    "test-model-lifecycle",
	})
	if err != nil {
		t.Fatalf("RegisterDevice failed: %v", err)
	}
	deviceID := fmt.Sprintf("%d", registered.Device.ID)

	disabled, err := adapter.DisableDevice(ctx, DisableDeviceOptions{DeviceID: deviceID, Reason: "integration"})
	if err == nil {
		t.Fatalf("DisableDevice of a device with no switch port succeeded: %+v", disabled)
	}
	if !strings.Contains(err.Error(), lifecycleRefusal) {
		t.Fatalf("DisableDevice failed without reaching the lifecycle service: %v", err)
	}

	enabled, err := adapter.EnableDevice(ctx, EnableDeviceOptions{DeviceID: deviceID})
	if err == nil {
		t.Fatalf("EnableDevice of a device that was never disabled succeeded: %+v", enabled)
	}
	if !strings.Contains(err.Error(), lifecycleRefusal) {
		t.Fatalf("EnableDevice failed without reaching the lifecycle service: %v", err)
	}

	after, err := adapter.GetDevice(ctx, GetDeviceOptions{TenantID: tenantID, DeviceID: deviceID})
	if err != nil {
		t.Fatalf("GetDevice failed: %v", err)
	}
	if after.Device.State != registered.Device.State || after.Device.StateReason != registered.Device.StateReason {
		t.Errorf("a refused transition changed the device: state %q (%q), want %q (%q)",
			after.Device.State, after.Device.StateReason, registered.Device.State, registered.Device.StateReason)
	}
}

// ============================================================================
// Device CRUD Tests
// ============================================================================

func testDeviceCRUD(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("RegisterDevice", func(t *testing.T) {
		opts := RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID),
			Model:    "test-model-" + testID,
		}

		result, err := adapter.RegisterDevice(ctx, opts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		if result.Device == nil {
			t.Fatal("RegisterDevice returned nil device")
		}

		if result.Device.Serial != opts.Serial {
			t.Errorf("Device serial mismatch: got %s, want %s", result.Device.Serial, opts.Serial)
		}

		if result.Device.Model != opts.Model {
			t.Errorf("Device model mismatch: got %s, want %s", result.Device.Model, opts.Model)
		}
	})

	t.Run("GetDevice", func(t *testing.T) {
		// First register a device
		registerOpts := RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID + "-get"),
			Model:    "test-model-" + testID,
		}

		registerResult, err := adapter.RegisterDevice(ctx, registerOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		// Now get the device
		getOpts := GetDeviceOptions{
			TenantID: tenantID,
			DeviceID: fmt.Sprintf("%d", registerResult.Device.ID),
		}

		getResult, err := adapter.GetDevice(ctx, getOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("GetDevice failed: %v", err)
		}

		if getResult.Device == nil {
			t.Fatal("GetDevice returned nil device")
		}

		if getResult.Device.ID != registerResult.Device.ID {
			t.Errorf("Device ID mismatch: got %d, want %d", getResult.Device.ID, registerResult.Device.ID)
		}
	})

	t.Run("UpdateDevice", func(t *testing.T) {
		// First register a device
		registerOpts := RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID + "-update"),
			Model:    "test-model-original",
		}

		registerResult, err := adapter.RegisterDevice(ctx, registerOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		// Update the device
		updateOpts := UpdateDeviceOptions{
			TenantID: tenantID,
			DeviceID: fmt.Sprintf("%d", registerResult.Device.ID),
			Model:    "test-model-updated",
		}

		updateResult, err := adapter.UpdateDevice(ctx, updateOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("UpdateDevice failed: %v", err)
		}

		if updateResult.Device == nil {
			t.Fatal("UpdateDevice returned nil device")
		}

		if updateResult.Device.Model != updateOpts.Model {
			t.Errorf("Device model not updated: got %s, want %s", updateResult.Device.Model, updateOpts.Model)
		}
	})

	t.Run("AttestCertSurvivesUpdate", func(t *testing.T) {
		// #404: the enrolled attestation certificate is the only trust anchor
		// the quote verifier accepts. It must travel on this transport in
		// both directions and survive an update that does not name it.
		const attestCert = "-----BEGIN CERTIFICATE-----\nintegration-iak\n-----END CERTIFICATE-----\n"
		registerResult, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
			TenantID:   tenantID,
			Serial:     GenerateTestSerial(testID + "-attestcert"),
			Model:      "test-model-attestcert",
			AttestPub:  "integration-attest-pub",
			AttestCert: attestCert,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}
		if registerResult.Device.AttestCert != attestCert {
			t.Fatalf("RegisterDevice dropped attest_cert: got %q", registerResult.Device.AttestCert)
		}

		deviceID := fmt.Sprintf("%d", registerResult.Device.ID)
		getResult, err := adapter.GetDevice(ctx, GetDeviceOptions{TenantID: tenantID, DeviceID: deviceID})
		if err != nil {
			t.Fatalf("GetDevice failed: %v", err)
		}
		if getResult.Device.AttestCert != attestCert {
			t.Fatalf("GetDevice does not return attest_cert: got %q", getResult.Device.AttestCert)
		}

		if _, err := adapter.UpdateDevice(ctx, UpdateDeviceOptions{
			TenantID: tenantID,
			DeviceID: deviceID,
			Model:    "test-model-attestcert-updated",
		}); err != nil {
			t.Fatalf("UpdateDevice failed: %v", err)
		}

		afterUpdate, err := adapter.GetDevice(ctx, GetDeviceOptions{TenantID: tenantID, DeviceID: deviceID})
		if err != nil {
			t.Fatalf("GetDevice after update failed: %v", err)
		}
		if afterUpdate.Device.AttestCert != attestCert {
			t.Fatalf("an update that omits attest_cert erased it: got %q", afterUpdate.Device.AttestCert)
		}
		if afterUpdate.Device.Model != "test-model-attestcert-updated" {
			t.Errorf("Device model not updated: got %s", afterUpdate.Device.Model)
		}
	})

	t.Run("DeleteDevice", func(t *testing.T) {
		// First register a device
		registerOpts := RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID + "-delete"),
			Model:    "test-model-delete",
		}

		registerResult, err := adapter.RegisterDevice(ctx, registerOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		// Delete the device
		deleteOpts := DeleteDeviceOptions{
			TenantID: tenantID,
			DeviceID: fmt.Sprintf("%d", registerResult.Device.ID),
		}

		deleteResult, err := adapter.DeleteDevice(ctx, deleteOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("DeleteDevice failed: %v", err)
		}

		if !deleteResult.Success {
			t.Error("DeleteDevice did not return success")
		}

		// Verify device is deleted
		getOpts := GetDeviceOptions{
			TenantID: tenantID,
			DeviceID: fmt.Sprintf("%d", registerResult.Device.ID),
		}

		_, err = adapter.GetDevice(ctx, getOpts)
		if err == nil {
			t.Error("GetDevice should fail for deleted device")
		}
	})

	t.Run("ListDevices", func(t *testing.T) {
		// Register multiple devices
		for i := 0; i < 3; i++ {
			registerOpts := RegisterDeviceOptions{
				TenantID: tenantID,
				Serial:   GenerateTestSerial(testID + "-list-" + string(rune('a'+i))),
				Model:    "test-model-list",
			}

			_, err := adapter.RegisterDevice(ctx, registerOpts)
			if err != nil {
				surface.RequireImplemented(t, err)
				t.Fatalf("RegisterDevice failed: %v", err)
			}
		}

		// List devices
		listOpts := ListDevicesOptions{
			TenantID: tenantID,
			Limit:    10,
		}

		listResult, err := adapter.ListDevices(ctx, listOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("ListDevices failed: %v", err)
		}

		if len(listResult.Devices) == 0 {
			t.Error("ListDevices returned no devices")
		}
	})
}

// ============================================================================
// Device Lookup Tests
// ============================================================================

func testDeviceLookups(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("FindBySerial", func(t *testing.T) {
		serial := GenerateTestSerial(testID + "-lookup")

		// Register a device
		registerOpts := RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   serial,
			Model:    "test-model-lookup",
		}

		_, err := adapter.RegisterDevice(ctx, registerOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		// Find by serial
		findOpts := FindBySerialOptions{
			TenantID: tenantID,
			Serial:   serial,
		}

		findResult, err := adapter.FindBySerial(ctx, findOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("FindBySerial failed: %v", err)
		}

		if findResult.Device == nil {
			t.Fatal("FindBySerial returned nil device")
		}

		if findResult.Device.Serial != serial {
			t.Errorf("Device serial mismatch: got %s, want %s", findResult.Device.Serial, serial)
		}
	})

	t.Run("FindBySerial_NotFound", func(t *testing.T) {
		findOpts := FindBySerialOptions{
			TenantID: tenantID,
			Serial:   "NON-EXISTENT-SERIAL-" + testID,
		}

		_, err := adapter.FindBySerial(ctx, findOpts)
		if err == nil {
			t.Error("FindBySerial should fail for non-existent serial")
		}
	})
}

// ============================================================================
// Profile CRUD Tests
// ============================================================================

func testProfileCRUD(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CreateProfile", func(t *testing.T) {
		opts := CreateProfileOptions{
			TenantID:     tenantID,
			Name:         GenerateTestProfileName(testID),
			Model:        "test-model",
			Role:         entities.DeviceRoleServer,
			MACPrefix:    "AA:BB:CC",
			SerialPrefix: "TEST-",
		}

		result, err := adapter.CreateProfile(ctx, opts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		if result.Profile == nil {
			t.Fatal("CreateProfile returned nil profile")
		}

		if result.Profile.Name != opts.Name {
			t.Errorf("Profile name mismatch: got %s, want %s", result.Profile.Name, opts.Name)
		}
	})

	t.Run("GetProfile", func(t *testing.T) {
		// First create a profile
		createOpts := CreateProfileOptions{
			TenantID: tenantID,
			Name:     GenerateTestProfileName(testID + "-get"),
			Model:    "test-model-get",
			Role:     entities.DeviceRoleClient,
		}

		createResult, err := adapter.CreateProfile(ctx, createOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		// Now get the profile
		getOpts := GetProfileOptions{
			TenantID:  tenantID,
			ProfileID: fmt.Sprintf("%d", createResult.Profile.ID),
		}

		getResult, err := adapter.GetProfile(ctx, getOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("GetProfile failed: %v", err)
		}

		if getResult.Profile == nil {
			t.Fatal("GetProfile returned nil profile")
		}

		if getResult.Profile.ID != createResult.Profile.ID {
			t.Errorf("Profile ID mismatch: got %d, want %d", getResult.Profile.ID, createResult.Profile.ID)
		}
	})

	t.Run("UpdateProfile", func(t *testing.T) {
		// First create a profile
		createOpts := CreateProfileOptions{
			TenantID: tenantID,
			Name:     GenerateTestProfileName(testID + "-update"),
			Model:    "test-model-original",
			Role:     entities.DeviceRoleWorkstation,
		}

		createResult, err := adapter.CreateProfile(ctx, createOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		// Update the profile
		updateOpts := UpdateProfileOptions{
			TenantID:  tenantID,
			ProfileID: fmt.Sprintf("%d", createResult.Profile.ID),
			Name:      GenerateTestProfileName(testID + "-updated"),
			Model:     "test-model-updated",
			Role:      entities.DeviceRoleEdge,
		}

		updateResult, err := adapter.UpdateProfile(ctx, updateOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("UpdateProfile failed: %v", err)
		}

		if updateResult.Profile == nil {
			t.Fatal("UpdateProfile returned nil profile")
		}

		if updateResult.Profile.Name != updateOpts.Name {
			t.Errorf("Profile name not updated: got %s, want %s", updateResult.Profile.Name, updateOpts.Name)
		}
	})

	t.Run("DeleteProfile", func(t *testing.T) {
		// First create a profile
		createOpts := CreateProfileOptions{
			TenantID: tenantID,
			Name:     GenerateTestProfileName(testID + "-delete"),
			Model:    "test-model-delete",
			Role:     entities.DeviceRoleIoT,
		}

		createResult, err := adapter.CreateProfile(ctx, createOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		// Delete the profile
		deleteOpts := DeleteProfileOptions{
			TenantID:  tenantID,
			ProfileID: fmt.Sprintf("%d", createResult.Profile.ID),
		}

		deleteResult, err := adapter.DeleteProfile(ctx, deleteOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("DeleteProfile failed: %v", err)
		}

		if !deleteResult.Success {
			t.Error("DeleteProfile did not return success")
		}

		// Verify profile is deleted
		getOpts := GetProfileOptions{
			TenantID:  tenantID,
			ProfileID: fmt.Sprintf("%d", createResult.Profile.ID),
		}

		_, err = adapter.GetProfile(ctx, getOpts)
		if err == nil {
			t.Error("GetProfile should fail for deleted profile")
		}
	})

	t.Run("ListProfiles", func(t *testing.T) {
		// Create multiple profiles
		for i := 0; i < 3; i++ {
			createOpts := CreateProfileOptions{
				TenantID: tenantID,
				Name:     GenerateTestProfileName(testID + "-list-" + string(rune('a'+i))),
				Model:    "test-model-list",
				Role:     entities.DeviceRoleServer,
			}

			_, err := adapter.CreateProfile(ctx, createOpts)
			if err != nil {
				surface.RequireImplemented(t, err)
				t.Fatalf("CreateProfile failed: %v", err)
			}
		}

		// List profiles
		listOpts := ListProfilesOptions{
			TenantID: tenantID,
			Limit:    10,
		}

		listResult, err := adapter.ListProfiles(ctx, listOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("ListProfiles failed: %v", err)
		}

		if len(listResult.Profiles) == 0 {
			t.Error("ListProfiles returned no profiles")
		}
	})
}

// ============================================================================
// Profile Lookup Tests
// ============================================================================

func testProfileLookups(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("FindProfileByMACAddress", func(t *testing.T) {
		macPrefix := "AA:BB:" + testID[:2]

		// Create a profile with MAC prefix
		createOpts := CreateProfileOptions{
			TenantID:  tenantID,
			Name:      GenerateTestProfileName(testID + "-mac"),
			Model:     "test-model-mac",
			Role:      entities.DeviceRoleGateway,
			MACPrefix: macPrefix,
		}

		_, err := adapter.CreateProfile(ctx, createOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		// Find by MAC address
		findOpts := FindProfileByMACAddressOptions{
			TenantID:   tenantID,
			MACAddress: macPrefix + ":DD:EE:FF",
		}

		findResult, err := adapter.FindProfileByMACAddress(ctx, findOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("FindProfileByMACAddress failed: %v", err)
		}

		if findResult.Profile == nil {
			t.Fatal("FindProfileByMACAddress returned nil profile")
		}
	})

	t.Run("FindProfileBySerial", func(t *testing.T) {
		serialPrefix := "SN-" + testID + "-"

		// Create a profile with serial pattern
		createOpts := CreateProfileOptions{
			TenantID:     tenantID,
			Name:         GenerateTestProfileName(testID + "-serial"),
			Model:        "test-model-serial",
			Role:         entities.DeviceRoleLoadBalancer,
			SerialPrefix: serialPrefix,
		}

		_, err := adapter.CreateProfile(ctx, createOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		// Find by serial
		findOpts := FindProfileBySerialOptions{
			TenantID: tenantID,
			Serial:   serialPrefix + "12345",
		}

		findResult, err := adapter.FindProfileBySerial(ctx, findOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("FindProfileBySerial failed: %v", err)
		}

		if findResult.Profile == nil {
			t.Fatal("FindProfileBySerial returned nil profile")
		}
	})

	t.Run("FindMatchingProfile", func(t *testing.T) {
		// Create a profile with multiple matching criteria
		createOpts := CreateProfileOptions{
			TenantID:     tenantID,
			Name:         GenerateTestProfileName(testID + "-match"),
			Model:        "match-model-" + testID,
			Role:         entities.DeviceRoleServer,
			MACPrefix:    "CC:DD:" + testID[:2],
			SerialPrefix: "MATCH-" + testID + "-",
		}

		_, err := adapter.CreateProfile(ctx, createOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfile failed: %v", err)
		}

		// Find matching profile
		findOpts := FindMatchingProfileOptions{
			TenantID:   tenantID,
			MACAddress: "CC:DD:" + testID[:2] + ":AA:BB:CC",
			Serial:     "MATCH-" + testID + "-67890",
			Model:      "match-model-" + testID,
		}

		findResult, err := adapter.FindMatchingProfile(ctx, findOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("FindMatchingProfile failed: %v", err)
		}

		if findResult.Profile == nil {
			t.Fatal("FindMatchingProfile returned nil profile")
		}
	})
}

// ============================================================================
// Attestation Tests
//
// These assert the NEGATIVE case on purpose. A positive case would need the
// private attestation key the device enrolled, which the suite does not
// hold; but "evidence that must be refused" needs no key and is the
// assertion a stub verifier cannot satisfy. Before #403 the REST and QUIC
// attest handlers returned true for any input and this suite reported them
// passing.
// ============================================================================

// forgedQuoteEvidence is evidence in the shape the verifier consumes whose
// quote is not a TPMS_ATTEST structure and whose signature is not a
// signature over anything. No key can make it verify, on any transport.
func forgedQuoteEvidence(t *testing.T, testID string) []byte {
	t.Helper()
	evidence := map[string][]byte{
		"quote":     []byte("not-a-tpms-attest-structure-" + testID),
		"signature": []byte("not-a-signature-" + testID),
		"nonce":     []byte("nonce-" + testID),
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("marshal forged evidence: %v", err)
	}
	return raw
}

func testAttestation(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("RecordAttestCertRefusedWithoutEnrolledKey", func(t *testing.T) {
		// A device the suite registers carries no TPM-enrolled attestation
		// public area, so no certificate can be tied to it: the control
		// plane's fail-closed preflight must refuse (FAILED_PRECONDITION on
		// gRPC, 400 on REST) and leave the record untouched -- on every
		// transport, including with reissue, which must not reach the CA,
		// and with clear-on-refusal, which has nothing it may clear (#516).
		registerResult, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID + "-attcert"),
			Model:    "test-model-attcert",
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("RegisterDevice failed: %v", err)
		}
		deviceID := fmt.Sprintf("%d", registerResult.Device.ID)

		for _, opts := range []RecordAttestCertOptions{{}, {Reissue: true}, {ClearOnRefusal: true}} {
			opts.TenantID = tenantID
			opts.DeviceID = deviceID
			result, err := adapter.RecordAttestCert(ctx, opts)
			if err == nil {
				t.Fatalf("RecordAttestCert(reissue=%t, clear_on_refusal=%t) must be refused for a device with no enrolled attestation key, got %+v", opts.Reissue, opts.ClearOnRefusal, result)
			}
			surface.RequireImplemented(t, err)
			if !strings.Contains(strings.ToLower(err.Error()), "attestation") {
				t.Fatalf("refusal should name the attestation certificate, got: %v", err)
			}
		}

		got, err := adapter.GetDevice(ctx, GetDeviceOptions{TenantID: tenantID, DeviceID: deviceID})
		if err != nil {
			t.Fatalf("GetDevice after refusal: %v", err)
		}
		if got.Device.AttestCert != "" {
			t.Fatalf("a refused record must write nothing, but attest_cert is set: %q", got.Device.AttestCert)
		}
	})

	t.Run("ForgedQuoteIsRefused", func(t *testing.T) {
		registerResult, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID + "-attest"),
			Model:    "test-model-attest",
		})
		if err != nil {
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		deviceID := fmt.Sprintf("%d", registerResult.Device.ID)
		attestResult, err := adapter.AttestDevice(ctx, AttestDeviceOptions{
			TenantID: tenantID,
			DeviceID: deviceID,
			Evidence: forgedQuoteEvidence(t, testID),
		})

		// An adapter with no attestation surface says so. That is a
		// reported gap, not a pass: it must never be mistaken for a
		// verdict, and it must not be skipped away.
		var unavailable ErrAttestationTransportUnavailable
		if errors.As(err, &unavailable) {
			t.Logf("%s: %v", adapter.Name(), unavailable)
			return
		}

		// The platform may refuse to evaluate the request at all (an
		// unusable device, a missing dependency). That is also acceptable:
		// what is NOT acceptable is a verdict of verified.
		if err != nil {
			t.Logf("%s refused to evaluate forged evidence: %v", adapter.Name(), err)
			return
		}

		if attestResult == nil {
			t.Fatal("AttestDevice returned neither a verdict nor an error")
		}
		if attestResult.Verified {
			t.Fatalf("%s reported verified=true for a quote that is not a TPM quote: %+v",
				adapter.Name(), attestResult)
		}
		if attestResult.SignatureValid {
			t.Errorf("%s reported signature_valid=true for a signature over nothing: %+v",
				adapter.Name(), attestResult)
		}
		if attestResult.Message == "" && attestResult.AttestationStatus == "" {
			t.Error("a refused verdict must say why it was refused")
		}
	})

	t.Run("EmptyEvidenceIsRefused", func(t *testing.T) {
		registerResult, err := adapter.RegisterDevice(ctx, RegisterDeviceOptions{
			TenantID: tenantID,
			Serial:   GenerateTestSerial(testID + "-attest-empty"),
			Model:    "test-model-attest",
		})
		if err != nil {
			t.Fatalf("RegisterDevice failed: %v", err)
		}

		attestResult, err := adapter.AttestDevice(ctx, AttestDeviceOptions{
			TenantID: tenantID,
			DeviceID: fmt.Sprintf("%d", registerResult.Device.ID),
		})

		var unavailable ErrAttestationTransportUnavailable
		if errors.As(err, &unavailable) {
			t.Logf("%s: %v", adapter.Name(), unavailable)
			return
		}
		if err != nil {
			return // refusing to evaluate empty evidence is the right answer
		}
		if attestResult != nil && attestResult.Verified {
			t.Fatalf("%s reported verified=true for empty evidence: %+v",
				adapter.Name(), attestResult)
		}
	})

	t.Run("UnknownDeviceIsNotAVerdict", func(t *testing.T) {
		attestResult, err := adapter.AttestDevice(ctx, AttestDeviceOptions{
			TenantID: tenantID,
			DeviceID: "999999999",
			Evidence: forgedQuoteEvidence(t, testID),
		})

		var unavailable ErrAttestationTransportUnavailable
		if errors.As(err, &unavailable) {
			t.Logf("%s: %v", adapter.Name(), unavailable)
			return
		}
		if err == nil && attestResult != nil && attestResult.Verified {
			t.Fatalf("%s reported verified=true for a device that does not exist: %+v",
				adapter.Name(), attestResult)
		}
	})
}

// ============================================================================
// Template CRUD Tests
// ============================================================================

func testTemplateCRUD(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CreateAndGetTemplate", func(t *testing.T) {
		// Create a template
		createOpts := CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID),
			Description: "Integration test template for " + testID,
			Role:        entities.DeviceRoleServer,
			Config:      []byte(`{"test": "config"}`),
			MatchRules: &entities.ProfileMatchRules{
				SerialPrefix: "TMPL-" + testID + "-",
			},
		}

		createResult, err := adapter.CreateTemplate(ctx, createOpts)
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		if createResult.Template == nil {
			t.Fatal("CreateTemplate returned nil template")
		}

		if createResult.Template.ID == 0 {
			t.Error("CreateTemplate returned zero ID")
		}

		if createResult.Template.Name != createOpts.Name {
			t.Errorf("Template name mismatch: got %s, want %s",
				createResult.Template.Name, createOpts.Name)
		}

		if createResult.Template.Description != createOpts.Description {
			t.Errorf("Template description mismatch: got %s, want %s",
				createResult.Template.Description, createOpts.Description)
		}

		if createResult.Template.Role != createOpts.Role {
			t.Errorf("Template role mismatch: got %s, want %s",
				createResult.Template.Role, createOpts.Role)
		}

		// Get the template by ID
		getOpts := GetTemplateOptions{
			TenantID:   tenantID,
			TemplateID: fmt.Sprintf("%d", createResult.Template.ID),
		}

		getResult, err := adapter.GetTemplate(ctx, getOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("GetTemplate failed: %v", err)
		}

		if getResult.Template == nil {
			t.Fatal("GetTemplate returned nil template")
		}

		if getResult.Template.ID != createResult.Template.ID {
			t.Errorf("Template ID mismatch: got %d, want %d",
				getResult.Template.ID, createResult.Template.ID)
		}

		if getResult.Template.Name != createOpts.Name {
			t.Errorf("Template name mismatch on get: got %s, want %s",
				getResult.Template.Name, createOpts.Name)
		}

		if getResult.Template.Description != createOpts.Description {
			t.Errorf("Template description mismatch on get: got %s, want %s",
				getResult.Template.Description, createOpts.Description)
		}

		if getResult.Template.Role != createOpts.Role {
			t.Errorf("Template role mismatch on get: got %s, want %s",
				getResult.Template.Role, createOpts.Role)
		}
	})

	t.Run("UpdateTemplate", func(t *testing.T) {
		// Create a template first
		createOpts := CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID + "-upd"),
			Description: "Original description",
			Role:        entities.DeviceRoleServer,
		}

		createResult, err := adapter.CreateTemplate(ctx, createOpts)
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		// Update the template
		updatedDesc := "Updated description for " + testID
		updateOpts := UpdateTemplateOptions{
			TenantID:    tenantID,
			TemplateID:  fmt.Sprintf("%d", createResult.Template.ID),
			Name:        GenerateTestTemplateName(testID + "-upd-new"),
			Description: updatedDesc,
			Role:        entities.DeviceRoleEdge,
		}

		updateResult, err := adapter.UpdateTemplate(ctx, updateOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("UpdateTemplate failed: %v", err)
		}

		if updateResult.Template == nil {
			t.Fatal("UpdateTemplate returned nil template")
		}

		if updateResult.Template.Description != updatedDesc {
			t.Errorf("Template description not updated: got %s, want %s",
				updateResult.Template.Description, updatedDesc)
		}

		if updateResult.Template.Role != entities.DeviceRoleEdge {
			t.Errorf("Template role not updated: got %s, want %s",
				updateResult.Template.Role, entities.DeviceRoleEdge)
		}

		// Verify via get
		getResult, err := adapter.GetTemplate(ctx, GetTemplateOptions{
			TenantID:   tenantID,
			TemplateID: fmt.Sprintf("%d", createResult.Template.ID),
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("GetTemplate after update failed: %v", err)
		}

		if getResult.Template.Description != updatedDesc {
			t.Errorf("Template description not persisted: got %s, want %s",
				getResult.Template.Description, updatedDesc)
		}
	})

	t.Run("ListTemplates", func(t *testing.T) {
		// Create a couple of templates
		for i := 0; i < 2; i++ {
			createOpts := CreateTemplateOptions{
				TenantID:    tenantID,
				Name:        GenerateTestTemplateName(testID + "-lst-" + string(rune('a'+i))),
				Description: "List test template",
				Role:        entities.DeviceRoleServer,
			}

			_, err := adapter.CreateTemplate(ctx, createOpts)
			surface.RequireImplemented(t, err)
			if err != nil {
				t.Fatalf("CreateTemplate failed: %v", err)
			}
		}

		// List templates
		listOpts := ListTemplatesOptions{
			TenantID: tenantID,
			Limit:    10,
		}

		listResult, err := adapter.ListTemplates(ctx, listOpts)
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("ListTemplates failed: %v", err)
		}

		if len(listResult.Templates) == 0 {
			t.Error("ListTemplates returned no templates")
		}
	})

	t.Run("DeleteTemplate", func(t *testing.T) {
		// Create a template
		createOpts := CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID + "-del"),
			Description: "Template to delete",
			Role:        entities.DeviceRoleIoT,
		}

		createResult, err := adapter.CreateTemplate(ctx, createOpts)
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		templateID := fmt.Sprintf("%d", createResult.Template.ID)

		// Delete the template
		deleteResult, err := adapter.DeleteTemplate(ctx, DeleteTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("DeleteTemplate failed: %v", err)
		}

		if !deleteResult.Success {
			t.Error("DeleteTemplate did not return success")
		}

		// Verify get returns not found
		_, err = adapter.GetTemplate(ctx, GetTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
		})
		if err == nil {
			t.Error("GetTemplate should fail for deleted template")
		}
	})
}

// ============================================================================
// Template-to-Profile Tests
// ============================================================================

func testTemplateToProfile(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("CreateProfileFromTemplate", func(t *testing.T) {
		// Create a template with config and match rules
		createOpts := CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID + "-p2t"),
			Description: "Template for profile creation",
			Role:        entities.DeviceRoleServer,
			Config:      []byte(`{"server": {"port": 8443}}`),
			MatchRules: &entities.ProfileMatchRules{
				SerialPrefix: "P2T-" + testID + "-",
			},
		}

		templateResult, err := adapter.CreateTemplate(ctx, createOpts)
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		templateID := fmt.Sprintf("%d", templateResult.Template.ID)

		// Create a profile from the template with EK serial override
		ekSerial := "EK-" + testID + "-001"
		profileResult, err := adapter.CreateProfileFromTemplate(ctx, CreateProfileFromTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
			Name:       GenerateTestProfileName(testID + "-from-tmpl"),
			EKSerial:   ekSerial,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfileFromTemplate failed: %v", err)
		}

		if profileResult.Profile == nil {
			t.Fatal("CreateProfileFromTemplate returned nil profile")
		}

		// Verify profile has the template's role
		if profileResult.Profile.Role != entities.DeviceRoleServer {
			t.Errorf("Profile role mismatch: got %s, want %s",
				profileResult.Profile.Role, entities.DeviceRoleServer)
		}

		// Verify profile has the provided EK serial
		if profileResult.Profile.EKSerial != ekSerial {
			t.Errorf("Profile EK serial mismatch: got %s, want %s",
				profileResult.Profile.EKSerial, ekSerial)
		}

		// Clean up: delete profile then template
		if profileResult.Profile.ID != 0 {
			_, cleanupErr := adapter.DeleteProfile(ctx, DeleteProfileOptions{
				TenantID:  tenantID,
				ProfileID: fmt.Sprintf("%d", profileResult.Profile.ID),
			})
			if cleanupErr != nil {
				t.Logf("Warning: failed to clean up profile: %v", cleanupErr)
			}
		}

		_, cleanupErr := adapter.DeleteTemplate(ctx, DeleteTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
		})
		if cleanupErr != nil {
			t.Logf("Warning: failed to clean up template: %v", cleanupErr)
		}
	})
}

// ============================================================================
// Config-for-Device Tests
// ============================================================================

func testConfigForDevice(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("FindConfigByEKSerial", func(t *testing.T) {
		// Create a template
		templateResult, err := adapter.CreateTemplate(ctx, CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID + "-cfg-ek"),
			Description: "Template for config-for-device EK test",
			Role:        entities.DeviceRoleServer,
			Config:      []byte(`{"ek_test": true}`),
		})
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		templateID := fmt.Sprintf("%d", templateResult.Template.ID)

		// Create a profile from template with EK serial
		ekSerial := "TEST-EK-" + testID + "-001"
		profileResult, err := adapter.CreateProfileFromTemplate(ctx, CreateProfileFromTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
			Name:       GenerateTestProfileName(testID + "-cfg-ek"),
			EKSerial:   ekSerial,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfileFromTemplate failed: %v", err)
		}

		// FindConfigForDevice with EK serial should find this profile
		findResult, err := adapter.FindConfigForDevice(ctx, FindConfigForDeviceOptions{
			TenantID: tenantID,
			EKSerial: ekSerial,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("FindConfigForDevice by EK serial failed: %v", err)
		}

		if findResult.Profile == nil {
			t.Fatal("FindConfigForDevice returned nil profile")
		}

		if findResult.Profile.EKSerial != ekSerial {
			t.Errorf("Found profile EK serial mismatch: got %s, want %s",
				findResult.Profile.EKSerial, ekSerial)
		}

		// Clean up
		if profileResult.Profile != nil && profileResult.Profile.ID != 0 {
			_, _ = adapter.DeleteProfile(ctx, DeleteProfileOptions{
				TenantID:  tenantID,
				ProfileID: fmt.Sprintf("%d", profileResult.Profile.ID),
			})
		}
		_, _ = adapter.DeleteTemplate(ctx, DeleteTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
		})
	})

	t.Run("FindConfigByMAC", func(t *testing.T) {
		// Create a template
		templateResult, err := adapter.CreateTemplate(ctx, CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID + "-cfg-mac"),
			Description: "Template for config-for-device MAC test",
			Role:        entities.DeviceRoleEdge,
			Config:      []byte(`{"mac_test": true}`),
		})
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		templateID := fmt.Sprintf("%d", templateResult.Template.ID)

		// Create a profile from template with MAC address
		macAddr := "52:54:00:aa:bb:" + testID[:2]
		profileResult, err := adapter.CreateProfileFromTemplate(ctx, CreateProfileFromTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
			Name:       GenerateTestProfileName(testID + "-cfg-mac"),
			MACAddress: macAddr,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfileFromTemplate failed: %v", err)
		}

		// FindConfigForDevice with MAC should find this profile
		findResult, err := adapter.FindConfigForDevice(ctx, FindConfigForDeviceOptions{
			TenantID:   tenantID,
			MACAddress: macAddr,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("FindConfigForDevice by MAC failed: %v", err)
		}

		if findResult.Profile == nil {
			t.Fatal("FindConfigForDevice returned nil profile")
		}

		if findResult.Profile.MACAddress != macAddr {
			t.Errorf("Found profile MAC mismatch: got %s, want %s",
				findResult.Profile.MACAddress, macAddr)
		}

		// Clean up
		if profileResult.Profile != nil && profileResult.Profile.ID != 0 {
			_, _ = adapter.DeleteProfile(ctx, DeleteProfileOptions{
				TenantID:  tenantID,
				ProfileID: fmt.Sprintf("%d", profileResult.Profile.ID),
			})
		}
		_, _ = adapter.DeleteTemplate(ctx, DeleteTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
		})
	})

	t.Run("FindConfigForDevice_NotFound", func(t *testing.T) {
		_, err := adapter.FindConfigForDevice(ctx, FindConfigForDeviceOptions{
			TenantID: tenantID,
			EKSerial: "NONEXISTENT-EK-" + testID,
		})
		surface.RequireImplemented(t, err)
		if err == nil {
			t.Error("FindConfigForDevice should fail for unknown device identity")
		}
	})
}

// ============================================================================
// Profile Assignment Tests
// ============================================================================

func testProfileAssignment(t *testing.T, ctx context.Context, adapter DeviceCommands) {
	tenantID := DefaultTenantID()
	testID := uuid.New().String()[:8]

	t.Run("AssignProfileToDevice", func(t *testing.T) {
		// Create a template
		templateResult, err := adapter.CreateTemplate(ctx, CreateTemplateOptions{
			TenantID:    tenantID,
			Name:        GenerateTestTemplateName(testID + "-assign"),
			Description: "Template for assignment test",
			Role:        entities.DeviceRoleServer,
			Config:      []byte(`{"assign_test": true}`),
		})
		surface.RequireImplemented(t, err)
		if err != nil {
			t.Fatalf("CreateTemplate failed: %v", err)
		}

		templateID := fmt.Sprintf("%d", templateResult.Template.ID)

		// Create an unassigned profile from template
		profileResult, err := adapter.CreateProfileFromTemplate(ctx, CreateProfileFromTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
			Name:       GenerateTestProfileName(testID + "-assign"),
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("CreateProfileFromTemplate failed: %v", err)
		}

		profileID := fmt.Sprintf("%d", profileResult.Profile.ID)

		// Verify profile is not assigned
		if profileResult.Profile.Assigned {
			t.Error("Newly created profile should not be assigned")
		}

		// Assign profile to device
		ekSerial := "ASSIGN-EK-" + testID
		assignResult, err := adapter.AssignProfileToDevice(ctx, AssignProfileToDeviceOptions{
			TenantID:  tenantID,
			ProfileID: profileID,
			EKSerial:  ekSerial,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("AssignProfileToDevice failed: %v", err)
		}

		if assignResult.Profile == nil {
			t.Fatal("AssignProfileToDevice returned nil profile")
		}

		if !assignResult.Profile.Assigned {
			t.Error("Profile should be assigned after AssignProfileToDevice")
		}

		if assignResult.Profile.EKSerial != ekSerial {
			t.Errorf("Profile EK serial mismatch after assignment: got %s, want %s",
				assignResult.Profile.EKSerial, ekSerial)
		}

		// Get profile again to verify persistence
		getResult, err := adapter.GetProfile(ctx, GetProfileOptions{
			TenantID:  tenantID,
			ProfileID: profileID,
		})
		if err != nil {
			surface.RequireImplemented(t, err)
			t.Fatalf("GetProfile after assignment failed: %v", err)
		}

		if !getResult.Profile.Assigned {
			t.Error("Profile should be assigned after re-fetch")
		}

		if getResult.Profile.EKSerial != ekSerial {
			t.Errorf("Profile EK serial not persisted: got %s, want %s",
				getResult.Profile.EKSerial, ekSerial)
		}

		// Clean up
		_, _ = adapter.DeleteProfile(ctx, DeleteProfileOptions{
			TenantID:  tenantID,
			ProfileID: profileID,
		})
		_, _ = adapter.DeleteTemplate(ctx, DeleteTemplateOptions{
			TenantID:   tenantID,
			TemplateID: templateID,
		})
	})
}

// ============================================================================
// Error Handling Tests
// ============================================================================

func TestDeviceMultiProtocol_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapters := []DeviceCommands{
		NewCLIAdapter(),
		NewRESTAdapter(),
		NewMCPAdapter(),
	}

	gate := helpers.NewAdapterGate(t, "device", helpers.AdapterNames(adapters)...)
	for _, adapter := range adapters {
		adapter := adapter
		t.Run(adapter.Name(), func(t *testing.T) {
			gate.RequireSetup(t, adapter.Name(), adapter.Setup(ctx))
			defer func() {
				_ = adapter.Teardown(ctx)
			}()

			t.Run("GetDevice_NotFound", func(t *testing.T) {
				opts := GetDeviceOptions{
					TenantID: DefaultTenantID(),
					DeviceID: "999999999",
				}

				_, err := adapter.GetDevice(ctx, opts)
				if err == nil {
					t.Error("GetDevice should return error for non-existent device")
				}
			})

			t.Run("GetProfile_NotFound", func(t *testing.T) {
				opts := GetProfileOptions{
					TenantID:  DefaultTenantID(),
					ProfileID: "999999999",
				}

				_, err := adapter.GetProfile(ctx, opts)
				if err == nil {
					t.Error("GetProfile should return error for non-existent profile")
				}
			})

			t.Run("GetTemplate_NotFound", func(t *testing.T) {
				opts := GetTemplateOptions{
					TenantID:   DefaultTenantID(),
					TemplateID: "999999999",
				}

				_, err := adapter.GetTemplate(ctx, opts)
				surface.RequireImplemented(t, err)
				if err == nil {
					t.Error("GetTemplate should return error for non-existent template")
				}
			})

			t.Run("RegisterDevice_DuplicateSerial", func(t *testing.T) {
				testID := uuid.New().String()[:8]
				serial := GenerateTestSerial(testID + "-dup")

				// Register first device
				opts := RegisterDeviceOptions{
					TenantID: DefaultTenantID(),
					Serial:   serial,
					Model:    "test-model-dup1",
				}

				_, err := adapter.RegisterDevice(ctx, opts)
				if err != nil {
					surface.RequireImplemented(t, err)
					t.Fatalf("First RegisterDevice failed: %v", err)
				}

				// Try to register second device with same serial
				opts.Model = "test-model-dup2"
				_, err = adapter.RegisterDevice(ctx, opts)
				if err == nil {
					t.Error("RegisterDevice should fail for duplicate serial")
				}
			})
		})
	}
}

// ============================================================================
// Protocol-Specific Tests
// ============================================================================

func TestDeviceCLI(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewCLIAdapter()
	helpers.RequireAdapterSetup(t, "device", "CLI", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testDeviceCRUD(t, ctx, adapter)
}

func TestDeviceREST(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewRESTAdapter()
	helpers.RequireAdapterSetup(t, "device", "REST", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testDeviceCRUD(t, ctx, adapter)
}

func TestDeviceGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewGRPCAdapter()
	helpers.RequireAdapterSetup(t, "device", "gRPC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testDeviceCRUD(t, ctx, adapter)
}

func TestDeviceQUIC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewQUICAdapter()
	helpers.RequireAdapterSetup(t, "device", "QUIC", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testDeviceCRUD(t, ctx, adapter)
}

func TestDeviceMCP(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewMCPAdapter()
	helpers.RequireAdapterSetup(t, "device", "MCP", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testDeviceCRUD(t, ctx, adapter)
}

func TestDeviceUnix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	adapter := NewUnixAdapter()
	helpers.RequireAdapterSetup(t, "device", "Unix", adapter.Setup(ctx))
	defer func() {
		_ = adapter.Teardown(ctx)
	}()

	testDeviceCRUD(t, ctx, adapter)
}
