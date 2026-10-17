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

package quicwire

// Device profile assignment sub-opcodes, multiplexed under
// OpProvisioningCategory (0xCF) because the single-byte opcode space is
// fully allocated (same precedent as the EAB sub-range 0x10-0x1A). The
// first byte of the request payload is the sub-opcode; the remaining
// bytes are the msgpack-encoded platform.v1 request message. Sub-range
// 0x20-0x2F is reserved for device profile operations.
//
// Server dispatcher: pkg/api/daemon/quic_device_handlers.go
// (handleDeviceProfileCategorySub). SDK routing:
// sdk/go/transport/quic/adapter.go (categorySubOpcodeMap).
const (
	// DeviceProfileSubAssign binds a profile to a device identity (EK
	// serial and/or MAC address) and optionally prestages the device's
	// PEM-encoded EK certificate. Request/response:
	// platform.v1 AssignProfileToDeviceRequest/Response.
	DeviceProfileSubAssign byte = 0x20

	// DeviceProfileSubUnassign clears a profile's device binding.
	// Request/response: platform.v1
	// UnassignProfileFromDeviceRequest/Response.
	DeviceProfileSubUnassign byte = 0x21

	// DeviceSubRecordAttestCert records (or re-records) a device's
	// attestation certificate on its platform record without re-enrolling
	// the device: DeviceService.RecordAttestationCertificate. Payload after
	// the sub-opcode byte is the encoded RecordAttestationCertificateRequest.
	DeviceSubRecordAttestCert byte = 0x22

	// DeviceSubBootCertificate returns a diskless node's recorded IDevID
	// chain to the node that proves it holds the key:
	// DeviceService.BootCertificate. Payload after the sub-opcode byte is the
	// encoded BootCertificateRequest. The node holds no platform token, so
	// the auth middleware lets this sub-opcode through (see the pre-auth
	// catalog in pkg/api/quic); the boot service authenticates the
	// request itself, bound to this connection's TLS exporter value.
	DeviceSubBootCertificate byte = 0x23

	// DeviceSubBootDelivery returns a verified diskless node's profile and CA
	// bundle: DeviceService.BootDelivery. Payload after the sub-opcode byte is
	// the encoded BootDeliveryRequest. Like DeviceSubBootCertificate it
	// carries no token; the node's client certificate and quote, both bound
	// to this connection, are its credential.
	DeviceSubBootDelivery byte = 0x24

	// DeviceSubDisable is the operator Disable Device:
	// DeviceService.DisableDevice. Payload after the sub-opcode byte is the
	// encoded DisableDeviceRequest; the response is DeviceLifecycleResponse.
	DeviceSubDisable byte = 0x25

	// DeviceSubEnable is the operator Enable Device:
	// DeviceService.EnableDevice. Payload after the sub-opcode byte is the
	// encoded EnableDeviceRequest; the response is DeviceLifecycleResponse.
	DeviceSubEnable byte = 0x26

	// DeviceSubTemplateCreate stores a device template:
	// DeviceService.CreateTemplate. Request/response: platform.v1
	// DeviceTemplateCreateRequest/Response.
	DeviceSubTemplateCreate byte = 0x27

	// DeviceSubProfileFromTemplate builds and saves a profile from a stored
	// device template: DeviceService.CreateProfileFromTemplate.
	// Request/response: platform.v1 CreateProfileFromTemplateRequest/
	// CreateProfileResponse.
	DeviceSubProfileFromTemplate byte = 0x28

	// DeviceSubFindMatchingProfile finds the profile whose match rules fit a
	// device's MAC, serial or model: DeviceService.FindMatchingProfile.
	// Request/response: platform.v1 FindMatchingProfileRequest/
	// FindMatchingProfileResponse.
	DeviceSubFindMatchingProfile byte = 0x29

	// DeviceSubTemplateGet reads a device template: DeviceService.GetTemplate.
	// Request/response: platform.v1 DeviceTemplateGetRequest/Response.
	DeviceSubTemplateGet byte = 0x2A

	// DeviceSubTemplateList pages the device templates:
	// DeviceService.ListTemplates. Request/response: platform.v1
	// DeviceTemplateListRequest/Response.
	DeviceSubTemplateList byte = 0x2B

	// DeviceSubTemplateUpdate replaces a device template:
	// DeviceService.UpdateTemplate. Request/response: platform.v1
	// DeviceTemplateUpdateRequest/Response.
	DeviceSubTemplateUpdate byte = 0x2C

	// DeviceSubTemplateDelete removes a device template:
	// DeviceService.DeleteTemplate. Request/response: platform.v1
	// DeviceTemplateDeleteRequest/Response.
	DeviceSubTemplateDelete byte = 0x2D

	// DeviceSubFindConfigForDevice finds the profile stored for a device's
	// EK serial or MAC address: DeviceService.FindConfigForDevice.
	// Request/response: platform.v1 FindConfigForDeviceRequest/Response.
	DeviceSubFindConfigForDevice byte = 0x2E
)
