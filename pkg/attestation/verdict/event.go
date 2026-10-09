// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// SPDX-License-Identifier: AGPL-3.0-or-later

package verdict

import "strconv"

// EventSource is the `source` of the platform event platformd raises for
// every recorded device verdict. Relying parties outside platformd, such as
// the overlay gateways, follow verdicts by streaming the platform events and
// keeping those from this source.
const EventSource = "attestation.device-verdict"

// Metadata keys of a device verdict event.
const (
	eventKeyDeviceID      = "device_id"
	eventKeyHostID        = "host_id"
	eventKeySerial        = "serial"
	eventKeyPassed        = "passed"
	eventKeyCryptographic = "cryptographic"
	eventKeyReason        = "reason"
)

// ErrMalformedVerdictEvent reports a device verdict event whose metadata
// cannot be read back as a verdict.
type ErrMalformedVerdictEvent struct {
	Key   string
	Value string
}

// Error names the metadata key that could not be read and its value.
func (e ErrMalformedVerdictEvent) Error() string {
	return "verdict: malformed device verdict event: " + e.Key + "=" + strconv.Quote(e.Value)
}

// EventMetadata renders the outcome of v as the metadata of its platform
// event: the device, whether it passed, the failure class and reason. The
// baseline fields stay in the attestation event log.
func EventMetadata(v DeviceVerdict) map[string]string {
	return map[string]string{
		eventKeyDeviceID:      strconv.FormatUint(v.DeviceID, 10),
		eventKeyHostID:        v.HostID,
		eventKeySerial:        v.Serial,
		eventKeyPassed:        strconv.FormatBool(v.Passed),
		eventKeyCryptographic: strconv.FormatBool(v.Cryptographic),
		eventKeyReason:        v.Reason,
	}
}

// FromEventMetadata reads back the verdict EventMetadata rendered. Metadata
// that does not hold a consistent verdict is refused.
func FromEventMetadata(meta map[string]string) (DeviceVerdict, error) {
	deviceID, err := strconv.ParseUint(meta[eventKeyDeviceID], 10, 64)
	if err != nil {
		return DeviceVerdict{}, ErrMalformedVerdictEvent{Key: eventKeyDeviceID, Value: meta[eventKeyDeviceID]}
	}
	passed, err := strconv.ParseBool(meta[eventKeyPassed])
	if err != nil {
		return DeviceVerdict{}, ErrMalformedVerdictEvent{Key: eventKeyPassed, Value: meta[eventKeyPassed]}
	}
	cryptographic, err := strconv.ParseBool(meta[eventKeyCryptographic])
	if err != nil {
		return DeviceVerdict{}, ErrMalformedVerdictEvent{Key: eventKeyCryptographic, Value: meta[eventKeyCryptographic]}
	}
	v := DeviceVerdict{
		DeviceID:      deviceID,
		HostID:        meta[eventKeyHostID],
		Serial:        meta[eventKeySerial],
		Passed:        passed,
		Cryptographic: cryptographic,
		Reason:        meta[eventKeyReason],
	}
	if err := v.Validate(); err != nil {
		return DeviceVerdict{}, err
	}
	return v, nil
}
