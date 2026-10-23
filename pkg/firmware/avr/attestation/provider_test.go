// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// Dual-licensed under AGPL-3.0 or a commercial license.

package attestation

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"

	bmcattestation "github.com/jeremyhahn/go-trusted-platform/pkg/bmc/attestation"
)

func TestNew_AttachesToSecureElementDevice(t *testing.T) {
	link := secureElementLink()
	b := newTestBackend(t, link)

	if b.TenantID() != testTenant {
		t.Fatalf("tenant = %q, want %q", b.TenantID(), testTenant)
	}
	if got := b.Caps().CryptoTier; got != tfw.CryptoSecureElement {
		t.Fatalf("crypto tier = %v, want secure element", got)
	}
	if want := hex.EncodeToString(testSerial); b.elementSerial != want {
		t.Fatalf("element serial = %q, want %q", b.elementSerial, want)
	}
	// A secure-element device is asked for its element identity exactly
	// once, at construction: a backend that re-read it would have to invent
	// an answer whenever the device did not reply.
	if n := link.commandCount(tfw.CmdProvInfo); n != 1 {
		t.Fatalf("PROV_INFO round trips = %d, want 1", n)
	}
}

func TestNew_SoftwareDeviceIsNotAskedForAnElement(t *testing.T) {
	link := softwareLink()
	b := newTestBackend(t, link)

	if b.elementSerial != "" {
		t.Fatalf("element serial = %q, want empty on a software-tier device", b.elementSerial)
	}
	if n := link.commandCount(tfw.CmdProvInfo); n != 0 {
		t.Fatalf("PROV_INFO round trips = %d, want 0 on a device with no element", n)
	}
}

func TestNew_RefusesBadInput(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		device func() *tfw.Device
		want   error
	}{
		{
			name:   "nil config",
			config: nil,
			device: func() *tfw.Device { return newTestDevice(secureElementLink()) },
			want:   ErrNilConfig{},
		},
		{
			name:   "no tenant",
			config: &Config{RequestTimeout: linkTimeout},
			device: func() *tfw.Device { return newTestDevice(secureElementLink()) },
			want:   ErrInvalidTenant{},
		},
		{
			name:   "tenant with a path separator",
			config: &Config{TenantID: "acme/evil", RequestTimeout: linkTimeout},
			device: func() *tfw.Device { return newTestDevice(secureElementLink()) },
			want:   ErrInvalidTenant{},
		},
		{
			name:   "negative timeout",
			config: &Config{TenantID: testTenant, RequestTimeout: -time.Second},
			device: func() *tfw.Device { return newTestDevice(secureElementLink()) },
			want:   ErrInvalidConfig{},
		},
		{
			name:   "nil device",
			config: testConfig(frozenNow),
			device: func() *tfw.Device { return nil },
			want:   ErrNilDevice{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(context.Background(), tc.config, tc.device())
			if err == nil {
				t.Fatal("New succeeded, want a refusal")
			}
			if !sameErrorType(err, tc.want) {
				t.Fatalf("err = %T (%v), want %T", err, err, tc.want)
			}
		})
	}
}

func TestNew_RefusesDeviceWithoutAttestationCompiledIn(t *testing.T) {
	link := newFakeLink().answer(tfw.CmdCaps, capsPayload(
		tfw.CryptoSecureElement,
		tfw.FeatureGPIO, // no FeatureAttest
		tfw.AlgECDSAP256SHA256,
	))

	_, err := New(context.Background(), testConfig(frozenNow), newTestDevice(link))
	var want ErrAttestationNotCompiledIn
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrAttestationNotCompiledIn", err, err)
	}
	if want.CryptoTier != "secure-element" {
		t.Fatalf("crypto tier in error = %q", want.CryptoTier)
	}
	// The refusal happens before the element is touched.
	if n := link.commandCount(tfw.CmdProvInfo); n != 0 {
		t.Fatalf("PROV_INFO round trips = %d, want 0", n)
	}
}

func TestNew_RefusesDeviceThatWillNotSayWhatItIs(t *testing.T) {
	link := newFakeLink().refuse(tfw.CmdCaps, tfw.StatusErrInternal)

	_, err := New(context.Background(), testConfig(frozenNow), newTestDevice(link))
	var want bmcattestation.ErrAttestationFailed
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrAttestationFailed", err, err)
	}
	if want.Vendor != Vendor {
		t.Fatalf("vendor = %q, want %q", want.Vendor, Vendor)
	}
	if want.Unwrap() == nil {
		t.Fatal("ErrAttestationFailed lost the device's cause")
	}
}

func TestNew_RefusesSecureElementThatWillNotIdentifyItself(t *testing.T) {
	link := newFakeLink().
		answer(tfw.CmdCaps, capsPayload(
			tfw.CryptoSecureElement,
			tfw.FeatureAttest,
			tfw.AlgECDSAP256SHA256,
		)).
		refuse(tfw.CmdProvInfo, tfw.StatusErrInternal)

	_, err := New(context.Background(), testConfig(frozenNow), newTestDevice(link))
	var want bmcattestation.ErrAttestationFailed
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrAttestationFailed", err, err)
	}
}

func TestDump_RelaysTheDeviceBytesVerbatim(t *testing.T) {
	nonce := attestNonce(0x42)
	raw := defaultFrame(nonce)
	link := secureElementLink().answerAttest(raw)
	b := newTestBackend(t, link)

	ev, err := b.Dump(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if !bytes.Equal(ev.Raw, raw) {
		t.Fatal("Raw is not the bytes the device sent")
	}
	if ev.Vendor != Vendor || ev.Action != ActionDump {
		t.Fatalf("vendor/action = %q/%q", ev.Vendor, ev.Action)
	}
	if ev.Metadata[MetadataFormat] != FormatFrame {
		t.Fatalf("format = %q, want %q", ev.Metadata[MetadataFormat], FormatFrame)
	}
	if ev.Metadata[MetadataTenantID] != testTenant {
		t.Fatalf("tenant metadata = %q", ev.Metadata[MetadataTenantID])
	}
	if ev.Metadata[MetadataElementSerial] != hex.EncodeToString(testSerial) {
		t.Fatalf("element serial metadata = %q", ev.Metadata[MetadataElementSerial])
	}
	// CreatedAt is the GATEWAY's stamp, not anything the device said.
	if !ev.CreatedAt.Equal(frozenNow) {
		t.Fatalf("CreatedAt = %v, want the gateway clock %v", ev.CreatedAt, frozenNow)
	}
}

func TestDump_RecordsTheChallengeIssuedNotTheDevicesEcho(t *testing.T) {
	// A device that echoes a different nonce must not be able to rewrite
	// what it was asked. Evidence.Nonce is the host's record of the
	// challenge, and it is what a later echo check compares against.
	issued := attestNonce(0x42)
	echoed := attestNonce(0x99)
	link := secureElementLink().answerAttest(defaultFrame(echoed))
	b := newTestBackend(t, link)

	ev, err := b.Dump(context.Background(), issued)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if !bytes.Equal(ev.Nonce, issued) {
		t.Fatalf("Evidence.Nonce = %x, want the issued challenge %x", ev.Nonce, issued)
	}

	info, err := b.GetInfo(context.Background(), ev)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !bytes.Equal(info.NonceEcho, echoed) {
		t.Fatalf("NonceEcho = %x, want the device's echo %x", info.NonceEcho, echoed)
	}
}

func TestDump_RefusesTheWrongNonceWidthWithoutARoundTrip(t *testing.T) {
	link := secureElementLink().answerAttest(defaultFrame(attestNonce(1)))
	b := newTestBackend(t, link)
	before := link.commandCount(tfw.CmdAttest)

	for _, n := range [][]byte{nil, aliasNonce(1), make([]byte, 15)} {
		_, err := b.Dump(context.Background(), n)
		var want ErrNonceLength
		if !errors.As(err, &want) {
			t.Fatalf("nonce of %d bytes: err = %T (%v), want ErrNonceLength", len(n), err, err)
		}
		if want.Flow != "runtime" || want.Want != tfw.AttestNonceLen {
			t.Fatalf("error describes the wrong flow: %+v", want)
		}
	}
	if link.commandCount(tfw.CmdAttest) != before {
		t.Fatal("a refused nonce cost a device round trip")
	}
}

func TestDump_ReportsADeviceThatRefuses(t *testing.T) {
	link := secureElementLink().refuse(tfw.CmdAttest, tfw.StatusErrUnsupported)
	b := newTestBackend(t, link)

	_, err := b.Dump(context.Background(), attestNonce(1))
	var want bmcattestation.ErrAttestationFailed
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrAttestationFailed", err, err)
	}
	if want.Action != ActionDump {
		t.Fatalf("action = %q, want %q", want.Action, ActionDump)
	}
}

func TestAttestCert_RelaysTheCertificateVerbatim(t *testing.T) {
	der := aliasCertificate(t, true)
	nonce := aliasNonce(0x7F)
	link := secureElementLink().answerAttestCert(der)
	b := newTestBackend(t, link)

	ev, err := b.AttestCert(context.Background(), nonce)
	if err != nil {
		t.Fatalf("AttestCert: %v", err)
	}
	if !bytes.Equal(ev.Raw, der) {
		t.Fatal("Raw is not the DER the device minted")
	}
	if ev.Action != ActionAttestCert {
		t.Fatalf("action = %q, want %q", ev.Action, ActionAttestCert)
	}
	if ev.Metadata[MetadataFormat] != FormatDICE {
		t.Fatalf("format = %q, want %q", ev.Metadata[MetadataFormat], FormatDICE)
	}
	if !bytes.Equal(ev.Nonce, nonce) {
		t.Fatalf("Evidence.Nonce = %x, want %x", ev.Nonce, nonce)
	}
}

func TestAttestCert_RefusesTheWrongNonceWidthWithoutARoundTrip(t *testing.T) {
	link := secureElementLink().answerAttestCert(aliasCertificate(t, true))
	b := newTestBackend(t, link)

	// The runtime width is the one a caller is most likely to pass here by
	// mistake, and it must not reach the device: the two widths are
	// different on purpose.
	_, err := b.AttestCert(context.Background(), attestNonce(1))
	var want ErrNonceLength
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrNonceLength", err, err)
	}
	if want.Flow != "enrolment" || want.Want != tfw.AliasNonceLen {
		t.Fatalf("error describes the wrong flow: %+v", want)
	}
	if link.commandCount(tfw.CmdAttestCert) != 0 {
		t.Fatal("a refused nonce cost a device round trip")
	}
}

func TestAttestCert_ReportsADeviceWithNothingToCertify(t *testing.T) {
	// A software-tier build knows what a certificate is and has no public
	// half to put in one, so it answers unsupported.
	link := softwareLink().refuse(tfw.CmdAttestCert, tfw.StatusErrUnsupported)
	b := newTestBackend(t, link)

	_, err := b.AttestCert(context.Background(), aliasNonce(1))
	var want bmcattestation.ErrAttestationFailed
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrAttestationFailed", err, err)
	}
	if want.Action != ActionAttestCert {
		t.Fatalf("action = %q, want %q", want.Action, ActionAttestCert)
	}
}

func TestGetInfo_ParsesAnEvidenceFrame(t *testing.T) {
	nonce := attestNonce(0x42)
	link := secureElementLink().answerAttest(defaultFrame(nonce))
	b := newTestBackend(t, link)

	ev, err := b.Dump(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	info, err := b.GetInfo(context.Background(), ev)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	if !bytes.Equal(info.NonceEcho, nonce) {
		t.Fatalf("NonceEcho = %x", info.NonceEcho)
	}
	if !bytes.Equal(info.PCRBank[PCRApplication], goldenFWHash) {
		t.Fatalf("pcr[%d] = %x, want FWHash", PCRApplication, info.PCRBank[PCRApplication])
	}
	// The bootloader index is ABSENT, never zero-filled: a verifier must
	// be able to tell "not reported" from "reported as zeroes".
	if _, present := info.PCRBank[PCRBootloader]; present {
		t.Fatalf("pcr[%d] is present; the wire does not carry it", PCRBootloader)
	}
	if !info.CreatedAt.IsZero() {
		t.Fatal("Measurement.CreatedAt is set; the device supplied no time")
	}
	wantAttrs := map[string]string{
		AttrFrameVersion: strconv.Itoa(int(frameVersion)),
		AttrDeviceID:     hex.EncodeToString(testDeviceID),
		AttrBootCount:    "7",
		AttrUptimeMillis: "123456",
		AttrAlgorithm:    "1",
		AttrTenantID:     testTenant,
	}
	for k, want := range wantAttrs {
		if got := info.Attributes[k]; got != want {
			t.Errorf("attribute %s = %q, want %q", k, got, want)
		}
	}
}

func TestGetInfo_ParsedViewDoesNotAliasTheEvidence(t *testing.T) {
	// The containment property: a caller holding a Measurement must not be
	// able to reach back and change what the device is recorded as saying.
	nonce := attestNonce(0x42)
	link := secureElementLink().answerAttest(defaultFrame(nonce))
	b := newTestBackend(t, link)

	ev, err := b.Dump(context.Background(), nonce)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	before := append([]byte(nil), ev.Raw...)

	info, err := b.GetInfo(context.Background(), ev)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	for i := range info.PCRBank[PCRApplication] {
		info.PCRBank[PCRApplication][i] ^= 0xFF
	}
	for i := range info.NonceEcho {
		info.NonceEcho[i] ^= 0xFF
	}
	if !bytes.Equal(ev.Raw, before) {
		t.Fatal("mutating the measurement changed the evidence")
	}
}

func TestGetInfo_ParsesAnAliasCertificate(t *testing.T) {
	der := aliasCertificate(t, true)
	link := secureElementLink().answerAttestCert(der)
	b := newTestBackend(t, link)

	ev, err := b.AttestCert(context.Background(), aliasNonce(2))
	if err != nil {
		t.Fatalf("AttestCert: %v", err)
	}
	info, err := b.GetInfo(context.Background(), ev)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}

	if len(info.CertChain) != 1 {
		t.Fatalf("cert chain length = %d, want 1", len(info.CertChain))
	}
	if info.Attributes[AttrUCCSPresent] != "true" {
		t.Fatalf("uccs present = %q", info.Attributes[AttrUCCSPresent])
	}
	// The challenge lives inside the UCCS claims set, which this package
	// does not decode. Reporting an echo it had not read would be
	// reporting a check it had not performed.
	if info.NonceEcho != nil {
		t.Fatal("NonceEcho is set on certificate evidence; the claims set is not decoded here")
	}
	if len(info.PCRBank) != 0 {
		t.Fatal("PCRBank is populated from a certificate; the measurement is inside the claims set")
	}
}

func TestGetInfo_ReportsACertificateWithoutUCCSEvidence(t *testing.T) {
	der := aliasCertificate(t, false)
	link := secureElementLink().answerAttestCert(der)
	b := newTestBackend(t, link)

	ev, err := b.AttestCert(context.Background(), aliasNonce(2))
	if err != nil {
		t.Fatalf("AttestCert: %v", err)
	}
	info, err := b.GetInfo(context.Background(), ev)
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.Attributes[AttrUCCSPresent] != "false" {
		t.Fatalf("uccs present = %q, want false", info.Attributes[AttrUCCSPresent])
	}
}

func TestGetInfo_RefusesEvidenceItCannotTrust(t *testing.T) {
	b := newTestBackend(t, secureElementLink())
	good := func() *bmcattestation.Evidence {
		return &bmcattestation.Evidence{
			Vendor:   Vendor,
			Action:   ActionDump,
			Raw:      defaultFrame(attestNonce(1)),
			Metadata: map[string]string{MetadataTenantID: testTenant},
		}
	}

	tests := []struct {
		name     string
		evidence func() *bmcattestation.Evidence
		want     error
	}{
		{
			name:     "nil evidence",
			evidence: func() *bmcattestation.Evidence { return nil },
			want:     bmcattestation.ErrInvalidEvidence{},
		},
		{
			name: "another vendor",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Vendor = bmcattestation.VendorDell
				return ev
			},
			want: bmcattestation.ErrInvalidEvidence{},
		},
		{
			name: "another tenant",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Metadata[MetadataTenantID] = "globex"
				return ev
			},
			want: ErrTenantMismatch{},
		},
		{
			name: "no tenant at all",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Metadata = nil
				return ev
			},
			want: ErrTenantMismatch{},
		},
		{
			name: "an action this backend has no meaning for",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Action = bmcattestation.ActionList
				return ev
			},
			want: ErrUnsupportedAction{},
		},
		{
			name: "a truncated frame",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Raw = ev.Raw[:100]
				return ev
			},
			want: ErrEvidenceLength{},
		},
		{
			name: "a frame version this host does not parse",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Raw[offFrameVersion] = 99
				return ev
			},
			want: ErrEvidenceVersion{},
		},
		{
			name: "a certificate that does not parse",
			evidence: func() *bmcattestation.Evidence {
				ev := good()
				ev.Action = ActionAttestCert
				ev.Raw = []byte{0x30, 0x00, 0xFF}
				return ev
			},
			want: bmcattestation.ErrAttestationFailed{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := b.GetInfo(context.Background(), tc.evidence())
			if err == nil {
				t.Fatal("GetInfo succeeded, want a refusal")
			}
			if !sameErrorType(err, tc.want) {
				t.Fatalf("err = %T (%v), want %T", err, err, tc.want)
			}
		})
	}
}

func TestCompare_MatchesAGoldenBuild(t *testing.T) {
	// Two readings of the same healthy device differ in nonce, boot count
	// and uptime. A comparison that flagged those would report every
	// device as drifted.
	b := newTestBackend(t, secureElementLink())
	live := evidenceFor(buildFrame(frameOpts{
		version: frameVersion, nonce: attestNonce(1), deviceID: testDeviceID,
		fwHash: goldenFWHash, bootCount: 11, uptimeMs: 999, algorithm: 1,
	}))
	ref := evidenceFor(buildFrame(frameOpts{
		version: frameVersion, nonce: attestNonce(2), deviceID: testDeviceID,
		fwHash: goldenFWHash, bootCount: 3, uptimeMs: 1, algorithm: 1,
	}))

	got, err := b.Compare(context.Background(), live, ref)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if !got.Match {
		t.Fatalf("Match = false, differences = %+v", got.Differences)
	}
}

func TestCompare_ReportsADriftedApplicationMeasurement(t *testing.T) {
	b := newTestBackend(t, secureElementLink())
	drifted := bytes.Repeat([]byte{0xCD}, lenFrameFWHash)
	live := evidenceFor(buildFrame(frameOpts{
		version: frameVersion, nonce: attestNonce(1), deviceID: testDeviceID,
		fwHash: drifted, algorithm: 1,
	}))
	ref := evidenceFor(buildFrame(frameOpts{
		version: frameVersion, nonce: attestNonce(1), deviceID: testDeviceID,
		fwHash: goldenFWHash, algorithm: 1,
	}))

	got, err := b.Compare(context.Background(), live, ref)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if got.Match {
		t.Fatal("Match = true for a device running something else")
	}
	wantField := "pcr[" + strconv.FormatUint(uint64(PCRApplication), 10) + "]"
	found := false
	for _, d := range got.Differences {
		if d.Field == wantField {
			found = true
			if d.Live != hex.EncodeToString(drifted) || d.Ref != hex.EncodeToString(goldenFWHash) {
				t.Fatalf("difference does not name the measurements: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("differences do not name %s: %+v", wantField, got.Differences)
	}
}

func TestCompare_RefusesWhatItCannotCompare(t *testing.T) {
	b := newTestBackend(t, secureElementLink())
	frame := evidenceFor(defaultFrame(attestNonce(1)))
	cert := evidenceFor(aliasCertificate(t, true))
	cert.Action = ActionAttestCert

	if _, err := b.Compare(context.Background(), nil, frame); err == nil {
		t.Fatal("Compare accepted nil live evidence")
	}
	if _, err := b.Compare(context.Background(), frame, nil); err == nil {
		t.Fatal("Compare accepted nil reference evidence")
	}

	_, err := b.Compare(context.Background(), cert, cert)
	var want ErrUnsupportedCompare
	if !errors.As(err, &want) {
		t.Fatalf("err = %T (%v), want ErrUnsupportedCompare", err, err)
	}
}

func TestCompare_PropagatesAParseRefusal(t *testing.T) {
	b := newTestBackend(t, secureElementLink())
	good := evidenceFor(defaultFrame(attestNonce(1)))
	bad := evidenceFor(defaultFrame(attestNonce(1)))
	bad.Raw = bad.Raw[:10]

	if _, err := b.Compare(context.Background(), bad, good); err == nil {
		t.Fatal("Compare accepted a truncated live frame")
	}
	if _, err := b.Compare(context.Background(), good, bad); err == nil {
		t.Fatal("Compare accepted a truncated reference frame")
	}
}

func TestEvidenceStoreVerbsAreTerminallyUnsupported(t *testing.T) {
	// The device regenerates evidence per nonce and caches none. That is a
	// terminal condition, not a deferred implementation, so these must not
	// read as "not implemented yet".
	link := secureElementLink()
	b := newTestBackend(t, link)
	before := len(link.requests)

	var unsupported bmcattestation.ErrAttestationUnsupported

	if _, err := b.List(context.Background()); !errors.As(err, &unsupported) {
		t.Fatalf("List err = %T (%v)", err, err)
	}
	if _, err := b.Download(context.Background(), "any"); !errors.As(err, &unsupported) {
		t.Fatalf("Download err = %T (%v)", err, err)
	}
	if err := b.Delete(context.Background(), "any"); !errors.As(err, &unsupported) {
		t.Fatalf("Delete err = %T (%v)", err, err)
	}
	if unsupported.Vendor != Vendor {
		t.Fatalf("vendor = %q, want %q", unsupported.Vendor, Vendor)
	}
	if len(link.requests) != before {
		t.Fatal("a terminal refusal cost a device round trip")
	}
}

func TestTenantOf(t *testing.T) {
	if got := TenantOf(nil); got != "" {
		t.Fatalf("TenantOf(nil) = %q, want empty", got)
	}
	if got := TenantOf(&bmcattestation.Evidence{}); got != "" {
		t.Fatalf("TenantOf(bare evidence) = %q, want empty", got)
	}
	ev := &bmcattestation.Evidence{Metadata: map[string]string{MetadataTenantID: "globex"}}
	if got := TenantOf(ev); got != "globex" {
		t.Fatalf("TenantOf = %q, want globex", got)
	}
}

// evidenceFor wraps raw bytes as this tenant's evidence frame, for tests that
// exercise parsing without a device round trip.
func evidenceFor(raw []byte) *bmcattestation.Evidence {
	return &bmcattestation.Evidence{
		Vendor:    Vendor,
		Action:    ActionDump,
		Raw:       raw,
		CreatedAt: frozenNow,
		Metadata:  map[string]string{MetadataTenantID: testTenant},
	}
}

// sameErrorType reports whether err is, or wraps, an error of want's dynamic
// type. It exists so a table can name an expected error type in one field
// instead of each row declaring its own errors.As target.
func sameErrorType(err, want error) bool {
	wantType := reflect.TypeOf(want)
	for e := err; e != nil; {
		if reflect.TypeOf(e) == wantType {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
