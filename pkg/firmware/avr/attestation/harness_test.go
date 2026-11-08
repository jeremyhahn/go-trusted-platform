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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"io"
	"math/big"
	"testing"
	"time"

	tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"
)

// The tests in this package talk to a FAKE LINK and the REAL CODEC.
//
// Every byte a test sends is framed by the SDK's own EncodeResponse and every
// byte this package sends is parsed by the SDK's own Decode, so what is under
// test is this package against the protocol as trusted-firmware implements it.
// Mocking *tfw.Device instead would replace the one thing worth
// exercising — a reply's layout, a status code's meaning, the width a command
// needs — with this package's own opinion of it, and the tests would pass for
// a device that does not exist. The shape follows trusted-firmware's own
// cannedLink and go-xkms's pkg/backend/avr harness, which are the precedent.

// linkTimeout is the deadline these tests give the backend and the SDK. No
// exchange here ever waits on it: fakeLink queues its reply inside Write,
// before the SDK reads, and reports EOF once drained, so a test that goes
// wrong returns at once. What the deadline does measure is wall time — the
// backend's over a whole paged conversation, the SDK's between writing a
// command and decoding its reply — and a loaded CI runner under -race can
// stall a goroutine past any few milliseconds. A deadline short enough to
// matter would fail a correct exchange for the scheduler's sake, so this one
// sits far above any stall and only stops a test that has truly hung.
const linkTimeout = time.Minute

// testTenant is the tenant every backend in these tests is bound to.
const testTenant = "acme"

// reply is one canned response.
type reply struct {
	status  tfw.Status
	payload []byte
}

// fakeLink answers requests from a per-command table, framing each answer
// with the SDK's encoder and echoing the sequence number so the SDK accepts
// it.
//
// A command with no entry is answered with StatusErrUnknownCmd, which is what
// a firmware built without that feature actually does: the absence of a reply
// in the table models the absence of a handler in the image.
type fakeLink struct {
	replies map[tfw.Cmd]reply

	// pagedReplies answers successive requests for one command with
	// successive entries, which is how a paged command reads on the wire.
	pagedReplies map[tfw.Cmd][][]byte
	pageCursor   map[tfw.Cmd]int

	// requests records what this package asked for, so a test can assert
	// that a refusal cost no round trip.
	requests []tfw.Frame

	rx bytes.Buffer
}

func newFakeLink() *fakeLink {
	return &fakeLink{
		replies:      map[tfw.Cmd]reply{},
		pagedReplies: map[tfw.Cmd][][]byte{},
		pageCursor:   map[tfw.Cmd]int{},
	}
}

func (l *fakeLink) answer(cmd tfw.Cmd, payload []byte) *fakeLink {
	l.replies[cmd] = reply{payload: payload}
	return l
}

func (l *fakeLink) refuse(cmd tfw.Cmd, status tfw.Status) *fakeLink {
	l.replies[cmd] = reply{status: status}
	return l
}

// commandCount reports how many requests carried a given command.
func (l *fakeLink) commandCount(cmd tfw.Cmd) int {
	n := 0
	for _, f := range l.requests {
		if f.Cmd() == cmd {
			n++
		}
	}
	return n
}

func (l *fakeLink) Write(p []byte) (int, error) {
	f, _, err := tfw.Decode(p)
	if err != nil {
		return 0, err
	}
	l.requests = append(l.requests, f)

	r, ok := l.replies[f.Cmd()]
	if !ok {
		if pages, paged := l.pagedReplies[f.Cmd()]; paged {
			at := l.pageCursor[f.Cmd()]
			if at >= len(pages) {
				// Past the end the device answers a range error rather
				// than an empty success, so a host cannot loop forever.
				r = reply{status: tfw.StatusErrRange}
			} else {
				r = reply{payload: pages[at]}
				l.pageCursor[f.Cmd()] = at + 1
			}
		} else {
			r = reply{status: tfw.StatusErrUnknownCmd}
		}
	}
	resp, err := tfw.EncodeResponse(f.Seq, f.Cmd(), r.status, r.payload)
	if err != nil {
		return 0, err
	}
	l.rx.Write(resp)
	return len(p), nil
}

func (l *fakeLink) Read(p []byte) (int, error) {
	n, err := l.rx.Read(p)
	if err == io.EOF {
		// An exhausted buffer is a device that has stopped talking.
		// Reporting EOF makes the SDK give up at once instead of spinning
		// to its deadline, which keeps every negative test fast.
		return n, io.EOF
	}
	return n, err
}

// capsPayload builds the board header a current firmware sends, mirroring the
// layout in include/tfw/protocol.h: the fourteen-byte header every version has,
// then the algorithm bitmap appended after it.
func capsPayload(tier tfw.CryptoTier, features uint32, algorithms tfw.AlgorithmSet) []byte {
	p := make([]byte, 16)
	p[0], p[1] = tfw.ProtoVersionMajor, tfw.ProtoVersionMinor
	p[2], p[3], p[4] = 0, 2, 0
	p[5] = 0x01 // board id
	p[6] = 22   // pin count
	p[7] = 8    // scheduler slots
	p[8] = tfw.MaxPayload
	p[9] = byte(tier)
	binary.LittleEndian.PutUint32(p[10:14], features)
	binary.LittleEndian.PutUint16(p[14:16], uint16(algorithms))
	return p
}

// provInfoPayload builds a PROV_INFO reply: four revision bytes, config block
// 0, then the two lock bytes. The element splits its nine-byte serial across
// config bytes 0..3 and 8..12, which land at offsets 4 and 12 of the reply.
func provInfoPayload(serial []byte) []byte {
	p := make([]byte, 4+32+2)
	p[0], p[1], p[2], p[3] = 0x00, 0x00, 0x60, 0x02 // a 608-family revision
	copy(p[4:8], serial[0:4])
	copy(p[12:17], serial[4:9])
	p[36], p[37] = 0x00, 0x00 // both zones locked
	return p
}

// testSerial is the element serial every secure-element device in these tests
// reports.
var testSerial = []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01}

// frameOpts describes the evidence frame a fake device should return.
type frameOpts struct {
	version   uint8
	nonce     []byte
	deviceID  []byte
	fwHash    []byte
	bootCount uint32
	uptimeMs  uint32
	algorithm uint8
	signature []byte
}

// buildFrame renders a 164-byte evidence frame at the offsets
// include/tfw/protocol.h defines.
func buildFrame(o frameOpts) []byte {
	raw := make([]byte, tfw.EvidenceLen)
	raw[offFrameVersion] = o.version
	copy(raw[offFrameNonce:], o.nonce)
	copy(raw[offFrameDevice:offFrameDevice+lenFrameDeviceID], o.deviceID)
	copy(raw[offFrameFWHash:offFrameFWHash+lenFrameFWHash], o.fwHash)
	binary.LittleEndian.PutUint32(raw[offFrameBoot:offFrameBoot+4], o.bootCount)
	binary.LittleEndian.PutUint32(raw[offFrameUptime:offFrameUptime+4], o.uptimeMs)
	raw[offFrameAlg] = o.algorithm
	copy(raw[offFrameSig:offFrameEnd], o.signature)
	return raw
}

// goldenFWHash is the reproducible application measurement a healthy device
// reports in these tests.
var goldenFWHash = bytes.Repeat([]byte{0xAB}, lenFrameFWHash)

// testDeviceID is the identifier the trusted bootloader supplied.
var testDeviceID = bytes.Repeat([]byte{0x11}, lenFrameDeviceID)

// defaultFrame is a healthy device's answer to a challenge.
func defaultFrame(nonce []byte) []byte {
	return buildFrame(frameOpts{
		version:   frameVersion,
		nonce:     nonce,
		deviceID:  testDeviceID,
		fwHash:    goldenFWHash,
		bootCount: 7,
		uptimeMs:  123456,
		algorithm: 0x01, // TFW_ALG_ECDSA_P256_SHA256
		signature: bytes.Repeat([]byte{0x5A}, lenFrameSig),
	})
}

// answerAttest loads a whole evidence frame into the link, paged the way the
// device pages it: page 0 is the answer to the nonce, later pages answer a
// one-byte page request, and every page carries the [page:1][total:1] header
// src/caps/attest.c puts ahead of the evidence.
func (l *fakeLink) answerAttest(raw []byte) *fakeLink {
	const page = 48 // TFW_ATTEST_PAGE
	var pages [][]byte
	for off := 0; off < len(raw); off += page {
		end := off + page
		if end > len(raw) {
			end = len(raw)
		}
		hdr := make([]byte, 2, 2+end-off)
		hdr[0] = byte(off / page)
		hdr[1] = byte(len(raw))
		pages = append(pages, append(hdr, raw[off:end]...))
	}
	l.pagedReplies[tfw.CmdAttest] = pages
	return l
}

// answerAttestCert loads a whole certificate into the link, paged the way the
// device pages it: [page:1][total:2 little-endian][bytes].
func (l *fakeLink) answerAttestCert(der []byte) *fakeLink {
	const page = 60 // TFW_ALIAS_PAGE
	var pages [][]byte
	for off := 0; off < len(der); off += page {
		end := off + page
		if end > len(der) {
			end = len(der)
		}
		hdr := make([]byte, 3, 3+end-off)
		hdr[0] = byte(off / page)
		binary.LittleEndian.PutUint16(hdr[1:3], uint16(len(der)))
		pages = append(pages, append(hdr, der[off:end]...))
	}
	l.pagedReplies[tfw.CmdAttestCert] = pages
	return l
}

// secureElementLink is the ordinary device these tests are written against: a
// secure element with attestation compiled in, ECDSA P-256 and HMAC-SHA256
// and — as the ATECC608A really is — no Ed25519.
func secureElementLink() *fakeLink {
	return newFakeLink().
		answer(tfw.CmdCaps, capsPayload(
			tfw.CryptoSecureElement,
			tfw.FeatureGPIO|tfw.FeatureAttest,
			tfw.AlgECDSAP256SHA256|tfw.AlgHMACSHA256,
		)).
		answer(tfw.CmdProvInfo, provInfoPayload(testSerial))
}

// softwareLink is a software-tier device with attestation compiled in. It has
// no element, so construction asks it nothing about one.
func softwareLink() *fakeLink {
	return newFakeLink().answer(tfw.CmdCaps, capsPayload(
		tfw.CryptoSoftware,
		tfw.FeatureGPIO|tfw.FeatureAttest,
		tfw.AlgECDSAP256SHA256,
	))
}

// newTestDevice wraps a link in an SDK Device with the tests' deadline; see
// linkTimeout for why it cannot expire on a correct exchange.
func newTestDevice(link io.ReadWriter) *tfw.Device {
	return tfw.New(link, tfw.WithTimeout(linkTimeout), tfw.WithBootWait(0))
}

// testConfig is a valid configuration with a frozen clock, so the age rule is
// deterministic.
func testConfig(now time.Time) *Config {
	return &Config{
		TenantID:       testTenant,
		DeviceRef:      "usb0",
		Platform:       "avr-dev-board",
		RequestTimeout: linkTimeout,
		Clock:          func() time.Time { return now },
	}
}

// frozenNow is the instant every test's clock reports unless it says
// otherwise.
var frozenNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// newTestBackend attaches a backend to a link, failing the test when it
// cannot.
func newTestBackend(t *testing.T, link *fakeLink) *Backend {
	t.Helper()
	b, err := New(context.Background(), testConfig(frozenNow), newTestDevice(link))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return b
}

// aliasCertificate mints a certificate shaped like the device's: P-256,
// ecdsa-with-SHA256, and a critical tcg-dice-UCCS-evidence extension. The
// bytes inside the extension are not decoded by this package, so an opaque
// placeholder is exactly as much as the test needs and no less real.
func aliasCertificate(t *testing.T, withUCCS bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x4142434445464748),
		Subject:      pkix.Name{CommonName: "ag Alias"},
		Issuer:       pkix.Name{CommonName: "ag DeviceID"},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
	}
	if withUCCS {
		uccs, err := asn1.Marshal([]byte{0xA1, 0x0A, 0x58, 0x20})
		if err != nil {
			t.Fatalf("marshal uccs: %v", err)
		}
		tmpl.ExtraExtensions = []pkix.Extension{{
			Id:       oidUCCSEvidence,
			Critical: true,
			Value:    uccs,
		}}
	}
	// The issuer name comes from a parent template, because the device's
	// alias certificate names an issuer whose key it does not hold: the
	// DeviceID certificate is issued off-device at provisioning.
	parent := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ag DeviceID"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return der
}

// attestNonce and aliasNonce are challenges of the two widths.
func attestNonce(fill byte) []byte { return bytes.Repeat([]byte{fill}, tfw.AttestNonceLen) }
func aliasNonce(fill byte) []byte  { return bytes.Repeat([]byte{fill}, tfw.AliasNonceLen) }
