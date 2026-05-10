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

package backends

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	libtpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// LUKS TPM handler errors.

// ErrLUKSTPMNoTransport indicates no TPMOpener could be resolved — the host
// has no /dev/tpmrm0 and no simulator was injected.
var ErrLUKSTPMNoTransport = errors.New("luks tpm handler: no tpm transport available")

// ErrLUKSTPMPolicyFailed indicates the PCR policy digest could not be
// computed. This is typically a bug in the requested PCR selection.
var ErrLUKSTPMPolicyFailed = errors.New("luks tpm handler: pcr policy digest failed")

// ErrLUKSTPMSealFailed indicates the underlying TPM2_Create seal command
// returned an error.
var ErrLUKSTPMSealFailed = errors.New("luks tpm handler: seal failed")

// ErrLUKSTPMUnsealFailed indicates the TPM2_Unseal command returned an error
// (most commonly because current PCR state does not match the policy).
var ErrLUKSTPMUnsealFailed = errors.New("luks tpm handler: unseal failed")

// ErrLUKSTPMInvalidHandle indicates the requested persistent handle string
// could not be parsed as a uint32.
var ErrLUKSTPMInvalidHandle = errors.New("luks tpm handler: invalid tpm handle")

// ErrLUKSTPMInvalidToken indicates the TPM LUKS token JSON could not be
// parsed.
var ErrLUKSTPMInvalidToken = errors.New("luks tpm handler: invalid token payload")

// LUKSTPMTokenType is the LUKS2 token type we write for TPM-sealed slots.
// Matches the value already routed by luksKeySlotTypeMap.
const LUKSTPMTokenType = "systemd-tpm2"

// Default persistent handle used for the sealing parent when none is given
// in the enrol request. 0x81000001 is the storage SRK defined in the TCG PC
// Client Platform spec, matching what firstboot uses (see
// pkg/firstboot/strategy.go:getSSRKHandle).
const defaultLUKSTPMParentHandle uint32 = 0x81000001

// TPMOpener opens a go-tpm transport for a sealing / unsealing operation.
// The default implementation wraps linuxtpm.Open; tests inject an adapter
// around go-tpm-tools/simulator.
type TPMOpener interface {
	Open(ctx context.Context) (transport.TPMCloser, error)
}

// TPMOpenerFunc adapts a function to the TPMOpener interface.
type TPMOpenerFunc func(ctx context.Context) (transport.TPMCloser, error)

// Open invokes the underlying function.
func (f TPMOpenerFunc) Open(ctx context.Context) (transport.TPMCloser, error) { return f(ctx) }

// DefaultTPMOpener returns a TPMOpener that opens /dev/tpmrm0 on Linux.
// If the TPM device is missing the opener returns ErrLUKSTPMNoTransport so
// callers can downgrade cleanly to a "not wired" failure mode.
func DefaultTPMOpener() TPMOpener {
	return TPMOpenerFunc(func(ctx context.Context) (transport.TPMCloser, error) {
		tpm, err := linuxtpm.Open("/dev/tpmrm0")
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrLUKSTPMNoTransport, err)
		}
		return tpm, nil
	})
}

// tpmLUKSToken is the JSON payload written into the LUKS2 token for a
// TPM-sealed keyslot. Field names are stable with systemd-cryptsetup's
// "systemd-tpm2" token so third parties can still parse the slot.
type tpmLUKSToken struct {
	Type         string   `json:"type"`
	Keyslots     []string `json:"keyslots"`
	TPM2Blob     string   `json:"tpm2-blob"` // base64: public || '|' || private
	TPM2PCRBank  string   `json:"tpm2-pcr-bank"`
	TPM2PCRs     []int    `json:"tpm2-pcrs"`
	TPM2Handle   uint64   `json:"tpm2-key-handle"`
	TPM2PolicyHA string   `json:"tpm2-policy-hash,omitempty"` // base64
}

// LUKSTPMSealResult is the richer enrol output: passphrase bytes and the
// token payload to persist in the LUKS2 header.
type LUKSTPMSealResult struct {
	Passphrase   []byte
	TokenJSON    []byte
	PublicBlob   []byte
	PrivateBlob  []byte
	PolicyDigest []byte
}

// luksTPMHandler implements LUKSTPMHandler by driving go-tpm directly.
// Every Seal opens a fresh transport, performs CreatePrimary + Create, and
// closes. This keeps the handler stateless and safe to reuse across
// goroutines.
type luksTPMHandler struct {
	logger *logging.Logger
	opener TPMOpener
	// parentHandle is the persistent TPM handle used as the sealing parent.
	// When zero the default is defaultLUKSTPMParentHandle.
	parentHandle uint32
	// pcrBank is the PCR hash algorithm to bind the policy to. When zero
	// defaults to SHA-256.
	pcrBank libtpm2.TPMAlgID
}

// Compile-time assertion.
var _ LUKSTPMHandler = (*luksTPMHandler)(nil)

// NewLUKSTPMHandler constructs a TPM-backed LUKS handler. Passing a nil
// opener returns an error so callers can fall back to leaving the backend's
// TPM handler unset (ErrLUKSTPMNotWired path).
func NewLUKSTPMHandler(logger *logging.Logger, opener TPMOpener) (*luksTPMHandler, error) {
	if opener == nil {
		return nil, ErrLUKSTPMNoTransport
	}
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &luksTPMHandler{
		logger:       logger,
		opener:       opener,
		parentHandle: defaultLUKSTPMParentHandle,
		pcrBank:      libtpm2.TPMAlgSHA256,
	}, nil
}

// WithParentHandle overrides the persistent TPM handle used as the sealing
// parent. Zero resets to the default (0x81000001).
func (h *luksTPMHandler) WithParentHandle(handle uint32) *luksTPMHandler {
	h.parentHandle = handle
	if h.parentHandle == 0 {
		h.parentHandle = defaultLUKSTPMParentHandle
	}
	return h
}

// Seal satisfies the LUKSTPMHandler interface. It generates a random 32-byte
// passphrase, seals it to the TPM under the configured parent handle with a
// PCR policy bound to the supplied PCRs, and returns the passphrase plus a
// JSON token payload containing the sealed blobs.
func (h *luksTPMHandler) Seal(ctx context.Context, handle string, pcrs []int32) ([]byte, []byte, error) {
	res, err := h.SealPassphrase(ctx, handle, pcrs)
	if err != nil {
		return nil, nil, err
	}
	return res.Passphrase, res.TokenJSON, nil
}

// SealPassphrase is the richer API used internally by the LUKS backend and
// tests. It returns the raw sealed blobs + policy digest alongside the
// passphrase and token JSON.
func (h *luksTPMHandler) SealPassphrase(ctx context.Context, handle string, pcrs []int32) (*LUKSTPMSealResult, error) {
	parent, err := resolveParentHandle(handle, h.parentHandle)
	if err != nil {
		return nil, err
	}

	// 32 random bytes are sealed as the LUKS passphrase.
	passphrase := make([]byte, 32)
	if _, err := rand.Read(passphrase); err != nil {
		return nil, fmt.Errorf("%w: rand: %v", ErrLUKSTPMSealFailed, err)
	}

	tpm, err := h.opener.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer closeTPMIgnore(tpm)

	// Build PCR selection + policy digest. When no PCRs are requested we
	// still compute an empty policy so the sealed object has an auth policy
	// (keyed-hash objects without policy require userAuth, which we don't
	// want for LUKS).
	pcrSel := buildPCRSelection(h.pcrBank, pcrs)
	policyDigest, err := computePCRPolicyDigest(tpm, pcrSel)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLUKSTPMPolicyFailed, err)
	}

	// Seal as a keyed-hash object under the parent SRK.
	pub := libtpm2.New2B(libtpm2.TPMTPublic{
		Type:    libtpm2.TPMAlgKeyedHash,
		NameAlg: libtpm2.TPMAlgSHA256,
		ObjectAttributes: libtpm2.TPMAObject{
			FixedTPM:        true,
			FixedParent:     true,
			AdminWithPolicy: true,
			NoDA:            true,
		},
		AuthPolicy: libtpm2.TPM2BDigest{Buffer: policyDigest},
		Parameters: libtpm2.NewTPMUPublicParms(
			libtpm2.TPMAlgKeyedHash,
			&libtpm2.TPMSKeyedHashParms{
				Scheme: libtpm2.TPMTKeyedHashScheme{
					Scheme: libtpm2.TPMAlgNull,
				},
			},
		),
	})
	sensitive := libtpm2.TPM2BSensitiveCreate{
		Sensitive: &libtpm2.TPMSSensitiveCreate{
			Data: libtpm2.NewTPMUSensitiveCreate(&libtpm2.TPM2BSensitiveData{
				Buffer: passphrase,
			}),
		},
	}

	createRsp, err := (libtpm2.Create{
		ParentHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(parent),
			Auth:   libtpm2.PasswordAuth(nil),
		},
		InSensitive: sensitive,
		InPublic:    pub,
	}).Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLUKSTPMSealFailed, err)
	}

	token := &tpmLUKSToken{
		Type:         LUKSTPMTokenType,
		TPM2Blob:     encodeSealBlobs(createRsp.OutPublic.Bytes(), createRsp.OutPrivate.Buffer),
		TPM2PCRBank:  pcrBankName(h.pcrBank),
		TPM2PCRs:     int32sToInts(pcrs),
		TPM2Handle:   uint64(parent),
		TPM2PolicyHA: base64.StdEncoding.EncodeToString(policyDigest),
	}
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal token: %v", ErrLUKSTPMSealFailed, err)
	}

	return &LUKSTPMSealResult{
		Passphrase:   passphrase,
		TokenJSON:    tokenJSON,
		PublicBlob:   createRsp.OutPublic.Bytes(),
		PrivateBlob:  createRsp.OutPrivate.Buffer,
		PolicyDigest: policyDigest,
	}, nil
}

// UnsealPassphrase reads a TPM LUKS2 token and unseals the passphrase. Used
// by the unlock path — the enroll path receives the passphrase from
// SealPassphrase directly.
func (h *luksTPMHandler) UnsealPassphrase(ctx context.Context, tokenJSON []byte) ([]byte, error) {
	var token tpmLUKSToken
	if err := json.Unmarshal(tokenJSON, &token); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLUKSTPMInvalidToken, err)
	}
	publicBlob, privateBlob, err := decodeSealBlobs(token.TPM2Blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLUKSTPMInvalidToken, err)
	}
	parent := uint32(token.TPM2Handle)
	if parent == 0 {
		parent = h.parentHandle
	}

	tpm, err := h.opener.Open(ctx)
	if err != nil {
		return nil, err
	}
	defer closeTPMIgnore(tpm)

	// Load the sealed object back under the parent.
	pub, err := libtpm2.Unmarshal[libtpm2.TPM2BPublic](publicBlob)
	if err != nil {
		return nil, fmt.Errorf("%w: unmarshal public: %v", ErrLUKSTPMUnsealFailed, err)
	}
	loadRsp, err := (libtpm2.Load{
		ParentHandle: libtpm2.AuthHandle{
			Handle: libtpm2.TPMHandle(parent),
			Auth:   libtpm2.PasswordAuth(nil),
		},
		InPrivate: libtpm2.TPM2BPrivate{Buffer: privateBlob},
		InPublic:  *pub,
	}).Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: load: %v", ErrLUKSTPMUnsealFailed, err)
	}
	defer flushContext(tpm, loadRsp.ObjectHandle)

	// Start a PCR policy session matching the PCRs recorded in the token.
	pcrSel := buildPCRSelection(h.pcrBank, intsToInt32s(token.TPM2PCRs))
	policySession, policyCloser, err := libtpm2.PolicySession(tpm, libtpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("%w: policy session: %v", ErrLUKSTPMUnsealFailed, err)
	}
	defer func() { _ = policyCloser() }()

	if _, err := (libtpm2.PolicyPCR{
		PolicySession: policySession.Handle(),
		Pcrs:          pcrSel,
	}).Execute(tpm); err != nil {
		return nil, fmt.Errorf("%w: policy pcr: %v", ErrLUKSTPMUnsealFailed, err)
	}

	unsealRsp, err := (libtpm2.Unseal{
		ItemHandle: libtpm2.AuthHandle{
			Handle: loadRsp.ObjectHandle,
			Name:   loadRsp.Name,
			Auth:   policySession,
		},
	}).Execute(tpm)
	if err != nil {
		return nil, fmt.Errorf("%w: unseal: %v", ErrLUKSTPMUnsealFailed, err)
	}
	return unsealRsp.OutData.Buffer, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resolveParentHandle parses the request-supplied handle string, falling
// back to the handler default when empty. Accepts decimal or 0x-prefixed
// hex.
func resolveParentHandle(requested string, fallback uint32) (uint32, error) {
	if requested == "" {
		return fallback, nil
	}
	s := strings.TrimSpace(requested)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		// Accept decimal as a fallback.
		if dv, derr := strconv.ParseUint(strings.TrimSpace(requested), 10, 32); derr == nil {
			return uint32(dv), nil
		}
		return 0, fmt.Errorf("%w: %q", ErrLUKSTPMInvalidHandle, requested)
	}
	return uint32(v), nil
}

// buildPCRSelection converts a slice of PCR indexes into a TPMLPCRSelection
// for the requested bank. An empty slice yields an empty selection (valid —
// produces a trivial policy).
func buildPCRSelection(bank libtpm2.TPMAlgID, pcrs []int32) libtpm2.TPMLPCRSelection {
	if len(pcrs) == 0 {
		return libtpm2.TPMLPCRSelection{
			PCRSelections: []libtpm2.TPMSPCRSelection{{
				Hash:      bank,
				PCRSelect: make([]byte, 3),
			}},
		}
	}
	sel := make([]byte, 3)
	for _, p := range pcrs {
		if p < 0 || p > 23 {
			continue
		}
		sel[p/8] |= 1 << (uint(p) % 8)
	}
	return libtpm2.TPMLPCRSelection{
		PCRSelections: []libtpm2.TPMSPCRSelection{{
			Hash:      bank,
			PCRSelect: sel,
		}},
	}
}

// computePCRPolicyDigest runs a trial session + PolicyPCR to derive the
// policy digest for the given selection. Uses a trial session so the TPM
// computes the digest deterministically without requiring a live
// authentication.
func computePCRPolicyDigest(tpm transport.TPM, pcrSel libtpm2.TPMLPCRSelection) ([]byte, error) {
	trialSession, cleanup, err := libtpm2.PolicySession(tpm, libtpm2.TPMAlgSHA256, 16, libtpm2.Trial())
	if err != nil {
		return nil, err
	}
	defer func() { _ = cleanup() }()

	if _, err := (libtpm2.PolicyPCR{
		PolicySession: trialSession.Handle(),
		Pcrs:          pcrSel,
	}).Execute(tpm); err != nil {
		return nil, err
	}

	getDigest, err := (libtpm2.PolicyGetDigest{
		PolicySession: trialSession.Handle(),
	}).Execute(tpm)
	if err != nil {
		return nil, err
	}
	return getDigest.PolicyDigest.Buffer, nil
}

// pcrBankName returns the string representation of a PCR bank suitable for
// the LUKS2 token.
func pcrBankName(alg libtpm2.TPMAlgID) string {
	switch alg {
	case libtpm2.TPMAlgSHA256:
		return "sha256"
	case libtpm2.TPMAlgSHA384:
		return "sha384"
	case libtpm2.TPMAlgSHA512:
		return "sha512"
	case libtpm2.TPMAlgSHA1:
		return "sha1"
	}
	return "sha256"
}

// int32sToInts converts []int32 to []int for JSON encoding.
func int32sToInts(src []int32) []int {
	out := make([]int, len(src))
	for i, v := range src {
		out[i] = int(v)
	}
	return out
}

// intsToInt32s converts []int back to []int32.
func intsToInt32s(src []int) []int32 {
	out := make([]int32, len(src))
	for i, v := range src {
		out[i] = int32(v)
	}
	return out
}

// encodeSealBlobs packs the public and private portions of a sealed object
// into a single base64 string with a length-prefix separator so we can
// transport both halves in a single token field without an extra schema.
//
// Wire format:
//
//	base64( uint32BE(len(public)) | public | private )
func encodeSealBlobs(public, private []byte) string {
	buf := make([]byte, 4+len(public)+len(private))
	pl := len(public)
	buf[0] = byte(pl >> 24)
	buf[1] = byte(pl >> 16)
	buf[2] = byte(pl >> 8)
	buf[3] = byte(pl)
	copy(buf[4:], public)
	copy(buf[4+pl:], private)
	return base64.StdEncoding.EncodeToString(buf)
}

// decodeSealBlobs reverses encodeSealBlobs.
func decodeSealBlobs(s string) ([]byte, []byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, nil, err
	}
	if len(raw) < 4 {
		return nil, nil, errors.New("tpm2-blob too short")
	}
	pl := int(raw[0])<<24 | int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if pl < 0 || 4+pl > len(raw) {
		return nil, nil, errors.New("tpm2-blob length mismatch")
	}
	return raw[4 : 4+pl], raw[4+pl:], nil
}

// flushContext releases a transient TPM object handle. Errors are logged
// (noisy TPMs) but never surfaced — the caller already has their result.
func flushContext(tpm transport.TPM, handle libtpm2.TPMHandle) {
	_, _ = (libtpm2.FlushContext{FlushHandle: handle}).Execute(tpm)
}

// closeTPMIgnore closes the transport and swallows the error. The caller
// has already extracted everything of value from the transport.
func closeTPMIgnore(c io.Closer) {
	if c != nil {
		_ = c.Close()
	}
}
