package measure

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// TagSignedCoRIM is the CBOR tag of a signed-corim: a COSE_Sign1 (RFC 9052).
const TagSignedCoRIM = 18

// ManifestContentType is the COSE content type of a signed manifest's
// payload, a tagged-unsigned-corim-map.
const ManifestContentType = "application/rim+cbor"

// The COSE algorithms (RFC 9053 §2.1, RFC 8230 §2) a manifest can be signed
// with. The algorithm follows the signing key: an ECDSA P-256, P-384 or P-521
// key signs ES256, ES384 or ES512, an RSA key of 2048 bits or more PS256.
const (
	AlgES256 = -7
	AlgES384 = -35
	AlgES512 = -36
	AlgPS256 = -37
)

// coseAlgs is what each algorithm hashes with and, for ECDSA, its curve.
var coseAlgs = map[int64]struct {
	hash  crypto.Hash
	curve elliptic.Curve
}{
	AlgES256: {crypto.SHA256, elliptic.P256()},
	AlgES384: {crypto.SHA384, elliptic.P384()},
	AlgES512: {crypto.SHA512, elliptic.P521()},
	AlgPS256: {crypto.SHA256, nil},
}

// Signer is who signed a manifest, and when the signature is good for: the
// corim-meta of the COSE protected header.
type Signer struct {
	// Name is the corim-signer-map's signer-name.
	Name string
	// NotBefore and NotAfter are the signature-validity; NotAfter is
	// required, NotBefore is optional.
	NotBefore, NotAfter time.Time
}

// SignatureError reports a signed manifest whose signature, certificate
// chain or signer is not good, or a key that cannot sign one.
type SignatureError struct {
	Reason string
	Err    error
}

func (e *SignatureError) Error() string {
	if e.Err != nil {
		return "measure: measurement manifest signature: " + e.Reason + ": " + e.Err.Error()
	}
	return "measure: measurement manifest signature: " + e.Reason
}

// Unwrap returns the underlying error.
func (e *SignatureError) Unwrap() error { return e.Err }

type (
	// protectedHeader's keys are the COSE header labels a signed manifest
	// uses: alg 1, content type 3 and kid 4 (RFC 9052 §3.1), corim-meta 8
	// (draft-ietf-rats-corim-11 §4.2) and x5chain 33 (RFC 9360).
	protectedHeader struct {
		Alg         int64    `cbor:"1,keyasint"`
		ContentType string   `cbor:"3,keyasint"`
		KID         []byte   `cbor:"4,keyasint"`
		Meta        []byte   `cbor:"8,keyasint"`
		X5Chain     [][]byte `cbor:"33,keyasint"`
	}
	corimMeta struct {
		Signer   signerMap   `cbor:"0,keyasint"`
		Validity validityMap `cbor:"1,keyasint"`
	}
	signerMap struct {
		Name string `cbor:"0,keyasint"`
	}
	validityMap struct {
		NotBefore *time.Time `cbor:"0,keyasint,omitempty"`
		NotAfter  *time.Time `cbor:"1,keyasint"`
	}
	coseSign1 struct {
		_           struct{} `cbor:",toarray"`
		Protected   []byte
		Unprotected map[int64]any
		Payload     []byte
		Signature   []byte
	}
	sigStructure struct {
		_           struct{} `cbor:",toarray"`
		Context     string
		Protected   []byte
		ExternalAAD []byte
		Payload     []byte
	}
)

// metaMode encodes corim-meta's times as epoch-based date/time, #6.1(int).
var metaMode = func() cbor.EncMode {
	opts := cbor.CoreDetEncOptions()
	opts.Time = cbor.TimeUnix
	opts.TimeTag = cbor.EncTagRequired
	m, err := opts.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// algFor is the COSE algorithm pub signs with.
func algFor(pub crypto.PublicKey) (int64, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		for alg, a := range coseAlgs {
			if a.curve == k.Curve {
				return alg, nil
			}
		}
		return 0, &SignatureError{Reason: fmt.Sprintf("an ECDSA key on %s, not P-256, P-384 or P-521", k.Curve.Params().Name)}
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return 0, &SignatureError{Reason: fmt.Sprintf("a %d-bit RSA key, under 2048 bits", k.N.BitLen())}
		}
		return AlgPS256, nil
	default:
		return 0, &SignatureError{Reason: fmt.Sprintf("a %T key, not ECDSA or RSA", pub)}
	}
}

func toBeSigned(protected, payload []byte) ([]byte, error) {
	return encMode.Marshal(sigStructure{Context: "Signature1", Protected: protected, ExternalAAD: []byte{}, Payload: payload})
}

// SignManifest encodes m and signs it as a signed-corim: a COSE_Sign1 whose
// protected header carries the algorithm, ManifestContentType, the
// leaf's SHA-256 as kid, corim-meta from signer, and chain as x5chain, leaf
// first. key is the private half of chain[0]: a KMS key behind a
// crypto.Signer, so the build host never holds it. The algorithm follows the
// key (see AlgES256). A manifest EncodeManifest refuses, a key that is not
// the leaf's, a signer without a name or a NotAfter, or a validity that ends
// before it starts is refused.
func SignManifest(m Manifest, key crypto.Signer, chain []*x509.Certificate, signer Signer) ([]byte, error) {
	payload, err := EncodeManifest(m)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, &SignatureError{Reason: "no signing certificate"}
	}
	leaf := chain[0]
	if pk, ok := key.Public().(interface{ Equal(crypto.PublicKey) bool }); !ok || !pk.Equal(leaf.PublicKey) {
		return nil, &SignatureError{Reason: "the key is not the signing certificate's"}
	}
	if signer.Name == "" {
		return nil, &SignatureError{Reason: "no signer name"}
	}
	if signer.NotAfter.IsZero() {
		return nil, &SignatureError{Reason: "no signature-validity not-after"}
	}
	if !signer.NotBefore.IsZero() && signer.NotAfter.Before(signer.NotBefore) {
		return nil, &SignatureError{Reason: "the signature-validity ends before it starts"}
	}
	alg, err := algFor(key.Public())
	if err != nil {
		return nil, err
	}
	validity := validityMap{NotAfter: &signer.NotAfter}
	if !signer.NotBefore.IsZero() {
		validity.NotBefore = &signer.NotBefore
	}
	meta, err := metaMode.Marshal(corimMeta{Signer: signerMap{Name: signer.Name}, Validity: validity})
	if err != nil {
		return nil, &SignatureError{Reason: "encoding corim-meta", Err: err}
	}
	kid := sha256.Sum256(leaf.Raw)
	x5 := make([][]byte, 0, len(chain))
	for _, c := range chain {
		x5 = append(x5, c.Raw)
	}
	protected, err := encMode.Marshal(protectedHeader{Alg: alg, ContentType: ManifestContentType, KID: kid[:], Meta: meta, X5Chain: x5})
	if err != nil {
		return nil, &SignatureError{Reason: "encoding the protected header", Err: err}
	}
	tbs, err := toBeSigned(protected, payload)
	if err != nil {
		return nil, &SignatureError{Reason: "encoding the Sig_structure", Err: err}
	}
	sig, err := sign(rand.Reader, key, alg, tbs)
	if err != nil {
		return nil, err
	}
	out, err := encMode.Marshal(cbor.Tag{Number: TagSignedCoRIM, Content: coseSign1{
		Protected: protected, Unprotected: map[int64]any{}, Payload: payload, Signature: sig,
	}})
	if err != nil {
		return nil, &SignatureError{Reason: "encoding the COSE_Sign1", Err: err}
	}
	return out, nil
}

// sign signs tbs with key in alg; an ECDSA signature is turned from ASN.1
// into COSE's fixed-length r || s (RFC 9053 §2.1).
func sign(rnd io.Reader, key crypto.Signer, alg int64, tbs []byte) ([]byte, error) {
	a := coseAlgs[alg]
	h := a.hash.New()
	h.Write(tbs)
	digest := h.Sum(nil)
	var opts crypto.SignerOpts = a.hash
	if alg == AlgPS256 {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.hash}
	}
	sig, err := key.Sign(rnd, digest, opts)
	if err != nil {
		return nil, &SignatureError{Reason: "the key did not sign", Err: err}
	}
	if a.curve == nil {
		return sig, nil
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) != 0 {
		return nil, &SignatureError{Reason: "the ECDSA signature is not ASN.1", Err: err}
	}
	n := (a.curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*n)
	rs.R.FillBytes(out[:n])
	rs.S.FillBytes(out[n:])
	return out, nil
}

// SignedManifest is a manifest whose signature VerifyManifest checked.
type SignedManifest struct {
	Manifest Manifest
	// Signer is the corim-meta the signature carries.
	Signer Signer
	// Chain is the x5chain, leaf first, verified to a root.
	Chain []*x509.Certificate
}

// VerifyManifest checks a signed-corim SignManifest writes and decodes its
// manifest: the x5chain verifies to roots, the signature verifies with the
// leaf's key in the algorithm that key signs, at is inside both the leaf's
// validity and corim-meta's signature-validity, and the payload is a
// manifest DecodeManifest takes. Anything else is refused.
func VerifyManifest(data []byte, roots *x509.CertPool, at time.Time) (SignedManifest, error) {
	var outer cbor.RawTag
	if err := decMode.Unmarshal(data, &outer); err != nil {
		return SignedManifest{}, &SignatureError{Reason: "not a tagged COSE_Sign1", Err: err}
	}
	if outer.Number != TagSignedCoRIM {
		return SignedManifest{}, &SignatureError{Reason: fmt.Sprintf("CBOR tag %d, not a signed CoRIM (%d)", outer.Number, TagSignedCoRIM)}
	}
	var msg coseSign1
	if err := decMode.Unmarshal(outer.Content, &msg); err != nil {
		return SignedManifest{}, &SignatureError{Reason: "decoding the COSE_Sign1", Err: err}
	}
	if msg.Payload == nil {
		return SignedManifest{}, &SignatureError{Reason: "a detached payload"}
	}
	var hdr protectedHeader
	if err := decMode.Unmarshal(msg.Protected, &hdr); err != nil {
		return SignedManifest{}, &SignatureError{Reason: "decoding the protected header", Err: err}
	}
	if hdr.ContentType != ManifestContentType {
		return SignedManifest{}, &SignatureError{Reason: fmt.Sprintf("content type %q, not %q", hdr.ContentType, ManifestContentType)}
	}
	if len(hdr.X5Chain) == 0 {
		return SignedManifest{}, &SignatureError{Reason: "no x5chain"}
	}
	chain := make([]*x509.Certificate, 0, len(hdr.X5Chain))
	for _, der := range hdr.X5Chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return SignedManifest{}, &SignatureError{Reason: "an x5chain certificate does not parse", Err: err}
		}
		chain = append(chain, c)
	}
	leaf := chain[0]
	if kid := sha256.Sum256(leaf.Raw); !bytes.Equal(hdr.KID, kid[:]) {
		return SignedManifest{}, &SignatureError{Reason: "the kid is not the signing certificate's"}
	}
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return SignedManifest{}, &SignatureError{Reason: "the signing certificate does not verify", Err: err}
	}
	alg, err := algFor(leaf.PublicKey)
	if err != nil {
		return SignedManifest{}, err
	}
	if hdr.Alg != alg {
		return SignedManifest{}, &SignatureError{Reason: fmt.Sprintf("algorithm %d, but the signing key signs %d", hdr.Alg, alg)}
	}
	tbs, err := toBeSigned(msg.Protected, msg.Payload)
	if err != nil {
		return SignedManifest{}, &SignatureError{Reason: "encoding the Sig_structure", Err: err}
	}
	if err := verify(leaf.PublicKey, alg, tbs, msg.Signature); err != nil {
		return SignedManifest{}, err
	}
	var meta corimMeta
	if err := decMode.Unmarshal(hdr.Meta, &meta); err != nil {
		return SignedManifest{}, &SignatureError{Reason: "decoding corim-meta", Err: err}
	}
	if meta.Signer.Name == "" || meta.Validity.NotAfter == nil {
		return SignedManifest{}, &SignatureError{Reason: "corim-meta has no signer name or no not-after"}
	}
	signer := Signer{Name: meta.Signer.Name, NotAfter: *meta.Validity.NotAfter}
	if meta.Validity.NotBefore != nil {
		signer.NotBefore = *meta.Validity.NotBefore
	}
	if at.After(signer.NotAfter) || (!signer.NotBefore.IsZero() && at.Before(signer.NotBefore)) {
		return SignedManifest{}, &SignatureError{Reason: fmt.Sprintf("%v is outside the signature-validity", at.UTC())}
	}
	m, err := DecodeManifest(msg.Payload)
	if err != nil {
		return SignedManifest{}, err
	}
	return SignedManifest{Manifest: m, Signer: signer, Chain: chain}, nil
}

// errBadSignature is wrapped by the error verify returns.
var errBadSignature = errors.New("the signature does not verify")

func verify(pub crypto.PublicKey, alg int64, tbs, sig []byte) error {
	a := coseAlgs[alg]
	h := a.hash.New()
	h.Write(tbs)
	digest := h.Sum(nil)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		n := (a.curve.Params().BitSize + 7) / 8
		if len(sig) == 2*n {
			ok = ecdsa.Verify(k, digest, new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:]))
		}
	case *rsa.PublicKey:
		ok = rsa.VerifyPSS(k, a.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: a.hash}) == nil
	}
	if !ok {
		return &SignatureError{Reason: fmt.Sprintf("COSE algorithm %d", alg), Err: errBadSignature}
	}
	return nil
}
