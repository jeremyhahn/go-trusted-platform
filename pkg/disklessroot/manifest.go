package disklessroot

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

// Manifest is the build's statement of the diskless root it produced. It is
// signed with the Secure Boot db key at build time and verified by the
// installer against the db certificate before any of it reaches the UKI
// command line, so the root hash never comes from an unauthenticated source.
type Manifest struct {
	Version int `json:"version"`
	// RootHash is the dm-verity root hash of RootFSFile under the hash tree
	// in VerityFile.
	RootHash string `json:"root_hash"`
	// Salt is the verity salt the tree was formatted with (DeriveSalt).
	Salt string `json:"salt"`
	// RootFSSize and VeritySize are the exact artifact sizes. platform-initrd
	// refuses to read past them, which bounds the RAM a boot server can fill.
	RootFSSize int64 `json:"rootfs_size"`
	VeritySize int64 `json:"verity_size"`
}

// Validate checks every field. A manifest that fails is never signed and never
// trusted, whatever its signature.
func (m Manifest) Validate() error {
	if m.Version != ManifestVersion {
		return &FieldError{Field: "version", Reason: "must be " + strconv.Itoa(ManifestVersion)}
	}
	if err := ValidateRootHash(m.RootHash); err != nil {
		return err
	}
	if err := validateHex(ParamVeritySalt, m.Salt); err != nil {
		return err
	}
	return validateSizes(m.RootFSSize, m.VeritySize)
}

// DataBlocks is the number of dm-verity data blocks the root image covers.
func (m Manifest) DataBlocks() int64 {
	return m.RootFSSize / BlockSize
}

// validateSizes requires positive sizes and a root image that is a whole
// number of verity data blocks; mksquashfs pads its output to 4 KiB.
func validateSizes(rootfs, verity int64) error {
	if rootfs <= 0 || rootfs%BlockSize != 0 {
		return &FieldError{Field: ParamRootFSSize, Reason: "must be a positive multiple of " + strconv.Itoa(BlockSize)}
	}
	if verity <= 0 {
		return &FieldError{Field: ParamVeritySize, Reason: "must be positive"}
	}
	return nil
}

// WriteSigned validates m, signs its JSON encoding with signer and writes the
// manifest and its detached signature into dir.
func WriteSigned(dir string, m Manifest, signer crypto.Signer) error {
	if err := m.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(m)
	if err != nil {
		return &ManifestError{Path: dir, Err: err}
	}
	sig, err := sign(payload, signer)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return &ManifestError{Path: dir, Err: err}
	}
	manifestPath := filepath.Join(dir, ManifestFile)
	if err := os.WriteFile(manifestPath, payload, 0o644); err != nil {
		return &ManifestError{Path: manifestPath, Err: err}
	}
	sigPath := filepath.Join(dir, SignatureFile)
	if err := os.WriteFile(sigPath, sig, 0o644); err != nil {
		return &ManifestError{Path: sigPath, Err: err}
	}
	return nil
}

// ReadSigned reads the manifest in dir, verifies its detached signature
// against anchor and only then decodes and validates it.
func ReadSigned(dir string, anchor *x509.Certificate) (*Manifest, error) {
	manifestPath := filepath.Join(dir, ManifestFile)
	payload, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, &ManifestError{Path: manifestPath, Err: err}
	}
	sigPath := filepath.Join(dir, SignatureFile)
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, &ManifestError{Path: sigPath, Err: err}
	}
	if err := verify(payload, sig, anchor); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var m Manifest
	if err := decoder.Decode(&m); err != nil {
		return nil, &ManifestError{Path: manifestPath, Err: err}
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// signatureAlgorithms maps the db certificate's key type to the signature
// algorithm sign produces for it.
var signatureAlgorithms = map[x509.PublicKeyAlgorithm]x509.SignatureAlgorithm{
	x509.RSA:     x509.SHA256WithRSA,
	x509.ECDSA:   x509.ECDSAWithSHA256,
	x509.Ed25519: x509.PureEd25519,
}

// sign signs payload: sha256 then PKCS#1 v1.5 or ECDSA, or pure Ed25519.
func sign(payload []byte, signer crypto.Signer) ([]byte, error) {
	if signer == nil {
		return nil, &SignatureError{Reason: "no signing key"}
	}
	var (
		sig []byte
		err error
	)
	if _, ok := signer.Public().(ed25519.PublicKey); ok {
		sig, err = signer.Sign(rand.Reader, payload, crypto.Hash(0))
	} else {
		digest := sha256.Sum256(payload)
		sig, err = signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		return nil, &SignatureError{Reason: "signing the manifest", Err: err}
	}
	return sig, nil
}

// verify checks sig over payload against the anchor certificate's key.
func verify(payload, sig []byte, anchor *x509.Certificate) error {
	if anchor == nil {
		return &SignatureError{Reason: "no trust anchor"}
	}
	algorithm, ok := signatureAlgorithms[anchor.PublicKeyAlgorithm]
	if !ok {
		return &SignatureError{Reason: "unsupported anchor key " + anchor.PublicKeyAlgorithm.String()}
	}
	if err := anchor.CheckSignature(algorithm, payload, sig); err != nil {
		return &SignatureError{Reason: "the manifest does not verify against the anchor", Err: err}
	}
	return nil
}
