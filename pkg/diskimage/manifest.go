package diskimage

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// ManifestSuffix names an image's signed measurement manifest
// (architecture.md §8): ManifestPath appends it to the image's path, so
// every image in an output directory keeps its own manifest.
const ManifestSuffix = ".corim"

// ManifestPath is the path of the signed measurement manifest of the image
// at image: bin/rpi.img's is bin/rpi.img.corim.
func ManifestPath(image string) string {
	return image + ManifestSuffix
}

// removeManifest deletes the manifest a previous build left beside image,
// so a rebuild that writes none (unmeasured or failed) never
// leaves the old image's measurements beside the new image's bytes.
func removeManifest(image string) error {
	if err := os.Remove(ManifestPath(image)); err != nil && !os.IsNotExist(err) {
		return &MeasureError{Step: "removing the previous " + filepath.Base(ManifestPath(image)), Err: err}
	}
	return nil
}

// ManifestKeyRefError reports a ManifestKey that is not a kms:// reference.
// The manifest's key stays in the KMS: a file key on the build host is
// refused, as the HTTP boot fleet key's is.
type ManifestKeyRefError struct {
	Ref string
}

func (e *ManifestKeyRefError) Error() string {
	return fmt.Sprintf("diskimage: manifest key %q is not a kms:// reference: the measurement manifest is signed in the KMS, never with a key on the build host", e.Ref)
}

// errNoManifestKMS is validateManifestKey's error for a ManifestKey with no
// KMSClients to reach it through.
var errNoManifestKMS = errors.New("diskimage: a manifest key needs a platform client to reach the KMS")

// errNoManifestKey is validateManifestKey's error for an empty ManifestKey:
// a measured image is always signed.
var errNoManifestKey = errors.New("diskimage: a measured image needs a manifest key (default " + DefaultManifestKey + ")")

// validateManifestKey refuses a ManifestKey the build cannot sign with, so
// the build fails before it starts rather than after the image is written:
// an empty key (withDefaults names DefaultManifestKey), a reference that is
// not kms://, and, for a Secure Boot build (the only one measured), no
// KMSClients to reach the key through.
func (c *BuildConfig) validateManifestKey() error {
	if c.ManifestKey == "" {
		return errNoManifestKey
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.ManifestKey)), "kms://") {
		return &ManifestKeyRefError{Ref: c.ManifestKey}
	}
	if c.ISO != nil && c.ISO.SecureBoot && c.KMSClients == nil {
		return errNoManifestKMS
	}
	return nil
}

// writeManifest signs the measurement manifest of the image whose SHA-256
// is sum, with banks its predicted PCRs, and writes it to
// ManifestPath(image). The key is ManifestKey in the KMS, its certificate
// ManifestCert from the platform CA; corim-meta's signer is the
// certificate's common name and the signature is good from now until the
// certificate expires. The written manifest is verified with that
// certificate before the build reports it, so a KMS that signs in another
// algorithm than the key's fails the build. It returns the manifest's path;
// an empty ManifestKey or no KMSClients is a MeasureError, never an
// unsigned image.
func (c *BuildConfig) writeManifest(ctx context.Context, image, sum string, target Target, banks []measure.Bank) (string, error) {
	fail := func(step string, err error) (string, error) {
		return "", &MeasureError{Step: step, Err: err}
	}
	if err := c.validateManifestKey(); err != nil {
		return fail("the manifest key", err)
	}
	if c.KMSClients == nil {
		return fail("the manifest key", errNoManifestKMS)
	}
	digest, err := hex.DecodeString(sum)
	if err != nil {
		return fail("reading the image digest", err)
	}
	id, err := measure.ManifestTagID(digest)
	if err != nil {
		return fail("deriving the manifest's tag identity", err)
	}
	clients, err := c.KMSClients()
	if err != nil {
		return fail("connecting to the platform", err)
	}
	key, cert, err := secureboot.NewKMSSigner(ctx, clients.KMS, clients.CA, c.ManifestKey, c.ManifestCert)
	if err != nil {
		return fail("opening the manifest key", err)
	}
	// An RSA manifest is signed PS256, and the platform KMS Sign API carries
	// no RSA-PSS parameters: refuse the key here,
	// before anything is signed or written, not after a PKCS#1 v1.5
	// signature fails its check.
	if _, isRSA := key.Public().(*rsa.PublicKey); isRSA {
		return fail("opening the manifest key", secureboot.ErrKMSPSSUnsupported)
	}
	name := cert.Subject.CommonName
	if name == "" {
		name = measure.ManifestVendor
	}
	now := time.Now().UTC().Truncate(time.Second)
	m := measure.Manifest{TagID: id, Model: target.Name() + "/" + target.ModelName(), Banks: banks}
	chain, root, err := manifestChain(ctx, clients.CA, cert, now)
	if err != nil {
		return fail("building the manifest certificate's chain", err)
	}
	data, err := measure.SignManifest(m, key, chain, measure.Signer{Name: name, NotBefore: now, NotAfter: cert.NotAfter})
	if err != nil {
		return fail("signing the measurement manifest", err)
	}
	if _, err := measure.VerifyManifest(data, root, now); err != nil {
		return fail("checking the signed measurement manifest", err)
	}
	out := ManifestPath(image)
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return fail("writing "+filepath.Base(out), err)
	}
	return out, nil
}

// ReferenceValueRegistrar registers a signed measurement manifest, the
// CoRIM of the PCR values an image determines, in the reference-values store
// the verifier reads.
type ReferenceValueRegistrar interface {
	// RegisterManifest registers signed, the manifest of the image whose
	// SHA-256 digest is sum (hex).
	RegisterManifest(ctx context.Context, sum string, signed []byte) error
}

// publishManifest writes the image's signed manifest beside it and registers
// it through c.ReferenceValues. It reports whether the manifest was
// registered; a registration failure is a MeasureError. docs/SPEC.md:57
// requires every manifest registered, so Create refuses a measured build
// with no registrar (the pinned go-quicbaas SDK has no reference-values
// client until the bump held to #1348) at configuration, before assembly;
// the nil check here is the backstop and fails before it signs anything.
func (c *BuildConfig) publishManifest(ctx context.Context, image, sum string, target Target, banks []measure.Bank) (string, bool, error) {
	if c.ReferenceValues == nil {
		// docs/SPEC.md:57: every image's signed manifest is registered in the
		// reference-values store; a measured build that cannot register it
		// fails rather than shipping an image no verifier can appraise.
		return "", false, &MeasureError{Step: "registering the measurement manifest", Err: errNoRegistrar}
	}
	out, err := c.writeManifest(ctx, image, sum, target, banks)
	if err != nil {
		return "", false, err
	}
	signed, err := os.ReadFile(out)
	if err != nil {
		return out, false, &MeasureError{Step: "reading " + filepath.Base(out), Err: err}
	}
	if err := c.ReferenceValues.RegisterManifest(ctx, sum, signed); err != nil {
		return out, false, &MeasureError{Step: "registering the measurement manifest", Err: err}
	}
	return out, true, nil
}

// errNoRegistrar is why a measured build without a reference-values
// registrar is refused, by Create before assembly (until the go-quicbaas SDK
// bump, #1348, supplies one).
var errNoRegistrar = errors.New("no reference-values registrar: a measured build cannot register its manifest")

// errNoCABundle: the platform CA client cannot return the CA bundle, so the
// manifest certificate's issuer chain cannot be built.
var errNoCABundle = errors.New("diskimage: the platform CA client returns no CA bundle to build the manifest certificate's chain from")

// manifestChain builds the manifest certificate's chain from the platform
// CA's bundle (intermediates included): it returns the leaf followed by its
// intermediates, the chain a manifest carries, and a pool holding only the
// platform root the chain ends at, the anchor a consumer verifies against.
func manifestChain(ctx context.Context, ca secureboot.CertificateGetter, leaf *x509.Certificate, now time.Time) ([]*x509.Certificate, *x509.CertPool, error) {
	getter, ok := ca.(secureboot.CABundleGetter)
	if !ok {
		return nil, nil, errNoCABundle
	}
	resp, err := getter.GetCABundle(ctx, &platformv1.GetCABundleRequest{IncludeIntermediates: true})
	if err != nil {
		return nil, nil, fmt.Errorf("diskimage: fetching the platform CA bundle: %w", err)
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	rest := resp.GetBundle().GetPem()
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("diskimage: parsing the platform CA bundle: %w", err)
		}
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignatureFrom(cert) == nil {
			roots.AddCert(cert)
		} else {
			inters.AddCert(cert)
		}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, CurrentTime: now,
		// Publication applies the verifier's signer policy: code signing only.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}})
	if err != nil {
		return nil, nil, fmt.Errorf("diskimage: the manifest certificate does not chain to a platform root in the CA bundle: %w", err)
	}
	full := chains[0]
	root := x509.NewCertPool()
	root.AddCert(full[len(full)-1])
	if len(full) == 1 {
		return full, root, nil
	}
	return full[:len(full)-1], root, nil
}
