package diskimage

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/measure"
	"github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
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

// UnsignedNoManifestKey is Result.Unsigned for a measured build given no
// ManifestKey.
const UnsignedNoManifestKey = "no manifest key (--manifest-key kms://...): the image's PCRs are predicted but not signed, so it has no <image>" + ManifestSuffix

// removeManifest deletes the manifest a previous build left beside image,
// so a rebuild that writes none (unmeasured, unsigned or failed) never
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

// validateManifestKey refuses a ManifestKey the build cannot sign with, so
// the build fails before it starts rather than after the image is written.
func (c *BuildConfig) validateManifestKey() error {
	if c.ManifestKey == "" {
		return nil
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(c.ManifestKey)), "kms://") {
		return &ManifestKeyRefError{Ref: c.ManifestKey}
	}
	if c.KMSClients == nil {
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
// algorithm than the key's fails the build. It returns the manifest's path,
// or "" and UnsignedNoManifestKey with no ManifestKey.
func (c *BuildConfig) writeManifest(ctx context.Context, image, sum string, target Target, banks []measure.Bank) (string, string, error) {
	if c.ManifestKey == "" {
		return "", UnsignedNoManifestKey, nil
	}
	fail := func(step string, err error) (string, string, error) {
		return "", "", &MeasureError{Step: step, Err: err}
	}
	if err := c.validateManifestKey(); err != nil {
		return fail("the manifest key", err)
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
	name := cert.Subject.CommonName
	if name == "" {
		name = measure.ManifestVendor
	}
	now := time.Now().UTC().Truncate(time.Second)
	m := measure.Manifest{TagID: id, Model: target.Name() + "/" + target.ModelName(), Banks: banks}
	data, err := measure.SignManifest(m, key, []*x509.Certificate{cert}, measure.Signer{Name: name, NotBefore: now, NotAfter: cert.NotAfter})
	if err != nil {
		return fail("signing the measurement manifest", err)
	}
	self := x509.NewCertPool()
	self.AddCert(cert)
	if _, err := measure.VerifyManifest(data, self, now); err != nil {
		return fail("checking the signed measurement manifest", err)
	}
	out := ManifestPath(image)
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return fail("writing "+filepath.Base(out), err)
	}
	return out, "", nil
}
