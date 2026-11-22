package measure

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
)

// signedImageManifest signs the manifest the build writes for img: the
// banks Predict computes, tagged with the image's SHA-256.
func signedImageManifest(t *testing.T, img Image, imageSHA256 []byte, hashes ...crypto.Hash) ([]byte, testPKI) {
	t.Helper()
	banks, err := Predict(img, hashes...)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ManifestTagID(imageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	m := Manifest{TagID: id, Model: "qemu-virt/virt", Banks: banks}
	pki := newPKI(t, p384)
	signed, err := SignManifest(m, pki.key, pki.chain, testSigner)
	if err != nil {
		t.Fatal(err)
	}
	return signed, pki
}

// mismatches returns every *PCRMismatchError err joins.
func mismatches(t *testing.T, err error) []*PCRMismatchError {
	t.Helper()
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatalf("err %T (%v) does not join its mismatches", err, err)
	}
	var out []*PCRMismatchError
	for _, e := range joined.Unwrap() {
		var pm *PCRMismatchError
		if errors.As(e, &pm) {
			out = append(out, pm)
		}
	}
	return out
}

// TestCheckManifestEventLog checks a signed manifest against event logs
// encoded event by event from the boot chain's measurements
// (imageEvents), never against a replay of the log under test, so the
// predictors and the log are independent.
func TestCheckManifestEventLog(t *testing.T) {
	img, _ := testImage()
	hashes := []crypto.Hash{crypto.SHA256, crypto.SHA384}
	digest := sha256.Sum256([]byte("factory image"))
	signed, pki := signedImageManifest(t, img, digest[:], hashes...)
	banks, err := Predict(img, hashes...)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("the boot of this image", func(t *testing.T) {
		sm, err := CheckManifestEventLog(signed, digest[:], pki.roots, signedAt, imageLog(t, img, hashes...))
		if err != nil {
			t.Fatalf("err %v, want the log to match the manifest", err)
		}
		if sm.Manifest.Model != "qemu-virt/virt" {
			t.Fatalf("model %q, want qemu-virt/virt", sm.Manifest.Model)
		}
		if len(sm.Manifest.Banks) != len(banks) {
			t.Fatalf("banks %+v, want %+v", sm.Manifest.Banks, banks)
		}
		for i, b := range banks {
			got := sm.Manifest.Banks[i]
			if got.Hash != b.Hash || len(got.PCRs) != len(b.PCRs) {
				t.Fatalf("bank %d %+v, want %+v", i, got, b)
			}
			for pcr, v := range b.PCRs {
				if !bytes.Equal(got.PCRs[pcr], v) {
					t.Fatalf("%v PCR %d %x, want %x", b.Hash, pcr, got.PCRs[pcr], v)
				}
			}
		}
	})

	t.Run("one event changed", func(t *testing.T) {
		events := imageEvents(t, img, hashes...)
		events[lastEvent(events, 9)].digest[crypto.SHA256][0] ^= 1
		_, err := CheckManifestEventLog(signed, digest[:], pki.roots, signedAt, encodeEventLog(hashes, events...))
		var pm *PCRMismatchError
		if !errors.As(err, &pm) {
			t.Fatalf("err %v, want a PCRMismatchError", err)
		}
		if pm.Hash != crypto.SHA256 || pm.PCR != 9 || !bytes.Equal(pm.Predicted, banks[0].PCRs[9]) {
			t.Fatalf("mismatch %+v, want SHA-256 PCR 9 predicted %x", pm, banks[0].PCRs[9])
		}
		if n := len(mismatches(t, err)); n != 1 {
			t.Fatalf("%d mismatches (%v), want one", n, err)
		}
	})

	t.Run("the boot of another image", func(t *testing.T) {
		other := img
		other.UKI, _ = testUKI("root=/dev/mapper/other ro")
		_, err := CheckManifestEventLog(signed, digest[:], pki.roots, signedAt, imageLog(t, other, hashes...))
		got := map[crypto.Hash]map[int]bool{}
		for _, pm := range mismatches(t, err) {
			if got[pm.Hash] == nil {
				got[pm.Hash] = map[int]bool{}
			}
			got[pm.Hash][pm.PCR] = true
		}
		for _, h := range hashes {
			if !got[h][4] || !got[h][9] || got[h][0] || got[h][7] {
				t.Fatalf("%v mismatches %v, want PCR 4 and 9 and not 0 or 7 (err %v)", h, got[h], err)
			}
		}
	})

	t.Run("a log that never extends PCR 7", func(t *testing.T) {
		var no7 []logEvent
		for _, e := range imageEvents(t, img, hashes...) {
			if e.pcr != 7 {
				no7 = append(no7, e)
			}
		}
		_, err := CheckManifestEventLog(signed, digest[:], pki.roots, signedAt, encodeEventLog(hashes, no7...))
		var pm *PCRMismatchError
		if !errors.As(err, &pm) || pm.PCR != 7 || pm.Replayed != nil {
			t.Fatalf("err %v, want a PCR 7 mismatch with nothing replayed", err)
		}
	})

	t.Run("a log without the SHA-384 bank", func(t *testing.T) {
		_, err := CheckManifestEventLog(signed, digest[:], pki.roots, signedAt, imageLog(t, img, crypto.SHA256))
		var mb *MissingBankError
		if !errors.As(err, &mb) || mb.Hash != crypto.SHA384 {
			t.Fatalf("err %v, want a MissingBankError for SHA-384", err)
		}
	})

	t.Run("a malformed log", func(t *testing.T) {
		_, err := CheckManifestEventLog(signed, digest[:], pki.roots, signedAt, []byte("not an event log"))
		var me *MalformedEventLogError
		if !errors.As(err, &me) {
			t.Fatalf("err %v, want a MalformedEventLogError", err)
		}
	})

	t.Run("the manifest of another image", func(t *testing.T) {
		other := sha256.Sum256([]byte("another image"))
		want, err := ManifestTagID(other[:])
		if err != nil {
			t.Fatal(err)
		}
		tagged, err := ManifestTagID(digest[:])
		if err != nil {
			t.Fatal(err)
		}
		for _, log := range [][]byte{imageLog(t, img, hashes...), []byte("not an event log")} {
			_, err := CheckManifestEventLog(signed, other[:], pki.roots, signedAt, log)
			var mi *ManifestImageError
			if !errors.As(err, &mi) {
				t.Fatalf("err %v, want a ManifestImageError before the log is read", err)
			}
			if mi.Want != want || mi.Got != tagged {
				t.Fatalf("ManifestImageError %+v, want Want %s Got %s", mi, want, tagged)
			}
			if mi.Error() == "" {
				t.Fatal("ManifestImageError has an empty message")
			}
		}
	})

	t.Run("an untrusted signer", func(t *testing.T) {
		var roots *x509.CertPool = newPKI(t, p384).roots
		_, err := CheckManifestEventLog(signed, digest[:], roots, signedAt, imageLog(t, img, hashes...))
		var se *SignatureError
		if !errors.As(err, &se) {
			t.Fatalf("err %v, want a SignatureError", err)
		}
	})
}
