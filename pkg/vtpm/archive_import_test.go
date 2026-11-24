package vtpm

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// readBundleFiles returns every regular file under dir except manifest.json,
// keyed by its slash-separated path relative to dir.
func readBundleFiles(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	files := map[string][]byte{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "manifest.json" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files[rel] = data
		return nil
	})
	if err != nil {
		t.Fatalf("walk bundle %s: %v", dir, err)
	}
	return files
}

func assertBundleFiles(t *testing.T, dir string, want map[string][]byte) {
	t.Helper()
	got := readBundleFiles(t, dir)
	if len(got) != len(want) {
		names := make([]string, 0, len(got))
		for name := range got {
			names = append(names, name)
		}
		t.Fatalf("bundle holds %d files %v, want %d", len(got), names, len(want))
	}
	for name, content := range want {
		if !bytes.Equal(got[name], content) {
			t.Fatalf("bundle file %s = %d bytes not matching the winning archive", name, len(got[name]))
		}
	}
}

func assertNoStagingLeft(t *testing.T, config *Config) {
	t.Helper()
	entries, err := os.ReadDir(config.BundlesDir())
	if err != nil {
		t.Fatalf("read bundles dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Errorf("staging entry left in the bundle store: %s", e.Name())
		}
	}
}

// TestArchiver_ImportFromFile_ConcurrentSameIDOneWins starts two imports of
// different archives naming the same new bundle together: exactly one
// succeeds, the other reports the bundle already exists, and the published
// bundle holds the winner's files only.
func TestArchiver_ImportFromFile_ConcurrentSameIDOneWins(t *testing.T) {
	id := "race"
	big := func(b byte) []byte { return bytes.Repeat([]byte{b}, 256*1024) }
	contents := [2]map[string][]byte{
		{
			"tpm/tpm2-00.permall":       big('A'),
			"ovmf/OVMF_VARS.fd":         big('a'),
			"secure-boot-keys/PK.key":   big('1'),
			"secure-boot-keys/only-a.k": []byte("a"),
		},
		{
			"tpm/tpm2-00.permall":       big('B'),
			"ovmf/OVMF_VARS.fd":         big('b'),
			"secure-boot-keys/PK.key":   big('2'),
			"secure-boot-keys/only-b.k": []byte("b"),
		},
	}
	archives := [2]string{
		writeBudgetTestArchive(t, id, contents[0]),
		writeBudgetTestArchive(t, id, contents[1]),
	}

	for round := 0; round < 20; round++ {
		config := &Config{BaseDir: t.TempDir()}
		var errs [2]error
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range archives {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				a := NewArchiver(config, nil)
				<-start
				_, errs[i] = a.ImportFromFile(context.Background(), archives[i])
			}(i)
		}
		close(start)
		wg.Wait()

		winner := -1
		for i, err := range errs {
			if err == nil {
				if winner >= 0 {
					t.Fatalf("round %d: both imports of bundle %q succeeded", round, id)
				}
				winner = i
				continue
			}
			var exists ErrBundleAlreadyExists
			if !errors.As(err, &exists) {
				t.Fatalf("round %d: import %d error = %v, want ErrBundleAlreadyExists", round, i, err)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: neither import succeeded: %v", round, errs)
		}
		assertBundleFiles(t, config.BundlePath(id), contents[winner])
		assertNoStagingLeft(t, config)
	}
}

// TestArchiver_ImportFromFile_OverBudgetLeavesExistingBundle checks that an
// import refused for exceeding the extraction budget removes only its own
// output: a bundle of the same ID already published, or published by a
// concurrent import while it extracts, is left untouched.
func TestArchiver_ImportFromFile_OverBudgetLeavesExistingBundle(t *testing.T) {
	id := "keep"
	good := map[string][]byte{
		"tpm/tpm2-00.permall": []byte("good state"),
		"ovmf/OVMF_VARS.fd":   []byte("good vars"),
	}
	goodArchive := writeBudgetTestArchive(t, id, good)
	hugeArchive := writeBudgetTestArchive(t, id, map[string][]byte{
		"tpm/tpm2-00.permall": bytes.Repeat([]byte{0xA5}, 4*1024*1024),
	})
	const limit = 2 * 1024 * 1024

	t.Run("already published", func(t *testing.T) {
		config := &Config{BaseDir: t.TempDir()}
		if _, err := NewArchiver(config, nil).ImportFromFile(context.Background(), goodArchive); err != nil {
			t.Fatalf("first import: %v", err)
		}
		a := NewArchiver(config, nil)
		a.maxExpandedBytes = limit
		if _, err := a.ImportFromFile(context.Background(), hugeArchive); err == nil {
			t.Fatal("over-budget import of an existing bundle succeeded")
		}
		assertBundleFiles(t, config.BundlePath(id), good)
		assertNoStagingLeft(t, config)
	})

	t.Run("published concurrently", func(t *testing.T) {
		for round := 0; round < 20; round++ {
			config := &Config{BaseDir: t.TempDir()}
			var goodErr, hugeErr error
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				a := NewArchiver(config, nil)
				a.maxExpandedBytes = limit
				<-start
				_, hugeErr = a.ImportFromFile(context.Background(), hugeArchive)
			}()
			go func() {
				defer wg.Done()
				a := NewArchiver(config, nil)
				<-start
				_, goodErr = a.ImportFromFile(context.Background(), goodArchive)
			}()
			close(start)
			wg.Wait()

			if hugeErr == nil {
				t.Fatalf("round %d: over-budget import succeeded", round)
			}
			if goodErr != nil {
				// The huge import may only lose by already-exists, never
				// by publishing; the good one may lose only the same way.
				t.Fatalf("round %d: good import failed: %v", round, goodErr)
			}
			if _, err := os.Stat(config.BundlePath(id)); err != nil {
				t.Fatalf("round %d: published bundle removed by the refused import: %v", round, err)
			}
			assertBundleFiles(t, config.BundlePath(id), good)
			assertNoStagingLeft(t, config)
		}
	})
}

// TestService_ImportBundle_RootLevelEntriesPublishTheManifest pins that an
// archive whose manifest.json sits at the tar root, with or without a "./"
// prefix, imports every entry (#2021 Codex round 4): the root prefix "."
// used to skip them all and publish an empty bundle.
func TestService_ImportBundle_RootLevelEntriesPublishTheManifest(t *testing.T) {
	for _, tc := range []struct{ name, prefix string }{{"bare", ""}, {"dot-slash", "./"}} {
		t.Run(tc.name, func(t *testing.T) {
			archive := buildArchive(t, []tarEntry{
				{name: tc.prefix + "manifest.json", typeflag: tar.TypeReg, body: `{"id":"rootlvl"}`},
				{name: tc.prefix + "tpm/", typeflag: tar.TypeDir},
				{name: tc.prefix + "tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
			}, 0)
			config := createTestConfig(t)
			service, err := NewService(config, nil, &mockCA{})
			if err != nil {
				t.Fatalf("NewService: %v", err)
			}
			ctx := context.Background()
			if _, err := service.ImportBundle(ctx, bytes.NewReader(archive)); err != nil {
				t.Fatalf("ImportBundle: %v", err)
			}
			bundle, err := service.GetBundle(ctx, "rootlvl")
			if err != nil {
				t.Fatalf("GetBundle after import: %v", err)
			}
			if bundle.ID != "rootlvl" {
				t.Fatalf("bundle ID = %q, want rootlvl", bundle.ID)
			}
			state, err := os.ReadFile(bundle.TPMState.PermallFile)
			if err != nil {
				t.Fatalf("read permall: %v", err)
			}
			if string(state) != "state" {
				t.Fatalf("permall = %q, want state", state)
			}
			assertNoStagingLeft(t, config)
		})
	}
}

// TestArchiver_ImportFromFile_RefusesAnArchiveWithoutManifestJSON pins that
// a file merely ending in manifest.json is not taken for the manifest, and
// that a stage with no manifest.json is never published.
func TestArchiver_ImportFromFile_RefusesAnArchiveWithoutManifestJSON(t *testing.T) {
	archive := buildArchive(t, []tarEntry{
		{name: "p/old-manifest.json", typeflag: tar.TypeReg, body: `{"id":"nomani"}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
	}, 0)
	archivePath := filepath.Join(t.TempDir(), "nomani.tar.gz")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	config := &Config{BaseDir: t.TempDir()}
	if err := os.MkdirAll(config.BundlesDir(), 0o700); err != nil {
		t.Fatalf("create bundles dir: %v", err)
	}
	_, err := NewArchiver(config, nil).ImportFromFile(context.Background(), archivePath)
	if !errors.As(err, &ErrInvalidManifest{}) {
		t.Fatalf("ImportFromFile error = %v, want ErrInvalidManifest", err)
	}
	if _, statErr := os.Stat(config.BundlePath("nomani")); !os.IsNotExist(statErr) {
		t.Fatalf("bundle published without manifest.json: stat err %v", statErr)
	}
	assertNoStagingLeft(t, config)
}

func TestArchiver_ImportFromFile_RefusesTheStagingPrefix(t *testing.T) {
	config, _, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":".import-backup","checksums":{"tpm/tpm2-00.permall":"` + checksumOf("state") + `"}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
	})
	if !errors.As(err, &ErrInvalidManifest{}) {
		t.Fatalf("ImportFromFile error = %v, want ErrInvalidManifest", err)
	}
	assertImportRefusedUnpublished(t, config, err, ".import-backup")
}

// checksumOf returns the manifest checksum ("sha256:<hex>") of body.
func checksumOf(body string) string {
	sum := sha256.Sum256([]byte(body))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// importChecksumArchive writes the archive of entries to a temp file and
// imports it into a fresh bundle store, returning the store's config.
func importChecksumArchive(t *testing.T, entries []tarEntry) (*Config, *Bundle, error) {
	t.Helper()
	archivePath := filepath.Join(t.TempDir(), "checksum.tar.gz")
	if err := os.WriteFile(archivePath, buildArchive(t, entries, 0), 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	config := &Config{BaseDir: t.TempDir()}
	if err := os.MkdirAll(config.BundlesDir(), 0o700); err != nil {
		t.Fatalf("create bundles dir: %v", err)
	}
	bundle, err := NewArchiver(config, nil).ImportFromFile(context.Background(), archivePath)
	return config, bundle, err
}

// assertChecksumRefused checks the import failed with ErrChecksumMismatch
// naming file, published no bundle id and left no staging behind.
func assertChecksumRefused(t *testing.T, config *Config, err error, id, file string) {
	t.Helper()
	var mismatch ErrChecksumMismatch
	if !errors.As(err, &mismatch) {
		t.Fatalf("ImportFromFile error = %v, want ErrChecksumMismatch", err)
	}
	if mismatch.File != file {
		t.Fatalf("ErrChecksumMismatch.File = %q, want %q", mismatch.File, file)
	}
	if _, statErr := os.Stat(config.BundlePath(id)); !os.IsNotExist(statErr) {
		t.Fatalf("bundle %s published despite a checksum mismatch: stat err %v", id, statErr)
	}
	assertNoStagingLeft(t, config)
}

// TestArchiver_ChecksumGate_RefusesAnAlteredFile imports an archive whose
// TPM state differs from the manifest checksum: nothing is published.
func TestArchiver_ChecksumGate_RefusesAnAlteredFile(t *testing.T) {
	config, _, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"altered","checksums":{"tpm/tpm2-00.permall":"` + checksumOf("original-state") + `"}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "altered-state"},
	})
	assertChecksumRefused(t, config, err, "altered", "tpm/tpm2-00.permall")
}

// TestArchiver_ChecksumGate_RefusesAMissingFile imports an archive that
// lacks a file the manifest checksums: nothing is published.
func TestArchiver_ChecksumGate_RefusesAMissingFile(t *testing.T) {
	config, _, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"missing","checksums":{"tpm/tpm2-00.permall":"` + checksumOf("state") + `","ovmf/OVMF_VARS.fd":"` + checksumOf("nvram") + `"}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
	})
	assertChecksumRefused(t, config, err, "missing", "ovmf/OVMF_VARS.fd")
}

// TestArchiver_ChecksumGate_RefusesAPathOutsideTheBundle refuses a manifest
// whose checksum path climbs out of the bundle directory.
func TestArchiver_ChecksumGate_RefusesAPathOutsideTheBundle(t *testing.T) {
	config, _, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"escape","checksums":{"../escape/tpm2-00.permall":"` + checksumOf("state") + `"}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
	})
	if !errors.As(err, &ErrInvalidManifest{}) {
		t.Fatalf("ImportFromFile error = %v, want ErrInvalidManifest", err)
	}
	if _, statErr := os.Stat(config.BundlePath("escape")); !os.IsNotExist(statErr) {
		t.Fatalf("bundle published with an escaping checksum path: stat err %v", statErr)
	}
	assertNoStagingLeft(t, config)
}

// TestArchiver_ChecksumGate_PublishesMatchingFiles imports an archive whose
// files all match the manifest checksums.
func TestArchiver_ChecksumGate_PublishesMatchingFiles(t *testing.T) {
	_, bundle, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"matching","checksums":{"tpm/tpm2-00.permall":"` + checksumOf("state") + `","ovmf/OVMF_VARS.fd":"` + checksumOf("nvram") + `"}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
		{name: "p/ovmf/OVMF_VARS.fd", typeflag: tar.TypeReg, body: "nvram"},
	})
	if err != nil {
		t.Fatalf("ImportFromFile failed: %v", err)
	}
	data, err := os.ReadFile(bundle.TPMState.PermallFile)
	if err != nil {
		t.Fatalf("read imported TPM state: %v", err)
	}
	if string(data) != "state" {
		t.Fatalf("imported TPM state = %q, want %q", data, "state")
	}
}

// TestArchiver_ChecksumGate_ExportRefreshesChangedState exports a bundle
// whose TPM state changed after creation: the archived manifest carries the
// current checksum, so the archive imports.
func TestArchiver_ChecksumGate_ExportRefreshesChangedState(t *testing.T) {
	srcDir := t.TempDir()
	bundleDir := filepath.Join(srcDir, "bundles", "refresh")
	if err := os.MkdirAll(filepath.Join(bundleDir, "tpm"), 0o700); err != nil {
		t.Fatalf("create bundle: %v", err)
	}
	manifest, err := json.Marshal(&Manifest{
		Version:   ManifestVersion,
		ID:        "refresh",
		Mode:      BundleModePreAssigned,
		CreatedAt: time.Now(),
		Checksums: map[string]string{"tpm/tpm2-00.permall": checksumOf("created-state")},
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"), manifest, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "tpm", "tpm2-00.permall"), []byte("running-state"), 0o600); err != nil {
		t.Fatalf("write TPM state: %v", err)
	}

	ctx := context.Background()
	var buf bytes.Buffer
	if err := NewArchiver(&Config{BaseDir: srcDir}, nil).Export(ctx, "refresh", &buf); err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	bundle, err := NewArchiver(&Config{BaseDir: t.TempDir()}, nil).Import(ctx, &buf)
	if err != nil {
		t.Fatalf("Import of an exported used bundle failed: %v", err)
	}
	if got, want := bundle.Manifest.Checksums["tpm/tpm2-00.permall"], checksumOf("running-state"); got != want {
		t.Fatalf("imported checksum = %q, want %q", got, want)
	}
}

// assertImportRefusedUnpublished checks the import failed, published none
// of ids and left no staging behind.
func assertImportRefusedUnpublished(t *testing.T, config *Config, err error, ids ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("ImportFromFile succeeded, want a refusal")
	}
	for _, id := range ids {
		if _, statErr := os.Stat(config.BundlePath(id)); !os.IsNotExist(statErr) {
			t.Errorf("bundle %s published despite the refusal: stat err %v", id, statErr)
		}
	}
	assertNoStagingLeft(t, config)
}

// TestArchiver_ChecksumGate_RefusesADuplicateManifest imports an archive
// whose second manifest.json (an equivalent cleaned path) would replace the
// validated one in the stage: the import is refused and nothing is
// published (#2021 Codex round 5).
func TestArchiver_ChecksumGate_RefusesADuplicateManifest(t *testing.T) {
	config, _, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"dup","checksums":{}}`},
		{name: "p/./manifest.json", typeflag: tar.TypeReg, body: `{"id":"dup","checksums":{"tpm/tpm2-00.permall":"` + checksumOf("original-state") + `"}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "altered-state"},
	})
	assertImportRefusedUnpublished(t, config, err, "dup")
}

// TestArchiver_ChecksumGate_RefusesAStagedManifestWithAnotherID imports an
// archive whose later manifest.json names another bundle ID than the one
// validated: neither ID is published (#2021 Codex round 5).
func TestArchiver_ChecksumGate_RefusesAStagedManifestWithAnotherID(t *testing.T) {
	config, _, err := importChecksumArchive(t, []tarEntry{
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"first","checksums":{}}`},
		{name: "p/tpm/tpm2-00.permall", typeflag: tar.TypeReg, body: "state"},
		{name: "p/manifest.json", typeflag: tar.TypeReg, body: `{"id":"second","checksums":{}}`},
	})
	assertImportRefusedUnpublished(t, config, err, "first", "second")
}
