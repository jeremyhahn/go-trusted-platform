package vtpm

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
