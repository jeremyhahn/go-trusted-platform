package vtpm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// endlessReader yields bytes forever, as a hostile or broken upload would.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

func assertNoImportStaging(t *testing.T, config *Config) {
	t.Helper()
	entries, err := os.ReadDir(config.BundlesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		t.Fatalf("read bundles dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), importStagingPrefix) {
			t.Fatalf("import staging file %s left behind", e.Name())
		}
	}
}

func TestImport_RefusesUploadBeyondCompressedLimit(t *testing.T) {
	config := &Config{BaseDir: t.TempDir()}
	a := NewArchiver(config, nil)
	a.maxCompressedBytes = 1024

	_, err := a.Import(context.Background(), bytes.NewReader(make([]byte, 4096)))
	var tooLarge ErrArchiveTooLarge
	if !errors.As(err, &tooLarge) {
		t.Fatalf("Import of an oversized upload: got %v, want ErrArchiveTooLarge", err)
	}
	if tooLarge.Limit != 1024 {
		t.Fatalf("limit reported %d, want 1024", tooLarge.Limit)
	}
	assertNoImportStaging(t, config)
}

func TestImport_CancelledContextStopsSpooling(t *testing.T) {
	config := &Config{BaseDir: t.TempDir()}
	a := NewArchiver(config, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, err := a.Import(ctx, io.Reader(endlessReader{}))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Import with a cancelled ctx: got %v, want context.Canceled", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Import kept spooling an endless reader after ctx was cancelled")
	}
	assertNoImportStaging(t, config)
}

func TestDefaultMaxImportCompressedBytesWithinExpandedBudget(t *testing.T) {
	if DefaultMaxImportCompressedBytes <= 0 || DefaultMaxImportCompressedBytes > DefaultMaxImportExpandedBytes {
		t.Fatalf("compressed limit %d must be positive and at most the expanded budget %d",
			DefaultMaxImportCompressedBytes, DefaultMaxImportExpandedBytes)
	}
	if NewArchiver(&Config{BaseDir: t.TempDir()}, nil).maxCompressedBytes != DefaultMaxImportCompressedBytes {
		t.Fatal("NewArchiver does not apply DefaultMaxImportCompressedBytes")
	}
}
