package vtpm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestService_ListBundles_SkipsImportStaging pins that an import staging
// directory inside the bundle store is never listed, even once extraction
// has written its manifest.json naming the final bundle ID.
func TestService_ListBundles_SkipsImportStaging(t *testing.T) {
	config := createTestConfig(t)
	service, err := NewService(config, nil, &mockCA{})
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}

	writeManifest := func(dir, id string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		data, err := json.Marshal(&Manifest{
			Version:   ManifestVersion,
			ID:        id,
			Mode:      BundleModePreAssigned,
			CreatedAt: time.Now(),
		})
		if err != nil {
			t.Fatalf("marshal manifest: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}

	writeManifest(filepath.Join(config.BundlesDir(), "published"), "published")
	// Two concurrent imports of the same ID, both mid-extraction.
	writeManifest(filepath.Join(config.BundlesDir(), ".import-staged-111"), "staged")
	writeManifest(filepath.Join(config.BundlesDir(), ".import-staged-222"), "staged")

	bundles, err := service.ListBundles(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListBundles failed: %v", err)
	}
	if len(bundles) != 1 || bundles[0].ID != "published" {
		ids := make([]string, 0, len(bundles))
		for _, b := range bundles {
			ids = append(ids, b.ID)
		}
		t.Fatalf("ListBundles = %v, want only [published]", ids)
	}
}
