package uboot

import (
	"path/filepath"
	"testing"
)

// BenchmarkCacheKey measures the per-build cost of hashing every builder
// input; it runs on every `diskimage create`, so it must stay cheap.
func BenchmarkCacheKey(b *testing.B) {
	builder, err := filepath.Abs(filepath.Join("..", "..", "..", "build", "docker", "uboot-builder"))
	if err != nil {
		b.Fatal(err)
	}
	keys := b.TempDir()
	for _, name := range certificateFiles {
		if err := writeFile(keys, name, "cert "+name); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := CacheKey(builder, keys, DefaultVersion, DefaultOwnerGUID); err != nil {
			b.Fatal(err)
		}
	}
}
