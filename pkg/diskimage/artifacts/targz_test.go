package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeMember appends one gzip member holding a tar stream of files; with
// trailer false the stream has no end-of-archive marker, as in an .apk.
func writeMember(t *testing.T, out *bytes.Buffer, files map[string]string, trailer bool) {
	t.Helper()
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if trailer {
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	} else if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractTarGz(t *testing.T) {
	dir := t.TempDir()

	t.Run("an apk's members are walked whole", func(t *testing.T) {
		var apk bytes.Buffer
		writeMember(t, &apk, map[string]string{".PKGINFO": "pkg=x"}, false)
		writeMember(t, &apk, map[string]string{"boot/start4.elf": "s", "boot/overlays/a.dtbo": "o", "lib/x": "no"}, false)
		path := filepath.Join(dir, "x-1.0-r0.apk")
		if err := os.WriteFile(path, apk.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		dest := t.TempDir()
		written, err := ExtractTarGz(path, "boot/", dest, func(string) bool { return true })
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(written)
		if len(written) != 2 || written[0] != "overlays/a.dtbo" || written[1] != "start4.elf" {
			t.Errorf("written = %v", written)
		}
		if got, err := os.ReadFile(filepath.Join(dest, "overlays", "a.dtbo")); err != nil || string(got) != "o" {
			t.Errorf("overlays/a.dtbo = %q, %v", got, err)
		}
	})

	t.Run("keep selects, and escaping paths are skipped", func(t *testing.T) {
		var tgz bytes.Buffer
		writeMember(t, &tgz, map[string]string{"./boot/vmlinuz-rpi": "k", "boot/vmlinuz-lts": "l", "boot/../../escape": "x"}, true)
		path := filepath.Join(dir, "netboot.tar.gz")
		if err := os.WriteFile(path, tgz.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		dest := t.TempDir()
		written, err := ExtractTarGz(path, "boot/", dest, func(rel string) bool { return rel != "vmlinuz-lts" })
		if err != nil {
			t.Fatal(err)
		}
		if len(written) != 1 || written[0] != "vmlinuz-rpi" {
			t.Errorf("written = %v", written)
		}
	})

	t.Run("failures are ExtractErrors", func(t *testing.T) {
		var tgz bytes.Buffer
		writeMember(t, &tgz, map[string]string{"boot/a": "0123456789"}, true)
		good := filepath.Join(dir, "good.tar.gz")
		truncated := filepath.Join(dir, "truncated.tar.gz")
		notGzip := filepath.Join(dir, "plain")
		blocker := filepath.Join(dir, "blocker")
		for p, data := range map[string][]byte{good: tgz.Bytes(), truncated: tgz.Bytes()[:tgz.Len()-20], notGzip: []byte("plain"), blocker: nil} {
			if err := os.WriteFile(p, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		all := func(string) bool { return true }
		for name, run := range map[string]func() error{
			"missing archive": func() error {
				_, err := ExtractTarGz(filepath.Join(dir, "absent"), "boot/", t.TempDir(), all)
				return err
			},
			"not gzip":          func() error { _, err := ExtractTarGz(notGzip, "boot/", t.TempDir(), all); return err },
			"truncated":         func() error { _, err := ExtractTarGz(truncated, "boot/", t.TempDir(), all); return err },
			"unwritable output": func() error { _, err := ExtractTarGz(good, "boot/", filepath.Join(blocker, "out"), all); return err },
		} {
			var ext *ExtractError
			if err := run(); !errors.As(err, &ext) {
				t.Errorf("%s: error = %v, want an ExtractError", name, err)
			} else if errors.Unwrap(err) == nil || ext.Error() == "" {
				t.Errorf("%s: the error does not carry its cause", name)
			}
		}
	})
}
