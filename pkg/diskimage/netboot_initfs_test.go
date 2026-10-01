package diskimage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
)

// initfsRunner records mkinitfs and mksquashfs, checking the modloop tree
// while it still exists, and produces their outputs.
type initfsRunner struct {
	calls   []string
	modloop []string
	fail    string
}

func (r *initfsRunner) run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == r.fail {
		return nil, errors.New("exit 1")
	}
	switch name {
	case "mkinitfs":
		return nil, os.WriteFile(args[len(args)-2], []byte("initramfs"), 0o644)
	case "mksquashfs":
		err := filepath.WalkDir(args[0], func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(args[0], p)
			r.modloop = append(r.modloop, filepath.ToSlash(rel))
			return err
		})
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(args[1], []byte("modloop"), 0o644)
	}
	return nil, nil
}

func modulesFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "modules-virt.tar.gz")
	if err := os.WriteFile(p, diskimagetest.ModulesTarball(t, diskimagetest.VirtKernelRelease), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenerateNetbootInitfs(t *testing.T) {
	root, out := t.TempDir(), t.TempDir()
	rec := &initfsRunner{}
	res, err := GenerateNetbootInitfs(context.Background(), NetbootInitfsOptions{
		Modules: modulesFile(t), Release: diskimagetest.VirtKernelRelease, Flavour: "virt", OutputDir: out, Root: root, Runner: rec.run,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Initramfs != filepath.Join(out, "initramfs-virt") || res.Modloop != filepath.Join(out, "modloop-virt") {
		t.Errorf("result = %+v", res)
	}
	if _, err := os.Stat(filepath.Join(root, "lib", "modules", diskimagetest.VirtKernelRelease, "modules.dep")); err != nil {
		t.Errorf("modules not installed under the root for mkinitfs: %v", err)
	}
	wantInit := "mkinitfs -b " + root + " -F " + NetbootInitfsFeatures + " -o " + res.Initramfs + " " + diskimagetest.VirtKernelRelease
	if len(rec.calls) != 2 || rec.calls[0] != wantInit || !strings.HasPrefix(rec.calls[1], "mksquashfs ") || !strings.HasSuffix(rec.calls[1], res.Modloop+" -comp xz -noappend -all-root") {
		t.Errorf("calls = %q", rec.calls)
	}
	wantTree := "modules/" + diskimagetest.VirtKernelRelease + "/kernel/drivers/net/virtio_net.ko"
	found := false
	for _, f := range rec.modloop {
		found = found || f == wantTree
	}
	if !found {
		t.Errorf("modloop tree %v lacks %s (Alpine's init mounts modules/<release>)", rec.modloop, wantTree)
	}
}

func TestGenerateNetbootInitfs_Failures(t *testing.T) {
	var stage *StageError
	if _, err := GenerateNetbootInitfs(context.Background(), NetbootInitfsOptions{}); !errors.As(err, &stage) {
		t.Errorf("missing inputs error = %v", err)
	}
	for _, fail := range []string{"mkinitfs", "mksquashfs"} {
		rec := &initfsRunner{fail: fail}
		_, err := GenerateNetbootInitfs(context.Background(), NetbootInitfsOptions{
			Modules: modulesFile(t), Release: diskimagetest.VirtKernelRelease, Flavour: "virt", OutputDir: t.TempDir(), Root: t.TempDir(), Runner: rec.run,
		})
		if !errors.As(err, &stage) || stage.Step != fail {
			t.Errorf("%s failure error = %v", fail, err)
		}
	}
	notTar := filepath.Join(t.TempDir(), "modules.tar.gz")
	if err := os.WriteFile(notTar, []byte("not a tarball"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateNetbootInitfs(context.Background(), NetbootInitfsOptions{
		Modules: notTar, Release: "r", Flavour: "virt", OutputDir: t.TempDir(), Root: t.TempDir(), Runner: (&initfsRunner{}).run,
	}); !errors.As(err, &stage) {
		t.Errorf("bad modules tarball error = %v", err)
	}
}

func TestBuildNetbootInitfs(t *testing.T) {
	rec := &diskimagetest.Runner{}
	staged, err := StageMedia(context.Background(), buildConfigForTest(t, "qemu-virt", rec))
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	res, err := staged.BuildNetbootInitfs(context.Background(), out)
	if err != nil {
		t.Fatal(err)
	}
	if res.Initramfs != filepath.Join(out, "initramfs-virt") || res.Modloop != filepath.Join(out, "modloop-virt") {
		t.Errorf("result = %+v", res)
	}
	run := rec.Joined()[len(rec.Calls)-1]
	for _, want := range []string{"--platform linux/arm64", staged.Kernel.Dir + ":/kernel:ro", out + ":/out", staged.MediaDir + ":/media/cdrom:ro",
		"/media/cdrom/platformd-bin/platformctl-static diskimage netboot-initfs", "--modules /kernel/modules-virt.tar.gz", "--release " + diskimagetest.VirtKernelRelease, "--flavour virt"} {
		if !strings.Contains(run, want) {
			t.Errorf("run %q lacks %q", run, want)
		}
	}

	t.Run("failures", func(t *testing.T) {
		var stage *StageError
		if _, err := (&StagedMedia{}).BuildNetbootInitfs(context.Background(), t.TempDir()); !errors.As(err, &stage) {
			t.Errorf("packaged kernel error = %v", err)
		}
		rec.Fail = "run"
		if _, err := staged.BuildNetbootInitfs(context.Background(), t.TempDir()); !errors.As(err, &stage) || stage.Step != "running the netboot initfs step" {
			t.Errorf("container failure error = %v", err)
		}
		rec.Fail = "build"
		if _, err := staged.BuildNetbootInitfs(context.Background(), t.TempDir()); !errors.As(err, &stage) || stage.Step != "building the builder container image" {
			t.Errorf("image build failure error = %v", err)
		}
	})
}
