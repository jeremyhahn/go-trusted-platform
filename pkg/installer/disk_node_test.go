package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"golang.org/x/sys/unix"
)

const fakePartitions = "major minor  #blocks  name\n\n   7        0    4194304 loop0\n 259        4     550912 loop0p1\n 259        5    3642368 loop0p2\n bad  x  1 broken\n"

func TestPartitionMajorMinor(t *testing.T) {
	major, minor, found := partitionMajorMinor([]byte(fakePartitions), "loop0p1")
	if !found || major != 259 || minor != 4 {
		t.Errorf("loop0p1 = %d:%d found=%v", major, minor, found)
	}
	if _, _, found := partitionMajorMinor([]byte(fakePartitions), "loop0p3"); found {
		t.Error("unlisted partition reported found")
	}
	if _, _, found := partitionMajorMinor([]byte(fakePartitions), "broken"); found {
		t.Error("malformed line reported found")
	}
}

// nodeTestManager returns a disk manager reading partitions from a fake file
// and stat results from the given function.
func nodeTestManager(t *testing.T, partitions string, stat func(string) (uint32, uint64, error)) *diskManager {
	t.Helper()
	proc := filepath.Join(t.TempDir(), "partitions")
	if err := os.WriteFile(proc, []byte(partitions), 0o600); err != nil {
		t.Fatal(err)
	}
	return &diskManager{logger: logging.DefaultLogger(), procPartitions: proc, statDevice: stat}
}

func blockStat(major, minor uint32) func(string) (uint32, uint64, error) {
	return func(string) (uint32, uint64, error) { return unix.S_IFBLK, unix.Mkdev(major, minor), nil }
}

func TestRefreshDeviceNodeLeavesCurrentNodesAlone(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "loop0p1")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// The kernel does not list the name: nothing to compare against.
	calls := 0
	dm := nodeTestManager(t, fakePartitions, func(string) (uint32, uint64, error) { calls++; return unix.S_IFBLK, 0, nil })
	if err := dm.refreshDeviceNode(context.Background(), filepath.Join(dir, "vg0-root")); err != nil || calls != 0 {
		t.Errorf("unlisted name: err=%v stat calls=%d", err, calls)
	}
	// A matching device number.
	dm = nodeTestManager(t, fakePartitions, blockStat(259, 4))
	if err := dm.refreshDeviceNode(context.Background(), node); err != nil {
		t.Errorf("current node: %v", err)
	}
	// Not a block device (a regular file of that name).
	dm = nodeTestManager(t, fakePartitions, func(string) (uint32, uint64, error) { return unix.S_IFREG, 0, nil })
	if err := dm.refreshDeviceNode(context.Background(), node); err != nil {
		t.Errorf("regular file: %v", err)
	}
	// The production stat on a regular file also leaves it alone.
	dm = nodeTestManager(t, fakePartitions, nil)
	if err := dm.refreshDeviceNode(context.Background(), node); err != nil {
		t.Errorf("production stat on a regular file: %v", err)
	}
	if _, err := os.Stat(node); err != nil {
		t.Errorf("node removed although current: %v", err)
	}
}

func TestRefreshDeviceNodeReplacesStaleNode(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "loop0p1")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The node carries the minor the partition had before the re-read.
	dm := nodeTestManager(t, fakePartitions, blockStat(259, 1))
	err := dm.refreshDeviceNode(context.Background(), node)
	// The stale node is always removed. Recreating it needs CAP_MKNOD: with
	// it the node comes back with the kernel's numbers, without it the
	// error is reported and no node is left behind.
	var st unix.Stat_t
	statErr := unix.Stat(node, &st)
	switch {
	case err == nil:
		if statErr != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Major(uint64(st.Rdev)) != 259 || unix.Minor(uint64(st.Rdev)) != 4 {
			t.Errorf("recreated node = mode %o rdev %d (stat err %v)", st.Mode, st.Rdev, statErr)
		}
	case !os.IsNotExist(statErr):
		t.Errorf("stale node left behind after error %v (stat err %v)", err, statErr)
	}
}

func TestRefreshDeviceNodeErrors(t *testing.T) {
	node := filepath.Join(t.TempDir(), "loop0p1")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var werr *WrappedError
	// The partition list cannot be read.
	dm := &diskManager{logger: logging.DefaultLogger(), procPartitions: filepath.Join(t.TempDir(), "missing")}
	if err := dm.refreshDeviceNode(context.Background(), node); !errors.As(err, &werr) {
		t.Errorf("unreadable partition list error = %v", err)
	}
	// The node cannot be stat'ed.
	statErr := errors.New("stat boom")
	dm = nodeTestManager(t, fakePartitions, func(string) (uint32, uint64, error) { return 0, 0, statErr })
	if err := dm.refreshDeviceNode(context.Background(), node); !errors.As(err, &werr) || !errors.Is(err, statErr) {
		t.Errorf("stat failure error = %v", err)
	}
	// A stale node that cannot be removed.
	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	lockedNode := filepath.Join(locked, "loop0p1")
	if err := os.WriteFile(lockedNode, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	dm = nodeTestManager(t, fakePartitions, blockStat(259, 1))
	if err := dm.refreshDeviceNode(context.Background(), lockedNode); os.Geteuid() != 0 && (!errors.As(err, &werr) || !errors.Is(err, os.ErrPermission)) {
		t.Errorf("unremovable stale node error = %v", err)
	}
}

func TestWaitAndEnsureDeviceNodeRefresh(t *testing.T) {
	dir := t.TempDir()
	node := filepath.Join(dir, "loop0p1")
	if err := os.WriteFile(node, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// An existing, current node satisfies both without any change.
	dm := nodeTestManager(t, fakePartitions, blockStat(259, 4))
	if err := dm.waitForDevice(context.Background(), node, time.Second); err != nil {
		t.Errorf("waitForDevice on a current node: %v", err)
	}
	if err := dm.EnsureDeviceNode(context.Background(), node, time.Second); err != nil {
		t.Errorf("EnsureDeviceNode on a current node: %v", err)
	}
	// An existing node whose partition list cannot be read surfaces the error.
	dm = &diskManager{logger: logging.DefaultLogger(), procPartitions: filepath.Join(t.TempDir(), "missing")}
	var werr *WrappedError
	if err := dm.waitForDevice(context.Background(), node, time.Second); !errors.As(err, &werr) {
		t.Errorf("waitForDevice refresh error = %v", err)
	}
	if err := dm.EnsureDeviceNode(context.Background(), node, time.Second); !errors.As(err, &werr) {
		t.Errorf("EnsureDeviceNode refresh error = %v", err)
	}
}
