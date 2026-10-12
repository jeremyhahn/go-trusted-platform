package initrd

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/disklessroot"
)

const (
	defaultDisklessWorkDir   = "/run/platform/diskless-root"
	defaultDisklessRootMount = "/sysroot"
	defaultDisklessMapper    = "platform-root"
	// disklessMapperDir is where device-mapper publishes the verity target.
	disklessMapperDir = "/dev/mapper"
	// defaultDisklessOverlaySize caps the tmpfs that takes the node's runtime
	// writes. A tmpfs size is a ceiling, not a reservation; without one a
	// runaway writer fills RAM until the kernel kills platformd.
	defaultDisklessOverlaySize = "25%"
	// disklessFetchTimeout bounds one artifact download end to end, and
	// disklessConnectTimeout the connect, TLS and response-header phases, so
	// a boot server that stops answering fails the boot instead of hanging it.
	disklessFetchTimeout   = 10 * time.Minute
	disklessConnectTimeout = 30 * time.Second
)

// DisklessRunner runs host commands needed in the initramfs.
type DisklessRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

// DisklessRootConfig describes a stateless HTTP root protected by dm-verity.
// Params come from the signed UKI command line; the rest are local defaults.
type DisklessRootConfig struct {
	Params      disklessroot.BootParams
	WorkDir     string
	RootMount   string
	Mapper      string
	OverlaySize string
	Client      *http.Client
	Runner      DisklessRunner
}

// DisklessRootMount describes the mounted stateless root.
type DisklessRootMount struct {
	RootFSPath string
	VerityPath string
	DataLoop   string
	HashLoop   string
	MapperPath string
	LowerDir   string
	RootMount  string
}

// DisklessFetchError reports a failed image fetch.
type DisklessFetchError struct {
	URL string
	Err error
}

func (e *DisklessFetchError) Error() string {
	return "diskless root: fetch " + e.URL + ": " + e.Err.Error()
}

func (e *DisklessFetchError) Unwrap() error {
	return e.Err
}

// DisklessHTTPStatusError reports a non-success image fetch response.
type DisklessHTTPStatusError struct {
	Status string
}

func (e *DisklessHTTPStatusError) Error() string {
	return "unexpected HTTP status " + e.Status
}

// DisklessSizeError reports an artifact whose length is not the signed size:
// a truncated download, or a server sending more than the node agreed to hold
// in RAM.
type DisklessSizeError struct {
	URL  string
	Want int64
	Got  int64
}

func (e *DisklessSizeError) Error() string {
	return "diskless root: " + e.URL + ": got " + strconv.FormatInt(e.Got, 10) +
		" bytes, the signed size is " + strconv.FormatInt(e.Want, 10)
}

// DisklessCommandError reports a failed initramfs command.
type DisklessCommandError struct {
	Step   string
	Err    error
	Output string
}

func (e *DisklessCommandError) Error() string {
	msg := "diskless root: " + e.Step + ": " + e.Err.Error()
	if e.Output != "" {
		msg += ": " + e.Output
	}
	return msg
}

func (e *DisklessCommandError) Unwrap() error {
	return e.Err
}

// MountDisklessRoot fetches the root image and its hash tree into RAM, opens
// them through dm-verity under the signed root hash, mounts the verified
// squashfs read-only and overlays it with a size-capped tmpfs at RootMount.
// Nothing is mounted unless dm-verity accepted the image; on any failure every
// step already taken is undone, newest first.
func MountDisklessRoot(ctx context.Context, cfg DisklessRootConfig) (*DisklessRootMount, error) {
	cfg.withDefaults()
	params := cfg.Params
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return nil, &WrappedError{Msg: "create diskless work directory", Err: err}
	}
	result := &DisklessRootMount{
		RootFSPath: filepath.Join(cfg.WorkDir, disklessroot.RootFSFile),
		VerityPath: filepath.Join(cfg.WorkDir, disklessroot.VerityFile),
		MapperPath: filepath.Join(disklessMapperDir, cfg.Mapper),
		LowerDir:   filepath.Join(cfg.WorkDir, "lower"),
		RootMount:  cfg.RootMount,
	}
	overlay := filepath.Join(cfg.WorkDir, "overlay")
	upper := filepath.Join(overlay, "upper")
	overlayWork := filepath.Join(overlay, "work")

	// Cleanups run on a context that outlives a cancelled boot context, or a
	// timed-out fetch would leave its loop devices behind.
	cleanupCtx := context.WithoutCancel(ctx)
	run := cfg.Runner
	var undo []func()
	mounted := false
	defer func() {
		if mounted {
			return
		}
		for i := len(undo) - 1; i >= 0; i-- {
			undo[i]()
		}
	}()

	undo = append(undo, func() { removeDisklessArtifacts(result.RootFSPath, result.VerityPath) })
	if err := fetchDiskless(ctx, cfg.Client, params.RootFSURL, result.RootFSPath, params.RootFSSize); err != nil {
		return nil, err
	}
	if err := fetchDiskless(ctx, cfg.Client, params.VerityURL, result.VerityPath, params.VeritySize); err != nil {
		return nil, err
	}

	var err error
	if result.DataLoop, err = runDiskless(ctx, run, "attach the root image", "losetup", "--find", "--show", "--read-only", result.RootFSPath); err != nil {
		return nil, err
	}
	undo = append(undo, func() { disklessCleanup(cleanupCtx, run, "losetup", "-d", result.DataLoop) })
	if result.HashLoop, err = runDiskless(ctx, run, "attach the hash tree", "losetup", "--find", "--show", "--read-only", result.VerityPath); err != nil {
		return nil, err
	}
	undo = append(undo, func() { disklessCleanup(cleanupCtx, run, "losetup", "-d", result.HashLoop) })

	// Every verity parameter is pinned here or signed: the hash tree has no
	// superblock, so nothing fetched over the network chooses the algorithm,
	// the block sizes, the data length or the salt. The table goes straight
	// to device-mapper, whose dmsetup every node and its initramfs carry, so
	// the boot needs no cryptsetup.
	if _, err := runDiskless(ctx, run, "open dm-verity", "dmsetup", "create", cfg.Mapper, "--readonly",
		"--table", verityTable(params, result.DataLoop, result.HashLoop)); err != nil {
		return nil, err
	}
	undo = append(undo, func() { disklessCleanup(cleanupCtx, run, "dmsetup", "remove", cfg.Mapper) })

	for _, dir := range []string{result.LowerDir, cfg.RootMount, overlay} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, &WrappedError{Msg: "create diskless mount directory", Err: err}
		}
	}
	if _, err := runDiskless(ctx, run, "mount the verified squashfs", "mount", "-t", "squashfs", "-o", "ro", result.MapperPath, result.LowerDir); err != nil {
		return nil, err
	}
	undo = append(undo, func() { disklessCleanup(cleanupCtx, run, "umount", result.LowerDir) })
	if _, err := runDiskless(ctx, run, "mount the overlay tmpfs", "mount", "-t", "tmpfs", "-o", "mode=755,size="+cfg.OverlaySize, "tmpfs", overlay); err != nil {
		return nil, err
	}
	undo = append(undo, func() { disklessCleanup(cleanupCtx, run, "umount", overlay) })
	for _, dir := range []string{upper, overlayWork} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, &WrappedError{Msg: "create diskless overlay directory", Err: err}
		}
	}
	overlayOptions := "lowerdir=" + result.LowerDir + ",upperdir=" + upper + ",workdir=" + overlayWork
	if _, err := runDiskless(ctx, run, "mount the root overlay", "mount", "-t", "overlay", "-o", overlayOptions, "overlay", cfg.RootMount); err != nil {
		return nil, err
	}
	mounted = true
	return result, nil
}

// verityTable is the dm-verity target for the root: format version 1, the
// pinned block sizes and hash, the hash tree from its first block (there is
// no superblock), the signed root hash and salt, and a panic on any block
// that does not verify.
func verityTable(params disklessroot.BootParams, dataDev, hashDev string) string {
	blockSize := strconv.Itoa(disklessroot.BlockSize)
	dataBlocks := params.DataBlocks()
	sectors := dataBlocks * (disklessroot.BlockSize / 512)
	return strings.Join([]string{
		"0", strconv.FormatInt(sectors, 10), "verity", "1",
		dataDev, hashDev, blockSize, blockSize,
		strconv.FormatInt(dataBlocks, 10), "0",
		disklessroot.HashAlgorithm, params.RootHash, params.Salt,
		"1", "panic_on_corruption",
	}, " ")
}

func (c *DisklessRootConfig) withDefaults() {
	if c.WorkDir == "" {
		c.WorkDir = defaultDisklessWorkDir
	}
	if c.RootMount == "" {
		c.RootMount = defaultDisklessRootMount
	}
	if c.Mapper == "" {
		c.Mapper = defaultDisklessMapper
	}
	if c.OverlaySize == "" {
		c.OverlaySize = defaultDisklessOverlaySize
	}
	if c.Client == nil {
		c.Client = newDisklessClient()
	}
	if c.Runner == nil {
		c.Runner = runDisklessCommand
	}
}

// newDisklessClient is the artifact client: no proxy from the environment,
// and every phase of the exchange bounded.
func newDisklessClient() *http.Client {
	return &http.Client{
		Timeout: disklessFetchTimeout,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: disklessConnectTimeout}).DialContext,
			TLSHandshakeTimeout:   disklessConnectTimeout,
			ResponseHeaderTimeout: disklessConnectTimeout,
		},
	}
}

// fetchDiskless downloads exactly size bytes from rawURL into dest. It never
// reads more than one byte past the signed size, so a hostile or broken server
// cannot fill RAM, and a short body is an error rather than a smaller image.
func fetchDiskless(ctx context.Context, client *http.Client, rawURL, dest string, size int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return &DisklessFetchError{URL: rawURL, Err: err}
	}
	resp, err := client.Do(req)
	if err != nil {
		return &DisklessFetchError{URL: rawURL, Err: err}
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "[DISKLESS] WARNING: close fetch body: %v\n", closeErr)
		}
	}()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return &DisklessFetchError{URL: rawURL, Err: &DisklessHTTPStatusError{Status: resp.Status}}
	}
	if resp.ContentLength >= 0 && resp.ContentLength != size {
		return &DisklessSizeError{URL: rawURL, Want: size, Got: resp.ContentLength}
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return &DisklessFetchError{URL: rawURL, Err: err}
	}
	written, copyErr := io.Copy(out, io.LimitReader(resp.Body, size+1))
	closeErr := out.Close()
	if copyErr != nil {
		return &DisklessFetchError{URL: rawURL, Err: copyErr}
	}
	if closeErr != nil {
		return &DisklessFetchError{URL: rawURL, Err: closeErr}
	}
	if written != size {
		return &DisklessSizeError{URL: rawURL, Want: size, Got: written}
	}
	return nil
}

func runDisklessCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func runDiskless(ctx context.Context, run DisklessRunner, step, name string, args ...string) (string, error) {
	out, err := run(ctx, name, args...)
	if err != nil {
		return "", &DisklessCommandError{Step: step, Err: err, Output: strings.TrimSpace(string(out))}
	}
	return strings.TrimSpace(string(out)), nil
}

// disklessCleanup undoes one step of a failed mount. It cannot fail the boot
// any further than it already has, so a failure is reported, not returned.
func disklessCleanup(ctx context.Context, run DisklessRunner, name string, args ...string) {
	if out, err := run(ctx, name, args...); err != nil {
		fmt.Fprintf(os.Stderr, "[DISKLESS] WARNING: cleanup %s %s: %v: %s\n", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

// removeDisklessArtifact frees the RAM a fetched artifact holds. An artifact
// never fetched is already gone, so its absence is not an error.
func removeDisklessArtifact(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return &WrappedError{Msg: "remove " + path, Err: err}
	}
	return nil
}

// removeDisklessArtifacts undoes the fetches of a failed mount. Like any
// cleanup it cannot fail the boot further, so a failure is reported and the
// remaining artifacts are still removed.
func removeDisklessArtifacts(paths ...string) {
	for _, path := range paths {
		if err := removeDisklessArtifact(path); err != nil {
			fmt.Fprintf(os.Stderr, "[DISKLESS] WARNING: %v\n", err)
		}
	}
}
