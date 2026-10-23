//go:build integration

package netboot

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/netboot"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/rpi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/rpibootsig"
)

// httpBootHost is the PXE test environment's HTTP server, which serves the
// data directory under /data/ as the container does.
const httpBootHost = "10.99.99.1:8080"

// httpProbeReport is the JSON `platformctl bootstrap probe rpi-http -o json`
// prints.
type httpProbeReport struct {
	URL       string   `json:"url"`
	Bytes     int64    `json:"bytes"`
	SHA256    string   `json:"sha256"`
	TargetSoC string   `json:"target_soc"`
	Ramdisk   []string `json:"ramdisk"`
}

// TestRaspberryPiSignedHTTPBoot proves the boot server's side of the Pi's
// signed HTTP boot: the PXE test environment serves the files a netboot media
// build stages under data/http-boot, and the Pi's bootloader stage — probed
// from its own network namespace on the boot segment, through the operator's
// command — fetches boot.img and boot.sig, checks the EEPROM's key against the
// OTP key hash, verifies the signature and mounts the image. It also proves
// the refusals SIGNED_BOOT exists for: an OTP hash of another key and an image
// altered after signing.
//
// The fleet key here is an in-process RSA key. The KMS-held key is covered by
// the netboot builder's unit tests against the platform client; this suite has
// no KMS service to sign with.
func TestRaspberryPiSignedHTTPBoot(t *testing.T) {
	in := requireInputs(t)
	logger := logging.DefaultLogger()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	treeDir, _ := stageRPiTree(t, ctx, in, "rpi-httpboot-tree", logger)

	fleetKey, err := rsa.GenerateKey(rand.Reader, rpibootsig.KeyBits)
	require.NoError(t, err)
	model, err := rpi.LookupModel("rpi4")
	require.NoError(t, err)

	// The container's layout: data/http-boot under the directory the HTTP
	// server serves as /data/.
	dataDir := filepath.Join(in.workDir, "rpi-httpboot-data")
	require.NoError(t, os.RemoveAll(dataDir))
	bootDir := filepath.Join(dataDir, container.HTTPBootDir)
	staged, err := netboot.StageHTTPBoot(netboot.HTTPBootInputs{
		BootTree:  treeDir,
		TargetSoC: model.SoC,
		Signer:    fleetKey,
		Timestamp: time.Unix(1790856000, 0),
	}, bootDir)
	require.NoError(t, err)

	cfg := ipxe.DefaultTestEnvConfig()
	cfg.DataDir = dataDir
	cfg.LocalFilesDir = filepath.Join(in.workDir, "pxe-files")
	require.NoError(t, os.MkdirAll(cfg.LocalFilesDir, 0o755))
	cfg.BootEntries = []ipxe.BootEntry{{Name: "unused", Description: "unused", Kernel: "http://10.99.99.1:8080/files/none"}}
	startPXEEnv(t, ctx, cfg, logger)
	ns := attachProbeNamespace(t, cfg.BridgeName)

	pubkey := filepath.Join(bootDir, container.HTTPBootPublicKey)
	probe := func(otpHash string) (httpProbeReport, string, error) {
		probeCtx, cancelProbe := context.WithTimeout(ctx, eepromProbeTimeout)
		defer cancelProbe()
		return runHTTPProbeCLI(t, probeCtx, in.platformctl, ns, pubkey, otpHash)
	}

	t.Run("a signed image boots", func(t *testing.T) {
		report, log, err := probe(staged.KeyHashHex())
		require.NoError(t, err, log)

		assert.Equal(t, "http://"+httpBootHost+"/"+(&container.NetbootMedia{HTTPBoot: container.HTTPBootDir}).HTTPBootPath(), report.URL)
		assert.Equal(t, int64(staged.ImageSize), report.Bytes)
		assert.Equal(t, fileSHA256(t, filepath.Join(bootDir, container.HTTPBootImage)), report.SHA256)
		assert.Equal(t, model.SoC, report.TargetSoC)
		assert.Contains(t, report.Ramdisk, "config.txt")
		assert.Contains(t, report.Ramdisk, "kernel8.img")
	})

	t.Run("an OTP hash of another key is refused", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, rpibootsig.KeyBits)
		require.NoError(t, err)
		otherHash, err := rpibootsig.KeyHash(&other.PublicKey)
		require.NoError(t, err)

		_, log, err := probe(hex.EncodeToString(otherHash[:]))
		assert.Error(t, err, "the EEPROM's key must hash to the OTP value: %s", log)
	})

	t.Run("an image altered after signing is refused", func(t *testing.T) {
		imagePath := filepath.Join(bootDir, container.HTTPBootImage)
		image, err := os.ReadFile(imagePath)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, os.WriteFile(imagePath, image, 0o644)) })
		tampered := append([]byte(nil), image...)
		tampered[len(tampered)-1] ^= 0xff
		require.NoError(t, os.WriteFile(imagePath, tampered, 0o644))

		_, log, err := probe(staged.KeyHashHex())
		assert.Error(t, err, "boot.img no longer matches boot.sig: %s", log)
	})
}

// runHTTPProbeCLI runs `platformctl bootstrap probe rpi-http` inside the
// namespace. It returns the JSON report of a boot, the log the command printed,
// and the command's error: a refusal exits non-zero, which the caller asserts.
func runHTTPProbeCLI(t *testing.T, ctx context.Context, platformctl, ns, pubkey, otpHash string) (httpProbeReport, string, error) {
	t.Helper()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", ns, platformctl, "bootstrap", "probe", "rpi-http",
		"--http-host", httpBootHost,
		"--pubkey", pubkey,
		"--otp-key-hash", otpHash,
		"-o", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	log := string(tail(stderr.Bytes(), 4096))
	var report httpProbeReport
	if runErr != nil {
		return report, log, runErr
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &report), "report: %s\nlog: %s", stdout.String(), log)
	return report, log, nil
}
