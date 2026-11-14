// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

// stageMetaSuffix is appended to the staged ISO's remote path to derive the
// sidecar metadata file path. The sidecar records what was last uploaded so
// freshness checks can avoid re-running `sha256sum` on a multi-GB ISO over
// SSH on every orchestrator invocation.
const stageMetaSuffix = ".meta.json"

// expandTilde resolves a leading "~/" in a filesystem path against the
// caller's $HOME. Bootstrap configs traditionally write SSH key paths as
// "~/.ssh/id_rsa" and Go's os.ReadFile does not perform shell-style
// expansion, so we do it explicitly before handing the path to the SSH
// client. Paths without a leading "~/" are returned unchanged.
func expandTilde(path string) string {
	if !strings.HasPrefix(path, "~/") && path != "~" {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == "~" {
		return home
	}
	return filepath.Join(home, path[2:])
}

// remoteISOClient is the deploy transport seam (deployer.RemoteHost) used
// by sshISOStager. Pulling it out as an interface keeps the freshness logic
// (size + sha256 comparison) unit-testable without spinning up a real SSH
// server, while production code still drives a real SSH connection.
type remoteISOClient = deployer.RemoteHost

// newRemoteISOClient is the factory used by sshISOStager to obtain its
// remote client for the deployer section's transport: a
// *deployer.SSHClient for ssh, a quicagent.Client for quic (registered by
// the quicagent import in deployer_adapter.go). Tests override it to inject
// a fake implementation.
var newRemoteISOClient = deployer.NewRemoteHost

// stageMeta is the on-disk schema for the iso-stager's sidecar metadata
// file. It records the size and lowercase-hex sha256 of the local source
// ISO at the time of the last successful stage.
//
// The sidecar lives next to the staged ISO on the deployer host as
// "<remotePath>.meta.json". On subsequent orchestrator runs, we re-hash the
// local source (we never trust mtime or skip the hash) and compare the
// result against this sidecar; on a match we also confirm the staged
// payload's size still matches before reusing it. This sidecar is purely a
// performance optimization that lets us avoid running `sha256sum` over SSH
// on a multi-GB ISO every time the orchestrator runs.
type stageMeta struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// sshISOStager stages a local ISO on a remote Linux host's bootstrap data
// directory via SSH. It is the production ISOStager for boot_method:
// virtual-media nodes deployed against a Linux jumpbox running the
// platform-pxeboot container.
//
// Idempotency: compares (size, sha256) of the local source against a sidecar
// metadata file ("<remotePath>.meta.json") written next to the staged ISO
// on the deployer host. The local sha256 is always recomputed (no fast
// path); only the remote sha256sum invocation is cached via the sidecar.
// Earlier revisions used (size, mtime) — which is unreliable across
// transports (rsync, scp, container volume mounts all mangle it) — and a
// later revision ran `sha256sum` over SSH on every invocation, which is
// far too slow for multi-GB ISOs. The sidecar gives us byte-level
// integrity with one cheap remote `cat` per invocation.
//
// On a mismatch (or remote-not-found, or sidecar-missing) the file is
// uploaded to a .partial path and atomically renamed by CopyFileStream;
// the sidecar is then re-written atomically.
type sshISOStager struct {
	cfg    *DeployerConfig
	logger *slog.Logger
}

// newISOStager constructs an ISOStager from a DeployerConfig: the ISO is
// uploaded over SSH into the Linux deployer host's data directory, where the
// bootstrap container's smbd serves it.
func newISOStager(cfg *DeployerConfig, logger *slog.Logger) (ISOStager, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig{Field: "deployer", Reason: "must not be nil"}
	}
	if err := cfg.validateRemote(); err != nil {
		return nil, err
	}
	return &sshISOStager{cfg: cfg, logger: logger}, nil
}

// StageVirtualMediaISO uploads localISOPath to the bootstrap container's
// /data host directory and returns the smb:// URL the BMC should mount.
//
// Steps:
//  1. Stat the local file (size) and compute its sha256 (streaming).
//  2. Open SSH to the deployer host.
//  3. Stat the remote staged file.
//     - Missing -> upload.
//  4. Read the sidecar "<remotePath>.meta.json".
//     - Missing or unparseable -> upload.
//     - Sidecar size != local size -> upload.
//     - Sidecar sha256 != local sha256 -> upload.
//     - Remote staged size != sidecar size -> upload (defensive: someone
//     replaced the staged file out-of-band).
//  5. Stream the file via CopyFileStream (atomic .partial rename).
//  6. Write the sidecar atomically (CopyFileStream of the JSON payload).
//  7. Return smb://<deployer.host>/boot/<basename>.
func (s *sshISOStager) StageVirtualMediaISO(ctx context.Context, localISOPath string) (string, error) {
	localInfo, err := os.Stat(localISOPath)
	if err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      err,
		}
	}

	// Compute the local sha256 unconditionally. This is the integrity
	// guarantee the issue calls out: the sidecar is only trusted as a
	// record of what we *last uploaded*, never as a substitute for
	// hashing the current local source.
	localHash, err := sha256File(localISOPath)
	if err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      ErrISOStageFreshnessCheck{Path: localISOPath, Cause: err},
		}
	}

	dc := s.cfg.remoteConfig()
	dc.ApplyDefaults()
	client, err := newRemoteISOClient(&dc)
	if err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      err,
		}
	}
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			s.logger.Warn("bootstrap: iso-stager: ssh close failed",
				slog.String("host", s.cfg.Host),
				slog.String("error", closeErr.Error()))
		}
	}()

	if err := client.Connect(ctx); err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      err,
		}
	}

	dataDir := s.cfg.EffectiveDataDir()
	remotePath := dataDir + "/" + filepath.Base(localISOPath)
	metaPath := remotePath + stageMetaSuffix

	// Ensure remote data directory exists. The Phase 2 deployer creates this
	// for normal PXE flows, but virtual-media boot can run before Phase 2
	// (or with no Phase 2 at all), so we mkdir defensively.
	if _, mkErr := client.Run(ctx, "mkdir -p '"+dataDir+"'"); mkErr != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      mkErr,
		}
	}

	// Decide whether the remote file is current. This is the freshness gate
	// that gives us idempotency on repeat orchestrator runs.
	upload, reason, freshErr := s.shouldUpload(ctx, client, localInfo.Size(), localHash, remotePath, metaPath)
	if freshErr != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      freshErr,
		}
	}
	if !upload {
		s.logger.Info("bootstrap: iso-stager: remote ISO already current, skipping upload",
			slog.String("host", s.cfg.Host),
			slog.String("remote_path", remotePath),
			slog.Int64("size", localInfo.Size()),
			slog.String("sha256", localHash))
		return virtualMediaSMBURL(s.cfg.EffectiveSMBHost(), localISOPath), nil
	}
	s.logger.Info("bootstrap: iso-stager: uploading ISO",
		slog.String("host", s.cfg.Host),
		slog.String("remote_path", remotePath),
		slog.Int64("size", localInfo.Size()),
		slog.String("reason", reason))

	if err := client.CopyFileStream(ctx, localISOPath, remotePath); err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      err,
		}
	}

	// Write the sidecar atomically. CopyFileStream already uses a .partial
	// + rename dance under the hood, so the sidecar is never observed in a
	// half-written state.
	if err := writeStageMeta(ctx, client, metaPath, stageMeta{
		Size:   localInfo.Size(),
		SHA256: localHash,
	}); err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      ErrISOStageFreshnessCheck{Path: metaPath, Cause: err},
		}
	}

	s.logger.Info("bootstrap: iso-stager: ISO upload complete",
		slog.String("host", s.cfg.Host),
		slog.String("remote_path", remotePath),
		slog.Int64("bytes", localInfo.Size()),
		slog.String("sha256", localHash))

	return virtualMediaSMBURL(s.cfg.EffectiveSMBHost(), localISOPath), nil
}

// shouldUpload performs the size + sha256 freshness check using the sidecar
// metadata file. Returns:
//   - upload=false when the staged file is byte-identical to the local one
//     according to the sidecar (and the staged file's size on disk still
//     matches the sidecar's claim).
//   - upload=true with a human-readable reason when the staged file is
//     missing, the sidecar is missing or unparseable, or any size/sha256
//     comparison disagrees.
//   - a non-nil error only for unexpected transport / parse failures the
//     caller should surface as a hard staging failure.
func (s *sshISOStager) shouldUpload(
	ctx context.Context,
	client remoteISOClient,
	localSize int64,
	localHash string,
	remotePath string,
	metaPath string,
) (bool, string, error) {
	remoteSize, _, statErr := client.StatRemote(ctx, remotePath)
	if statErr != nil {
		var notFound deployer.ErrRemoteFileNotFound
		if errors.As(statErr, &notFound) {
			return true, "remote file missing", nil
		}
		return false, "", statErr
	}

	meta, err := readStageMeta(ctx, client, metaPath)
	if err != nil {
		var notFound deployer.ErrRemoteFileNotFound
		if errors.As(err, &notFound) {
			s.logger.Info("bootstrap: iso-stager: sidecar missing, will re-upload",
				slog.String("host", s.cfg.Host),
				slog.String("meta_path", metaPath))
			return true, "sidecar missing", nil
		}
		var badMeta ErrISOStageFreshnessCheck
		if errors.As(err, &badMeta) {
			// Corrupt or unparseable sidecar — treat as missing so we
			// re-stage and rewrite a clean sidecar. Don't propagate as
			// a hard failure: the recovery path is exactly the same as
			// the missing-sidecar path.
			s.logger.Warn("bootstrap: iso-stager: sidecar unparseable, will re-upload",
				slog.String("host", s.cfg.Host),
				slog.String("meta_path", metaPath),
				slog.String("error", badMeta.Error()))
			return true, "sidecar unparseable", nil
		}
		return false, "", err
	}

	if meta.Size != localSize {
		s.logger.Info("bootstrap: iso-stager: sidecar size mismatch, will re-upload",
			slog.String("host", s.cfg.Host),
			slog.Int64("local_size", localSize),
			slog.Int64("sidecar_size", meta.Size))
		return true, "size mismatch", nil
	}

	if !strings.EqualFold(meta.SHA256, localHash) {
		s.logger.Info("bootstrap: iso-stager: sidecar sha256 mismatch, will re-upload",
			slog.String("host", s.cfg.Host),
			slog.String("local_sha256", localHash),
			slog.String("sidecar_sha256", meta.SHA256))
		return true, "sha256 mismatch", nil
	}

	// Defensive: if the staged file's on-disk size disagrees with the
	// sidecar, something replaced the staged ISO out-of-band. Re-upload to
	// get back to a known-good state.
	if remoteSize != meta.Size {
		s.logger.Warn("bootstrap: iso-stager: staged file size disagrees with sidecar, will re-upload",
			slog.String("host", s.cfg.Host),
			slog.Int64("remote_size", remoteSize),
			slog.Int64("sidecar_size", meta.Size))
		return true, "staged size drift", nil
	}

	return false, "", nil
}

// readStageMeta reads the sidecar metadata file at metaPath via the SSH
// client and parses it as JSON. Returns deployer.ErrRemoteFileNotFound when
// the sidecar does not exist; ErrISOStageFreshnessCheck when it exists but
// can't be parsed; and the underlying transport error otherwise.
func readStageMeta(ctx context.Context, client remoteISOClient, metaPath string) (stageMeta, error) {
	out, err := client.Run(ctx, "cat '"+metaPath+"' 2>/dev/null || echo MISSING")
	if err != nil {
		return stageMeta{}, err
	}
	trimmed := strings.TrimSpace(out)
	if trimmed == "" || trimmed == "MISSING" {
		return stageMeta{}, deployer.ErrRemoteFileNotFound{Path: metaPath}
	}
	var meta stageMeta
	if err := json.Unmarshal([]byte(out), &meta); err != nil {
		return stageMeta{}, ErrISOStageFreshnessCheck{Path: metaPath, Cause: err}
	}
	if meta.Size <= 0 {
		return stageMeta{}, ErrISOStageFreshnessCheck{
			Path:  metaPath,
			Cause: ErrInvalidStageMeta{Field: "size", Value: meta.Size},
		}
	}
	if len(meta.SHA256) != sha256.Size*2 {
		return stageMeta{}, ErrISOStageFreshnessCheck{
			Path:  metaPath,
			Cause: ErrInvalidStageMeta{Field: "sha256", Value: meta.SHA256},
		}
	}
	if _, decErr := hex.DecodeString(meta.SHA256); decErr != nil {
		return stageMeta{}, ErrISOStageFreshnessCheck{
			Path:  metaPath,
			Cause: ErrInvalidStageMeta{Field: "sha256", Value: meta.SHA256},
		}
	}
	return meta, nil
}

// writeStageMeta serializes meta to JSON, writes it to a local temp file,
// and uploads it to metaPath via CopyFileStream which guarantees atomic
// rename on the deployer side.
func writeStageMeta(ctx context.Context, client remoteISOClient, metaPath string, meta stageMeta) error {
	payload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp("", "iso-stager-meta-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return client.CopyFileStream(ctx, tmpName, metaPath)
}

// sha256File computes the lowercase hex sha256 digest of localPath. The
// file is streamed through the hasher so multi-GB ISOs don't have to be
// held in memory.
func sha256File(localPath string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
