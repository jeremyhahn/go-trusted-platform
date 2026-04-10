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
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/deployer"
)

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

// sshISOStager stages a local ISO on a remote Linux host's bootstrap data
// directory via SSH. It is the production ISOStager for boot_method:
// virtual-media nodes deployed against a Linux jumpbox running the
// platform-pxeboot container.
//
// Idempotency: compares (size, mtime) against the remote file before
// re-uploading. The orchestrator stores ISOs that change rarely (one per
// platform release), so SHA-256 verification would be wasteful overhead.
// On a mismatch (or remote-not-found) the file is uploaded to a .partial
// path and atomically renamed.
type sshISOStager struct {
	cfg    *DeployerConfig
	logger *slog.Logger
}

// newISOStager constructs an ISOStager from a DeployerConfig. Currently only
// the linux target is supported because virtual-media boot is the workflow
// where the bootstrap container runs on a Linux jumpbox. Other targets
// (cisco app-hosting, etc.) can grow their own implementations later.
func newISOStager(cfg *DeployerConfig, logger *slog.Logger) (ISOStager, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig{Field: "deployer", Reason: "must not be nil"}
	}
	if cfg.Host == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.host"}
	}
	if cfg.User == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.user"}
	}
	if cfg.SSHKey == "" {
		return nil, ErrMissingRequiredField{Field: "deployer.ssh_key"}
	}
	return &sshISOStager{cfg: cfg, logger: logger}, nil
}

// StageVirtualMediaISO uploads localISOPath to the bootstrap container's
// /data host directory and returns the smb:// URL the BMC should mount.
//
// Steps:
//  1. Stat the local file (size + mtime).
//  2. Open SSH to the deployer host.
//  3. Stat the remote file. If size + mtime match, skip the upload.
//  4. Otherwise stream the file via CopyFileStream (atomic .partial rename).
//  5. Set the remote mtime to match the local mtime so the next call
//     sees a clean idempotency hit.
//  6. Return smb://<deployer.host>/boot/<basename>.
func (s *sshISOStager) StageVirtualMediaISO(ctx context.Context, localISOPath string) (string, error) {
	localInfo, err := os.Stat(localISOPath)
	if err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      err,
		}
	}

	port := deployer.DefaultSSHPort
	client, err := deployer.NewSSHClient(s.cfg.Host, port, s.cfg.User, expandTilde(s.cfg.SSHKey))
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

	remotePath := deployer.DefaultRemoteDataDir + "/" + filepath.Base(localISOPath)

	// Ensure remote data directory exists. The Phase 2 deployer creates this
	// for normal PXE flows, but virtual-media boot can run before Phase 2
	// (or with no Phase 2 at all), so we mkdir defensively.
	if _, mkErr := client.Run(ctx, "mkdir -p '"+deployer.DefaultRemoteDataDir+"'"); mkErr != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      mkErr,
		}
	}

	// Idempotency check: skip upload if size+mtime match.
	remoteSize, remoteMtime, statErr := client.StatRemote(ctx, remotePath)
	if statErr == nil {
		if remoteSize == localInfo.Size() && remoteMtime == localInfo.ModTime().Unix() {
			s.logger.Info("bootstrap: iso-stager: remote ISO already current, skipping upload",
				slog.String("host", s.cfg.Host),
				slog.String("remote_path", remotePath),
				slog.Int64("size", remoteSize))
			return virtualMediaSMBURL(s.cfg.EffectiveSMBHost(), localISOPath), nil
		}
		s.logger.Info("bootstrap: iso-stager: remote ISO size/mtime mismatch, re-uploading",
			slog.String("host", s.cfg.Host),
			slog.Int64("local_size", localInfo.Size()),
			slog.Int64("remote_size", remoteSize),
			slog.Int64("local_mtime", localInfo.ModTime().Unix()),
			slog.Int64("remote_mtime", remoteMtime))
	} else {
		var notFound deployer.ErrRemoteFileNotFound
		if !errors.As(statErr, &notFound) {
			// Unexpected stat error — bail rather than guess.
			return "", ErrISOStagingFailed{
				LocalPath:  localISOPath,
				RemoteHost: s.cfg.Host,
				Cause:      statErr,
			}
		}
		s.logger.Info("bootstrap: iso-stager: remote ISO missing, uploading",
			slog.String("host", s.cfg.Host),
			slog.String("remote_path", remotePath),
			slog.Int64("size", localInfo.Size()))
	}

	if err := client.CopyFileStream(ctx, localISOPath, remotePath); err != nil {
		return "", ErrISOStagingFailed{
			LocalPath:  localISOPath,
			RemoteHost: s.cfg.Host,
			Cause:      err,
		}
	}

	// Touch remote mtime to match local so the next idempotency check hits.
	// Format: touch -d @<unix-seconds> '<path>'
	touchCmd := "touch -d @" + itoa64(localInfo.ModTime().Unix()) + " '" + remotePath + "'"
	if _, touchErr := client.Run(ctx, touchCmd); touchErr != nil {
		s.logger.Warn("bootstrap: iso-stager: remote mtime sync failed (next run will re-upload)",
			slog.String("host", s.cfg.Host),
			slog.String("error", touchErr.Error()))
	}

	s.logger.Info("bootstrap: iso-stager: ISO upload complete",
		slog.String("host", s.cfg.Host),
		slog.String("remote_path", remotePath),
		slog.Int64("bytes", localInfo.Size()))

	return virtualMediaSMBURL(s.cfg.EffectiveSMBHost(), localISOPath), nil
}

// itoa64 is a tiny dependency-free int64 → decimal-string formatter so
// iso_stager.go doesn't have to import strconv just for one call.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}
