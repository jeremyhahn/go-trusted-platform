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

package deployer

import (
	"context"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/bootstrap/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
)

// containerDataDir is where the container sees DeployConfig.DataDir (the
// bind mount GenerateRunCommand sets up).
const containerDataDir = "/data"

// remoteHost is what staging needs from the deploy target: run a command,
// and stream a file to a path. *SSHClient provides both.
type remoteHost interface {
	Run(ctx context.Context, command string) (string, error)
	CopyFileStream(ctx context.Context, localPath, remotePath string) error
}

// netbootMediaPaths are the container-side paths the staged build's index
// names, which the container is configured with.
type netbootMediaPaths struct {
	tftpDir   string
	arm64IPXE string
}

// stageNetbootMedia copies a netboot media build (container.NetbootMedia)
// into the deploy target's DataDir, laid out as it is in the build, and
// returns the container paths of its TFTP tree and arm64 iPXE. A copy
// already there is kept when its checksums file is the build's and every
// file still matches it; otherwise what the build owns is removed first,
// so no file of an older build survives, and the build is uploaded with
// its checksums last and verified in place.
func stageNetbootMedia(ctx context.Context, host remoteHost, localRoot, remoteRoot string, logger *slog.Logger) (netbootMediaPaths, error) {
	media, err := container.LoadNetbootMedia(localRoot)
	if err != nil {
		return netbootMediaPaths{}, ErrNetbootMediaStage{Step: "reading the build", Err: err}
	}
	paths := netbootMediaPaths{}
	if media.TFTPTree != "" {
		paths.tftpDir = path.Join(containerDataDir, filepath.ToSlash(filepath.Clean(media.TFTPTree)))
	}
	if media.ARM64IPXE != "" {
		paths.arm64IPXE = path.Join(containerDataDir, filepath.ToSlash(filepath.Clean(media.ARM64IPXE)))
	}

	localSums, err := artifacts.FileSHA256(filepath.Join(localRoot, container.NetbootMediaSums))
	if err != nil {
		return paths, ErrNetbootMediaStage{Step: "hashing the checksums file", Err: err}
	}
	verify := verifyCommand(remoteRoot, media)
	current := "cd " + shellQuote(remoteRoot) + " && sha256sum " + container.NetbootMediaSums + " | cut -d' ' -f1"
	if out, err := host.Run(ctx, current); err == nil && strings.TrimSpace(out) == localSums {
		if _, err := host.Run(ctx, verify); err == nil {
			logger.Info("netboot media already staged", slog.String("dir", remoteRoot))
			return paths, nil
		}
	}

	owned := []string{container.NetbootMediaIndex, container.NetbootMediaSums, container.HTTPBootDir}
	if media.ARM64IPXE != "" {
		owned = append(owned, filepath.Clean(media.ARM64IPXE))
	}
	owned = append(owned, ownedDirs(media)...)
	clear := make([]string, 0, len(owned))
	for _, p := range owned {
		clear = append(clear, shellQuote(path.Join(remoteRoot, filepath.ToSlash(p))))
	}
	if _, err := host.Run(ctx, "rm -rf "+strings.Join(clear, " ")); err != nil {
		return paths, ErrNetbootMediaStage{Step: "clearing the previous build", Err: err}
	}

	files, dirs, err := buildFiles(localRoot)
	if err != nil {
		return paths, ErrNetbootMediaStage{Step: "listing the build", Err: err}
	}
	mkdir := make([]string, 0, len(dirs))
	for _, d := range dirs {
		mkdir = append(mkdir, shellQuote(path.Join(remoteRoot, d)))
	}
	if len(mkdir) > 0 {
		if _, err := host.Run(ctx, "mkdir -p "+strings.Join(mkdir, " ")); err != nil {
			return paths, ErrNetbootMediaStage{Step: "creating directories", Err: err}
		}
	}
	for _, f := range files {
		if err := host.CopyFileStream(ctx, filepath.Join(localRoot, filepath.FromSlash(f)), path.Join(remoteRoot, f)); err != nil {
			return paths, ErrNetbootMediaStage{Step: "uploading " + f, Err: err}
		}
	}
	if _, err := host.Run(ctx, verify); err != nil {
		return paths, ErrNetbootMediaStage{Step: "verifying the staged copy", Err: err}
	}
	logger.Info("staged netboot media", slog.String("dir", remoteRoot), slog.Int("files", len(files)))
	return paths, nil
}

// buildFiles lists a build's files and directories, slash-separated and
// relative to root, with the checksums file last so a partial upload is
// never mistaken for a complete one.
// ownedDirs lists the directories a build owns, relative to the data
// directory. The canonical HTTP boot directory is always one, whether or not
// this build has HTTP boot files: a build without them must not leave an
// older build's signed image behind.
func ownedDirs(media *container.NetbootMedia) []string {
	dirs := []string{container.NetbootMediaSetsDir, container.HTTPBootDir}
	for _, p := range []string{media.TFTPTree, media.HTTPBoot} {
		if p != "" {
			dirs = append(dirs, filepath.Clean(p))
		}
	}
	return dirs
}

// verifyCommand checks the staged copy in place: every file the checksums
// list matches, and no file lies under a build-owned directory that the
// checksums do not list (sha256sum -c alone cannot see those).
func verifyCommand(remoteRoot string, media *container.NetbootMedia) string {
	dirs := ownedDirs(media)
	quoted := make([]string, 0, len(dirs))
	for _, d := range dirs {
		quoted = append(quoted, shellQuote(filepath.ToSlash(d)))
	}
	listed := "sed 's/^[0-9a-f]\\{64\\} [ *]//' " + container.NetbootMediaSums + " > \"$l\""
	unlisted := "! find " + strings.Join(quoted, " ") + " -type f 2>/dev/null | grep -vxFf \"$l\""
	return "cd " + shellQuote(remoteRoot) +
		" && sha256sum -c --quiet " + container.NetbootMediaSums +
		" && l=$(mktemp) && " + listed + " && { " + unlisted + "; r=$?; rm -f \"$l\"; exit $r; }"
}

func buildFiles(root string) (files, dirs []string, err error) {
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch {
		case d.IsDir():
			dirs = append(dirs, rel)
		case d.Type().IsRegular():
			if rel != container.NetbootMediaSums {
				files = append(files, rel)
			}
		default:
			return ErrNetbootMediaStage{Step: "listing the build", Err: &ErrFileRead{Path: p, Cause: fs.ErrInvalid}}
		}
		return nil
	})
	sort.Strings(files)
	sort.Strings(dirs)
	return append(files, container.NetbootMediaSums), dirs, err
}
