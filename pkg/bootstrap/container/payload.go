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

package container

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/artifacts"
)

// PayloadListName is the file in a media set that says what the installer
// it boots needs under /media/cdrom. A node booted over the network has no
// CD; its autoinstall fetches each entry from the set (platform_bin_url),
// checks its digest, and puts it where the CD would have had it. A missing
// or mismatching entry fails the install.
const PayloadListName = "payload.list"

// Payload entry kinds: a file placed at Dest, or a gzip tarball extracted
// into the directory Dest.
const (
	PayloadFile = "file"
	PayloadTar  = "tar"
)

// PayloadEntry is one line of a payload list:
//
//	<sha256> <kind> <dest> <src>
//
// Dest is relative to /media/cdrom, Src to the media set's URL; both are
// slash-separated and stay inside their roots.
type PayloadEntry struct {
	SHA256 string
	Kind   string
	Dest   string
	Src    string
}

// String is the entry's line in a payload list.
func (e PayloadEntry) String() string {
	return strings.Join([]string{e.SHA256, e.Kind, e.Dest, e.Src}, " ")
}

// validate checks one entry.
func (e PayloadEntry) validate() error {
	if len(e.SHA256) != sha256.Size*2 {
		return ErrPayloadList{Reason: "digest " + e.SHA256 + " is not a sha256"}
	}
	if _, err := hex.DecodeString(e.SHA256); err != nil {
		return ErrPayloadList{Reason: "digest " + e.SHA256 + " is not hex"}
	}
	if e.Kind != PayloadFile && e.Kind != PayloadTar {
		return ErrPayloadList{Reason: "kind " + e.Kind + " is not " + PayloadFile + " or " + PayloadTar}
	}
	for _, p := range []string{e.Dest, e.Src} {
		clean := path.Clean(p)
		if p == "" || clean != p || path.IsAbs(p) || clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || strings.ContainsAny(p, " \t\\") {
			return ErrPayloadList{Reason: "path " + p + " must be a clean relative path inside its root"}
		}
	}
	return nil
}

// ParsePayloadList reads a payload list. Blank lines and lines starting
// with # are ignored; every other line is an entry, and a destination may
// appear once.
func ParsePayloadList(r io.Reader) ([]PayloadEntry, error) {
	var entries []PayloadEntry
	seen := map[string]bool{}
	scanner := bufio.NewScanner(r)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, ErrPayloadList{Line: n, Reason: "want <sha256> <kind> <dest> <src>"}
		}
		e := PayloadEntry{SHA256: strings.ToLower(fields[0]), Kind: fields[1], Dest: fields[2], Src: fields[3]}
		if err := e.validate(); err != nil {
			var perr ErrPayloadList
			if errors.As(err, &perr) {
				perr.Line = n
				return nil, perr
			}
			return nil, err
		}
		if seen[e.Dest] {
			return nil, ErrPayloadList{Line: n, Reason: "destination " + e.Dest + " appears twice"}
		}
		seen[e.Dest] = true
		entries = append(entries, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, ErrPayloadList{Reason: "cannot read", Err: err}
	}
	return entries, nil
}

// WritePayloadList writes entries, sorted by destination, as a payload
// list.
func WritePayloadList(w io.Writer, entries []PayloadEntry) error {
	sorted := append([]PayloadEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Dest < sorted[j].Dest })
	if _, err := fmt.Fprintln(w, "# <sha256> <kind> <dest under /media/cdrom> <src under the media set>"); err != nil {
		return err
	}
	for _, e := range sorted {
		if err := e.validate(); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, e.String()); err != nil {
			return err
		}
	}
	return nil
}

// PayloadFromTree lists every regular file under root as a file entry:
// its destination is its path under root, its source srcPrefix joined with
// it (the tree's place in the media set).
func PayloadFromTree(root, srcPrefix string) ([]PayloadEntry, error) {
	var entries []PayloadEntry
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return ErrPayloadList{Reason: p + " is not a regular file"}
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		sum, err := artifacts.FileSHA256(p)
		if err != nil {
			return err
		}
		dest := filepath.ToSlash(rel)
		entries = append(entries, PayloadEntry{SHA256: sum, Kind: PayloadFile, Dest: dest, Src: path.Join(srcPrefix, dest)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

// VerifyPayload checks that every entry's source is in dir with its
// digest.
func VerifyPayload(dir string, entries []PayloadEntry) error {
	for _, e := range entries {
		sum, err := artifacts.FileSHA256(filepath.Join(dir, filepath.FromSlash(e.Src)))
		if err != nil {
			return ErrPayloadList{Reason: "source " + e.Src + " is missing", Err: err}
		}
		if sum != e.SHA256 {
			return ErrPayloadList{Reason: "source " + e.Src + " does not match its digest"}
		}
	}
	return nil
}
