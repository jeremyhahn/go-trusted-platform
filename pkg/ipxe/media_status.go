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

package ipxe

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultProcRoot is the procfs mount the media-status scan reads.
const defaultProcRoot = "/proc"

// MediaOpener is one process's cumulative record on a file. The media
// watcher keeps one per (file, process name, client) so a caller can ask
// specifically what smbd — the BMC's virtual-media client — did for one
// BMC, and when, without any other process's or BMC's activity blending
// in.
type MediaOpener struct {
	// Name is the process's /proc/<pid>/comm.
	Name string `json:"name"`
	// Client is the remote address the process serves when its process
	// title says so, and "" otherwise. Debian smbd retitles each
	// per-connection worker to "smbd: client [<ip>]"; Alpine/musl smbd
	// titles it "smbd[<ip>]", and /proc/<pid>/comm truncates that to 15
	// bytes, so the captured client may be an IP prefix with no closing
	// bracket (measured live: comm "smbd[192.168.50"). It is what lets
	// the orchestrator tell one BMC's reads of a shared ISO from
	// another's.
	Client string `json:"client,omitempty"`
	// ClientTruncated is true when Client was cut short by the kernel's
	// 15-byte comm limit and is therefore a prefix of the real address,
	// not the address itself. Consumers must match it as a prefix.
	ClientTruncated bool `json:"client_truncated,omitempty"`
	// Opens is the number of descriptors this process held at the last
	// sample; 0 once it closed the file.
	Opens int `json:"opens"`
	// OpenSamples counts the samples in which this process held the
	// file open, since the watcher started.
	OpenSamples int `json:"open_samples"`
	// OpenEvents counts the samples in which this process was found
	// holding the file after not holding it at the previous sample: a
	// fresh open, as opposed to a descriptor kept from before.
	OpenEvents int `json:"open_events"`
	// PosChanges counts the samples in which the sum of this process's
	// descriptor offsets differed from the previous sample: data moved
	// through a descriptor, whether or not it was newly opened.
	PosChanges int `json:"pos_changes"`
	// MaxPos is the largest offset ever seen on one of its descriptors.
	MaxPos int64 `json:"max_pos"`
	// FirstSeen and LastSeen bracket the samples in which it held the
	// file; LastActivity is the last sample that counted an open event
	// or a position change.
	FirstSeen    time.Time `json:"first_seen,omitempty"`
	LastSeen     time.Time `json:"last_seen,omitempty"`
	LastActivity time.Time `json:"last_activity,omitempty"`

	// posSum is the last sample's summed descriptor offsets, the state
	// PosChanges is computed against; heldPrev records whether the
	// process held the file at the previous sample, the state OpenEvents
	// is computed against. Neither is part of the wire record.
	posSum   int64
	heldPrev bool
}

// Activity is the number of samples that showed this process doing
// something new with the file — opening it or moving through it — the
// count a client compares across an attempt boundary.
func (o *MediaOpener) Activity() int {
	return o.OpenEvents + o.PosChanges
}

// MediaOpen describes one file under DataDir that some process in the
// container has held open since the watcher started. For an ISO served
// over SMB virtual media the opener is smbd acting for the BMC, and the
// BMC reads the file only while the host firmware is reading the
// emulated CD — so smbd activity on the ISO is evidence the host booted
// the media, and its position changes are how far it got.
type MediaOpen struct {
	// Path is the file's path on the container filesystem.
	Path string `json:"path"`
	// Opens is the number of descriptors open on the file at the last
	// sample across all processes other than pxeboot itself.
	Opens int `json:"opens"`
	// MaxPos is the largest offset ever seen among those descriptors.
	MaxPos int64 `json:"max_pos"`
	// OpenSamples counts the samples in which the file was open by any
	// process since the watcher started.
	OpenSamples int `json:"open_samples"`
	// FirstSeen and LastSeen bracket the samples in which the file was
	// open. Zero when it never was.
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	// Openers is the per-(process name, client) record, sorted by name
	// then client.
	Openers []MediaOpener `json:"openers,omitempty"`
}

// Opener returns the record for one process name serving no particular
// client, or nil. Use OpenersNamed for per-client records.
func (m *MediaOpen) Opener(name string) *MediaOpener {
	for i := range m.Openers {
		if m.Openers[i].Name == name && m.Openers[i].Client == "" {
			return &m.Openers[i]
		}
	}
	return nil
}

// OpenersNamed returns every record for one process name, across
// clients. A worker whose comm IS its title — Alpine/musl smbd names its
// per-connection workers "smbd[<ip>]", truncated by the kernel to 15
// bytes — matches by the "<name>[" prefix; exact-only matching would
// miss every such worker (the #126 false-abort).
func (m *MediaOpen) OpenersNamed(name string) []MediaOpener {
	var out []MediaOpener
	prefix := name + "["
	for i := range m.Openers {
		if m.Openers[i].Name == name || strings.HasPrefix(m.Openers[i].Name, prefix) {
			out = append(out, m.Openers[i])
		}
	}
	return out
}

// openerKey identifies an opener record: process name plus client, and
// whether the client survived only as a truncated prefix.
type openerKey struct {
	name      string
	client    string
	truncated bool
}

// MediaStatus is the body of GET /media/status: the media watcher's
// cumulative record of files under DataDir.
type MediaStatus struct {
	// DataDir is the directory the watcher covers.
	DataDir string `json:"data_dir"`
	// Since is when the watcher started recording.
	Since time.Time `json:"since"`
	// SampledAt is when the record was last updated.
	SampledAt time.Time `json:"sampled_at"`
	// Interval is the sampling cadence.
	Interval time.Duration `json:"interval"`
	// Files lists every file seen open since Since, sorted by path; a
	// file not open at the last sample has Opens 0 and keeps its history.
	// Empty when nothing was ever open.
	Files []MediaOpen `json:"files"`
}

// mediaScan is one instant's view of the open files under DataDir, as
// scanMediaOpens reads it from /proc; the watcher folds a sequence of
// these into MediaStatus.
type mediaScan struct {
	dataDir string
	files   map[string]*scannedFile
}

// scannedFile is one open file in a scan, with its descriptors grouped
// by the holding process's name and client.
type scannedFile struct {
	path   string
	opens  int
	maxPos int64
	byName map[openerKey]*scannedOpener
}

// scannedOpener is one process name's descriptors on a file in a scan.
type scannedOpener struct {
	opens  int
	maxPos int64
	posSum int64
}

// handleMediaStatus serves GET /media/status: the media watcher's
// cumulative record of which files under DataDir have been open, by
// whom, and how far they were read. pxeboot and smbd share the
// container's PID namespace, so a sampled scan of /proc/*/fd is the whole
// implementation — no smbstatus, no exec.
func (s *HTTPServer) handleMediaStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	watcher := s.mediaWatcher.Load()
	if s.config.DataDir == "" || watcher == nil {
		http.Error(w, "media watcher not running (no data directory)", http.StatusServiceUnavailable)
		return
	}
	if err := watcher.healthy(); err != nil {
		// A stale or never-populated record is not evidence of anything;
		// 503 tells the probe to keep asking rather than to conclude.
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(watcher.status()); err != nil {
		s.logger.Errorf("media status: encode failed: error=%v", err)
	}
}

// startMediaWatcher launches the sampler for the server's lifetime when
// a data directory is configured. Its first sample runs before this
// returns so the first /media/status already has a record; a scan
// failure there is logged and the route answers 503 until a scan
// succeeds, the watcher retrying on every tick.
func (s *HTTPServer) startMediaWatcher(ctx context.Context) {
	if s.config.DataDir == "" {
		return
	}
	watcher := newMediaWatcher(s.procRoot(), s.config.DataDir, os.Getpid(), 0, nil)
	if err := watcher.sample(); err != nil {
		s.logger.Errorf("media watcher: initial proc scan failed; /media/status answers 503 until one succeeds: proc=%s error=%v", s.procRoot(), err)
	}
	s.mediaWatcher.Store(watcher)
	go watcher.run(ctx)
}

// procRoot returns the procfs root the scan reads; tests substitute a
// fake tree through procRootOverride.
func (s *HTTPServer) procRoot() string {
	if s.procRootOverride != "" {
		return s.procRootOverride
	}
	return defaultProcRoot
}

// scanMediaOpens walks procRoot/<pid>/fd for every process except
// selfPID and reports the open files that resolve under dataDir, with
// their descriptors grouped by the holder's /proc/<pid>/comm. A process
// that vanishes mid-scan, an unreadable fd table, or a dangling link is
// skipped rather than failing the scan: the answer is "what is open
// now", and a race with a closing descriptor is not an error. A holder
// whose comm cannot be read is recorded under an empty name, which no
// client treats as smbd.
func scanMediaOpens(procRoot, dataDir string, selfPID int) (*mediaScan, error) {
	absData, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, ErrMediaScanFailed{ProcRoot: procRoot, Cause: err}
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, ErrMediaScanFailed{ProcRoot: procRoot, Cause: err}
	}

	scan := &mediaScan{dataDir: absData, files: make(map[string]*scannedFile)}
	for _, entry := range entries {
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || !entry.IsDir() || pid == selfPID {
			continue
		}
		fdDir := filepath.Join(procRoot, entry.Name(), "fd")
		fds, readErr := os.ReadDir(fdDir)
		if readErr != nil {
			continue
		}
		comm := readComm(filepath.Join(procRoot, entry.Name(), "comm"))
		client, truncated := readClientFromTitle(filepath.Join(procRoot, entry.Name(), "cmdline"))
		if client == "" {
			// Alpine/musl smbd carries its title in comm ("smbd[<ip>]",
			// truncated to 15 bytes) while cmdline keeps the plain argv.
			client, truncated = smbdWorkerClient(comm)
		}
		key := openerKey{name: comm, client: client, truncated: truncated}
		for _, fd := range fds {
			target, linkErr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if linkErr != nil {
				continue
			}
			if !isUnder(target, absData) {
				continue
			}
			file := scan.files[target]
			if file == nil {
				file = &scannedFile{path: target, byName: make(map[openerKey]*scannedOpener)}
				scan.files[target] = file
			}
			opener := file.byName[key]
			if opener == nil {
				opener = &scannedOpener{}
				file.byName[key] = opener
			}
			pos := readFDPos(filepath.Join(procRoot, entry.Name(), "fdinfo", fd.Name()))
			file.opens++
			opener.opens++
			opener.posSum += pos
			if pos > file.maxPos {
				file.maxPos = pos
			}
			if pos > opener.maxPos {
				opener.maxPos = pos
			}
		}
	}
	return scan, nil
}

// isUnder reports whether target is dataDir or a path inside it. The
// kernel reports a deleted-but-open file with a " (deleted)" suffix;
// that is still an open descriptor on media under DataDir, so it counts.
func isUnder(target, dataDir string) bool {
	target = strings.TrimSuffix(target, " (deleted)")
	rel, err := filepath.Rel(dataDir, target)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, "../")
}

// readComm returns a process's short name from /proc/<pid>/comm, or ""
// when it cannot be read.
func readComm(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// smbdClientTitleRE matches the process title Debian smbd gives each
// per-connection worker: "smbd: client [198.18.1.103]"; the bracket
// content is taken whole so an IPv6 address or a port suffix survives,
// and leading whitespace or a case change in the fixed words does not
// lose the tag.
var smbdClientTitleRE = regexp.MustCompile(`(?i)^\s*smbd:\s+client\s+\[([^\]]+)\]`)

// smbdBracketTitleRE matches the title Alpine/musl smbd gives each
// per-connection worker: "smbd[198.18.1.103]". The closing bracket is
// optional because /proc/<pid>/comm truncates the title to 15 bytes
// (measured live: "smbd[192.168.50"); a missing bracket means the
// captured client is a prefix of the real address.
var smbdBracketTitleRE = regexp.MustCompile(`(?i)^\s*smbd\[([^\]]+)(\])?`)

// parseSMBDWorkerTitle extracts the client address a title names, in
// either style, and whether it was cut short of its closing bracket.
// ("", false) when the title names no client.
func parseSMBDWorkerTitle(title string) (client string, truncated bool) {
	if m := smbdClientTitleRE.FindStringSubmatch(title); m != nil {
		return m[1], false
	}
	if m := smbdBracketTitleRE.FindStringSubmatch(title); m != nil {
		return m[1], m[2] == ""
	}
	return "", false
}

// readClientFromTitle returns the client address from a process's
// title (/proc/<pid>/cmdline, NUL-separated) when it carries one, or "".
func readClientFromTitle(path string) (client string, truncated bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	title := strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " ")
	return parseSMBDWorkerTitle(title)
}

// smbdWorkerClient returns the client address a process's comm names
// when the comm is itself an smbd worker title, or "".
func smbdWorkerClient(comm string) (client string, truncated bool) {
	return parseSMBDWorkerTitle(comm)
}

// readFDPos returns the "pos:" field of a /proc/<pid>/fdinfo/<fd> file,
// or 0 when the file cannot be read or carries no position.
func readFDPos(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "pos:") {
			continue
		}
		pos, convErr := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "pos:")), 10, 64)
		if convErr != nil {
			return 0
		}
		return pos
	}
	return 0
}
