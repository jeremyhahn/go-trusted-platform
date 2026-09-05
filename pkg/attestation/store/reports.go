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

package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
)

// Device attestation reports (#226 slice E): the most recent verified
// verdict per device, persisted so a restarted control plane presents the
// last known verdict WITH ITS AGE rather than "never collected".
//
// One file per device under <root>/reports, written atomically. The device
// id is the file name, so it is validated as a path segment before use.

const reportsDir = "reports"

// ErrInvalidReportDeviceID reports a device id that cannot name a file.
type ErrInvalidReportDeviceID struct {
	DeviceID string
}

func (e ErrInvalidReportDeviceID) Error() string {
	return "attestation store: device id " + e.DeviceID + " is not a valid report key"
}

func (s *FileStore) reportPath(deviceID string) (string, error) {
	if deviceID == "" || deviceID != filepath.Base(deviceID) || strings.ContainsAny(deviceID, `/\`) || strings.HasPrefix(deviceID, ".") {
		return "", ErrInvalidReportDeviceID{DeviceID: deviceID}
	}
	return filepath.Join(s.root, reportsDir, deviceID+".json"), nil
}

// PutReport implements reporting.Store.
func (s *FileStore) PutReport(r *reporting.Report) error {
	if r == nil {
		return errInvalidStoreConfig{Field: "report", Reason: "nil"}
	}
	path, err := s.reportPath(r.DeviceID)
	if err != nil {
		return err
	}
	body, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Reports implements reporting.Store. A file that no longer parses is
// skipped rather than failing the load: one corrupt report must not make
// every other device "never collected".
func (s *FileStore) Reports() ([]*reporting.Report, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir := filepath.Join(s.root, reportsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []*reporting.Report
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r reporting.Report
		if err := json.Unmarshal(body, &r); err != nil || r.DeviceID == "" {
			continue
		}
		out = append(out, &r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

var _ reporting.Store = (*FileStore)(nil)
