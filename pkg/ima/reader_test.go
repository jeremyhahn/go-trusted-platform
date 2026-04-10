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

package ima

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewReader(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		r := NewReader()
		require.NotNil(t, r)
		assert.Equal(t, DefaultSecurityFSPath, r.securityFSPath)
	})

	t.Run("custom security fs path", func(t *testing.T) {
		customPath := "/custom/security"
		r := NewReader(WithSecurityFSPath(customPath))
		require.NotNil(t, r)
		assert.Equal(t, customPath, r.securityFSPath)
	})
}

func TestReader_IsSecurityFSMounted(t *testing.T) {
	t.Run("existing path", func(t *testing.T) {
		// Create temp directory to simulate securityfs
		tmpDir := t.TempDir()
		r := NewReader(WithSecurityFSPath(tmpDir))
		assert.True(t, r.IsSecurityFSMounted())
	})

	t.Run("non-existing path", func(t *testing.T) {
		r := NewReader(WithSecurityFSPath("/nonexistent/path"))
		assert.False(t, r.IsSecurityFSMounted())
	})
}

func TestReader_IsAvailable(t *testing.T) {
	t.Run("ima directory exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		imaDir := filepath.Join(tmpDir, "ima")
		err := os.Mkdir(imaDir, 0755)
		require.NoError(t, err)

		r := NewReader(WithSecurityFSPath(tmpDir))
		assert.True(t, r.IsAvailable())
	})

	t.Run("ima directory missing", func(t *testing.T) {
		tmpDir := t.TempDir()
		r := NewReader(WithSecurityFSPath(tmpDir))
		assert.False(t, r.IsAvailable())
	})
}

func TestReader_ParseEvent(t *testing.T) {
	r := NewReader()

	t.Run("ima-ng format", func(t *testing.T) {
		line := "10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /usr/bin/bash"
		event, err := r.ParseEvent(line)
		require.NoError(t, err)
		require.NotNil(t, event)

		assert.Equal(t, 10, event.PCR)
		assert.Equal(t, "ima-ng", event.TemplateName)
		assert.Equal(t, "sha256", event.HashAlgorithm)
		assert.Equal(t, "/usr/bin/bash", event.FilePath)
		assert.Equal(t, line, event.RawLine)

		expectedTemplateHash, _ := hex.DecodeString("0123456789abcdef0123456789abcdef01234567")
		assert.Equal(t, expectedTemplateHash, event.TemplateHash)

		expectedFileHash, _ := hex.DecodeString("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
		assert.Equal(t, expectedFileHash, event.FileHash)
	})

	t.Run("ima-sig format with signature", func(t *testing.T) {
		line := "10 0123456789abcdef0123456789abcdef01234567 ima-sig sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /usr/bin/signed deadbeef"
		event, err := r.ParseEvent(line)
		require.NoError(t, err)
		require.NotNil(t, event)

		assert.Equal(t, "ima-sig", event.TemplateName)
		assert.Equal(t, "/usr/bin/signed", event.FilePath)

		expectedSig, _ := hex.DecodeString("deadbeef")
		assert.Equal(t, expectedSig, event.Signature)
	})

	t.Run("legacy sha1 format", func(t *testing.T) {
		line := "10 0123456789abcdef0123456789abcdef01234567 ima 0123456789abcdef0123456789abcdef01234567 /usr/bin/legacy"
		event, err := r.ParseEvent(line)
		require.NoError(t, err)
		require.NotNil(t, event)

		assert.Equal(t, "sha1", event.HashAlgorithm)
		assert.Equal(t, "/usr/bin/legacy", event.FilePath)
	})

	t.Run("invalid format - too few fields", func(t *testing.T) {
		line := "10 abc123 ima"
		_, err := r.ParseEvent(line)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})

	t.Run("invalid format - bad PCR", func(t *testing.T) {
		line := "notanumber abc123def456 ima-ng sha256:abc123 /file"
		_, err := r.ParseEvent(line)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})

	t.Run("invalid format - bad template hash", func(t *testing.T) {
		line := "10 notvalidhex ima-ng sha256:abc123 /file"
		_, err := r.ParseEvent(line)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})

	t.Run("invalid format - bad file hash", func(t *testing.T) {
		line := "10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:notvalidhex /file"
		_, err := r.ParseEvent(line)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidEventFormat)
	})
}

func TestReader_ParseEventLog(t *testing.T) {
	r := NewReader()

	t.Run("valid log", func(t *testing.T) {
		logContent := `10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /usr/bin/bash
10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:1234560123456789abcdef0123456789abcdef0123456789abcdef0123456789 /usr/bin/ls
10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:7890ab0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /usr/bin/bash`

		log, err := r.ParseEventLog(strings.NewReader(logContent))
		require.NoError(t, err)
		require.NotNil(t, log)

		assert.Equal(t, 3, log.TotalCount)
		assert.Equal(t, 2, log.UniqueFiles) // bash appears twice
		assert.Equal(t, 0, log.ParseErrors)
		assert.Len(t, log.Events, 3)
	})

	t.Run("empty log", func(t *testing.T) {
		log, err := r.ParseEventLog(strings.NewReader(""))
		require.NoError(t, err)
		require.NotNil(t, log)

		assert.Equal(t, 0, log.TotalCount)
		assert.Len(t, log.Events, 0)
	})

	t.Run("log with parse errors", func(t *testing.T) {
		logContent := `10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /valid/file
invalid line here
10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:1234560123456789abcdef0123456789abcdef0123456789abcdef0123456789 /another/valid`

		log, err := r.ParseEventLog(strings.NewReader(logContent))
		require.NoError(t, err)
		require.NotNil(t, log)

		assert.Equal(t, 2, log.TotalCount)
		assert.Equal(t, 1, log.ParseErrors)
	})

	t.Run("log with blank lines", func(t *testing.T) {
		logContent := `10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /file1

10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:1234560123456789abcdef0123456789abcdef0123456789abcdef0123456789 /file2`

		log, err := r.ParseEventLog(strings.NewReader(logContent))
		require.NoError(t, err)
		assert.Equal(t, 2, log.TotalCount)
	})
}

func TestReader_ReadEventLogFromFile(t *testing.T) {
	r := NewReader()

	t.Run("file not found", func(t *testing.T) {
		_, err := r.ReadEventLogFromFile("/nonexistent/file")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNotAvailable)
	})

	t.Run("valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		logFile := filepath.Join(tmpDir, "measurements")

		content := "10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /test/file\n"
		err := os.WriteFile(logFile, []byte(content), 0644)
		require.NoError(t, err)

		log, err := r.ReadEventLogFromFile(logFile)
		require.NoError(t, err)
		require.NotNil(t, log)
		assert.Equal(t, 1, log.TotalCount)
	})
}

func TestReader_ParsePolicyRule(t *testing.T) {
	r := NewReader()

	t.Run("measure rule", func(t *testing.T) {
		line := "measure func=FILE_CHECK mask=MAY_READ pcr=10 template=ima-ng"
		rule, err := r.ParsePolicyRule(line)
		require.NoError(t, err)
		require.NotNil(t, rule)

		assert.Equal(t, "measure", rule.Action)
		assert.Equal(t, "FILE_CHECK", rule.Func)
		assert.Equal(t, "MAY_READ", rule.Mask)
		assert.Equal(t, 10, rule.PCR)
		assert.Equal(t, "ima-ng", rule.Template)
		assert.Equal(t, line, rule.RawRule)
	})

	t.Run("appraise rule", func(t *testing.T) {
		line := "appraise func=BPRM_CHECK"
		rule, err := r.ParsePolicyRule(line)
		require.NoError(t, err)
		require.NotNil(t, rule)

		assert.Equal(t, "appraise", rule.Action)
		assert.Equal(t, "BPRM_CHECK", rule.Func)
	})

	t.Run("dont_measure rule", func(t *testing.T) {
		line := "dont_measure fsmagic=0x9fa0"
		rule, err := r.ParsePolicyRule(line)
		require.NoError(t, err)
		require.NotNil(t, rule)

		assert.Equal(t, "dont_measure", rule.Action)
		assert.Contains(t, rule.Condition, "fsmagic=0x9fa0")
	})

	t.Run("empty line", func(t *testing.T) {
		_, err := r.ParsePolicyRule("")
		assert.Error(t, err)
	})
}

func TestReader_ParsePolicy(t *testing.T) {
	r := NewReader()

	t.Run("valid policy", func(t *testing.T) {
		policyContent := `# Comment line
measure func=FILE_CHECK mask=MAY_READ pcr=10
appraise func=BPRM_CHECK
dont_measure fsmagic=0x9fa0`

		policy, err := r.ParsePolicy(strings.NewReader(policyContent))
		require.NoError(t, err)
		require.NotNil(t, policy)

		assert.Equal(t, 3, policy.RuleCount)
		assert.Len(t, policy.Rules, 3)
	})

	t.Run("empty policy", func(t *testing.T) {
		policy, err := r.ParsePolicy(strings.NewReader(""))
		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, 0, policy.RuleCount)
	})

	t.Run("policy with only comments", func(t *testing.T) {
		policyContent := `# Comment 1
# Comment 2`

		policy, err := r.ParsePolicy(strings.NewReader(policyContent))
		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, 0, policy.RuleCount)
	})
}

func TestReader_ReadPolicyFromFile(t *testing.T) {
	r := NewReader()

	t.Run("file not found", func(t *testing.T) {
		_, err := r.ReadPolicyFromFile("/nonexistent/file")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrNotAvailable)
	})

	t.Run("valid file", func(t *testing.T) {
		tmpDir := t.TempDir()
		policyFile := filepath.Join(tmpDir, "policy")

		content := "measure func=FILE_CHECK\n"
		err := os.WriteFile(policyFile, []byte(content), 0644)
		require.NoError(t, err)

		policy, err := r.ReadPolicyFromFile(policyFile)
		require.NoError(t, err)
		require.NotNil(t, policy)
		assert.Equal(t, 1, policy.RuleCount)
	})
}

func TestReader_GetStatistics(t *testing.T) {
	r := NewReader()

	t.Run("nil log", func(t *testing.T) {
		stats := r.GetStatistics(nil)
		assert.Nil(t, stats)
	})

	t.Run("valid log", func(t *testing.T) {
		log := &EventLog{
			TotalCount:  5,
			UniqueFiles: 3,
			Events: []*Event{
				{HashAlgorithm: "sha256", TemplateName: "ima-ng", FilePath: "/bin/bash"},
				{HashAlgorithm: "sha256", TemplateName: "ima-ng", FilePath: "/bin/bash"},
				{HashAlgorithm: "sha256", TemplateName: "ima-sig", FilePath: "/bin/ls"},
				{HashAlgorithm: "sha1", TemplateName: "ima", FilePath: "/bin/cat"},
				{HashAlgorithm: "sha256", TemplateName: "ima-ng", FilePath: "/bin/grep"},
			},
		}

		stats := r.GetStatistics(log)
		require.NotNil(t, stats)

		assert.Equal(t, 5, stats.TotalEvents)
		assert.Equal(t, 3, stats.UniqueFiles)

		// Hash algorithm counts
		assert.Equal(t, 4, stats.FilesByHashAlg["sha256"])
		assert.Equal(t, 1, stats.FilesByHashAlg["sha1"])

		// Template counts
		assert.Equal(t, 3, stats.FilesByTemplate["ima-ng"])
		assert.Equal(t, 1, stats.FilesByTemplate["ima-sig"])
		assert.Equal(t, 1, stats.FilesByTemplate["ima"])

		// Top paths should include /bin/bash first (2 occurrences)
		assert.Greater(t, len(stats.TopPaths), 0)
		assert.Equal(t, "/bin/bash", stats.TopPaths[0])
	})
}

func TestReader_GetStatus(t *testing.T) {
	t.Run("securityfs not mounted", func(t *testing.T) {
		r := NewReader(WithSecurityFSPath("/nonexistent"))
		_, err := r.GetStatus()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSecurityFSNotMounted)
	})

	t.Run("ima not available", func(t *testing.T) {
		tmpDir := t.TempDir()
		r := NewReader(WithSecurityFSPath(tmpDir))

		status, err := r.GetStatus()
		require.NoError(t, err)
		require.NotNil(t, status)

		assert.False(t, status.Available)
		assert.False(t, status.Enabled)
	})

	t.Run("ima available", func(t *testing.T) {
		tmpDir := t.TempDir()
		imaDir := filepath.Join(tmpDir, "ima")
		err := os.Mkdir(imaDir, 0755)
		require.NoError(t, err)

		// Create measurements file
		measurementsFile := filepath.Join(imaDir, "ascii_runtime_measurements")
		content := "10 0123456789abcdef0123456789abcdef01234567 ima-ng sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 /test\n"
		err = os.WriteFile(measurementsFile, []byte(content), 0644)
		require.NoError(t, err)

		r := NewReader(WithSecurityFSPath(tmpDir))
		status, err := r.GetStatus()
		require.NoError(t, err)
		require.NotNil(t, status)

		assert.True(t, status.Available)
		assert.True(t, status.Enabled)
		assert.Equal(t, 1, status.MeasurementCount)
		assert.Equal(t, "sha256", status.HashAlgorithm)
	})

	t.Run("policy loaded", func(t *testing.T) {
		tmpDir := t.TempDir()
		imaDir := filepath.Join(tmpDir, "ima")
		err := os.Mkdir(imaDir, 0755)
		require.NoError(t, err)

		// Create policy file
		policyFile := filepath.Join(imaDir, "policy")
		err = os.WriteFile(policyFile, []byte("measure func=FILE_CHECK\n"), 0644)
		require.NoError(t, err)

		// Create empty measurements file
		measurementsFile := filepath.Join(imaDir, "ascii_runtime_measurements")
		err = os.WriteFile(measurementsFile, []byte(""), 0644)
		require.NoError(t, err)

		r := NewReader(WithSecurityFSPath(tmpDir))
		status, err := r.GetStatus()
		require.NoError(t, err)
		require.NotNil(t, status)

		assert.True(t, status.PolicyLoaded)
	})
}

func TestReader_ReadViolations(t *testing.T) {
	t.Run("violations file not found", func(t *testing.T) {
		tmpDir := t.TempDir()
		r := NewReader(WithSecurityFSPath(tmpDir))

		count, err := r.ReadViolations()
		require.NoError(t, err)
		assert.Equal(t, 0, count)
	})

	t.Run("valid violations count", func(t *testing.T) {
		tmpDir := t.TempDir()
		imaDir := filepath.Join(tmpDir, "ima")
		err := os.Mkdir(imaDir, 0755)
		require.NoError(t, err)

		violationsFile := filepath.Join(imaDir, "violations")
		err = os.WriteFile(violationsFile, []byte("42\n"), 0644)
		require.NoError(t, err)

		r := NewReader(WithSecurityFSPath(tmpDir))
		count, err := r.ReadViolations()
		require.NoError(t, err)
		assert.Equal(t, 42, count)
	})

	t.Run("invalid violations content", func(t *testing.T) {
		tmpDir := t.TempDir()
		imaDir := filepath.Join(tmpDir, "ima")
		err := os.Mkdir(imaDir, 0755)
		require.NoError(t, err)

		violationsFile := filepath.Join(imaDir, "violations")
		err = os.WriteFile(violationsFile, []byte("not a number"), 0644)
		require.NoError(t, err)

		r := NewReader(WithSecurityFSPath(tmpDir))
		_, err = r.ReadViolations()
		assert.Error(t, err)
	})
}

func TestReader_FindEventByPath(t *testing.T) {
	r := NewReader()

	log := &EventLog{
		Events: []*Event{
			{FilePath: "/bin/bash"},
			{FilePath: "/bin/ls"},
			{FilePath: "/bin/bash"},
			{FilePath: "/bin/cat"},
		},
	}

	t.Run("nil log", func(t *testing.T) {
		events := r.FindEventByPath(nil, "/bin/bash")
		assert.Nil(t, events)
	})

	t.Run("found multiple", func(t *testing.T) {
		events := r.FindEventByPath(log, "/bin/bash")
		assert.Len(t, events, 2)
	})

	t.Run("found one", func(t *testing.T) {
		events := r.FindEventByPath(log, "/bin/ls")
		assert.Len(t, events, 1)
	})

	t.Run("not found", func(t *testing.T) {
		events := r.FindEventByPath(log, "/bin/nonexistent")
		assert.Len(t, events, 0)
	})
}

func TestReader_FindEventByHash(t *testing.T) {
	r := NewReader()

	hash1, _ := hex.DecodeString("abcdef")
	hash2, _ := hex.DecodeString("123456")
	hash3, _ := hex.DecodeString("abcdef")

	log := &EventLog{
		Events: []*Event{
			{FileHash: hash1, FilePath: "/file1"},
			{FileHash: hash2, FilePath: "/file2"},
			{FileHash: hash3, FilePath: "/file3"},
		},
	}

	t.Run("nil log", func(t *testing.T) {
		events := r.FindEventByHash(nil, hash1)
		assert.Nil(t, events)
	})

	t.Run("empty hash", func(t *testing.T) {
		events := r.FindEventByHash(log, []byte{})
		assert.Nil(t, events)
	})

	t.Run("found multiple with same hash", func(t *testing.T) {
		events := r.FindEventByHash(log, hash1)
		assert.Len(t, events, 2) // hash1 and hash3 are equal
	})

	t.Run("found one", func(t *testing.T) {
		events := r.FindEventByHash(log, hash2)
		assert.Len(t, events, 1)
	})

	t.Run("not found", func(t *testing.T) {
		notFoundHash, _ := hex.DecodeString("ffffff")
		events := r.FindEventByHash(log, notFoundHash)
		assert.Len(t, events, 0)
	})
}

func TestReader_getTopPaths(t *testing.T) {
	r := NewReader()

	t.Run("empty map", func(t *testing.T) {
		paths := r.getTopPaths(map[string]int{}, 10)
		assert.Len(t, paths, 0)
	})

	t.Run("fewer paths than n", func(t *testing.T) {
		pathCounts := map[string]int{
			"/a": 1,
			"/b": 2,
		}
		paths := r.getTopPaths(pathCounts, 10)
		assert.Len(t, paths, 2)
		assert.Equal(t, "/b", paths[0]) // Higher count first
	})

	t.Run("more paths than n", func(t *testing.T) {
		pathCounts := map[string]int{
			"/a": 1,
			"/b": 5,
			"/c": 3,
			"/d": 4,
			"/e": 2,
		}
		paths := r.getTopPaths(pathCounts, 3)
		assert.Len(t, paths, 3)
		assert.Equal(t, "/b", paths[0]) // 5
		assert.Equal(t, "/d", paths[1]) // 4
		assert.Equal(t, "/c", paths[2]) // 3
	})
}

func TestReader_ReadEventLog_Integration(t *testing.T) {
	// Test with sample data that matches real IMA log format
	r := NewReader()

	sampleLog := `10 a7ddb60a7c72f09d3c83c25c74c0ab226ab51f1e ima-ng sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730 /usr/bin/dbus-daemon
10 d0a1c4a3b2e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9 ima-ng sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef /lib/x86_64-linux-gnu/libc.so.6
10 e1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0 ima-sig sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321 /usr/sbin/sshd 030201dead`

	log, err := r.ParseEventLog(strings.NewReader(sampleLog))
	require.NoError(t, err)
	require.NotNil(t, log)

	assert.Equal(t, 3, log.TotalCount)
	assert.Equal(t, 3, log.UniqueFiles)

	// Check first event
	assert.Equal(t, 10, log.Events[0].PCR)
	assert.Equal(t, "ima-ng", log.Events[0].TemplateName)
	assert.Equal(t, "sha256", log.Events[0].HashAlgorithm)
	assert.Equal(t, "/usr/bin/dbus-daemon", log.Events[0].FilePath)

	// Check ima-sig event has signature
	assert.Equal(t, "ima-sig", log.Events[2].TemplateName)
	assert.NotNil(t, log.Events[2].Signature)

	// Statistics
	stats := r.GetStatistics(log)
	require.NotNil(t, stats)
	assert.Equal(t, 3, stats.FilesByHashAlg["sha256"])
	assert.Equal(t, 2, stats.FilesByTemplate["ima-ng"])
	assert.Equal(t, 1, stats.FilesByTemplate["ima-sig"])
}

func TestHashComparison(t *testing.T) {
	// Test that hash comparison works correctly using bytes.Equal
	hash1 := []byte{0xab, 0xcd, 0xef}
	hash2 := []byte{0xab, 0xcd, 0xef}
	hash3 := []byte{0x12, 0x34, 0x56}

	assert.True(t, bytes.Equal(hash1, hash2))
	assert.False(t, bytes.Equal(hash1, hash3))
}
