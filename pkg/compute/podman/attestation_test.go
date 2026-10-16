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

package podman

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTPMExtender implements TPMExtender for testing
type mockTPMExtender struct {
	pcrs        map[int][]byte
	extendErr   error
	readErr     error
	quoteErr    error
	extendCalls []struct {
		pcrIndex int
		data     []byte
	}
}

func newMockTPMExtender() *mockTPMExtender {
	return &mockTPMExtender{
		pcrs: make(map[int][]byte),
	}
}

func (m *mockTPMExtender) ExtendPCR(pcrIndex int, data []byte) error {
	if m.extendErr != nil {
		return m.extendErr
	}

	m.extendCalls = append(m.extendCalls, struct {
		pcrIndex int
		data     []byte
	}{pcrIndex, data})

	// Simulate PCR extension: PCR = SHA256(PCR || data)
	current, exists := m.pcrs[pcrIndex]
	if !exists {
		current = make([]byte, 32) // Zero-initialized PCR
	}

	combined := append(current, data...)
	hash := sha256.Sum256(combined)
	m.pcrs[pcrIndex] = hash[:]

	return nil
}

func (m *mockTPMExtender) ReadPCR(pcrIndex int) ([]byte, error) {
	if m.readErr != nil {
		return nil, m.readErr
	}

	pcr, exists := m.pcrs[pcrIndex]
	if !exists {
		return make([]byte, 32), nil
	}
	return pcr, nil
}

func (m *mockTPMExtender) CreateQuote(pcrIndices []int, nonce []byte) ([]byte, error) {
	if m.quoteErr != nil {
		return nil, m.quoteErr
	}

	// Simulate quote creation (just return a hash for testing)
	data := nonce
	for _, idx := range pcrIndices {
		if pcr, exists := m.pcrs[idx]; exists {
			data = append(data, pcr...)
		}
	}
	hash := sha256.Sum256(data)
	return hash[:], nil
}

// mockLogger implements minimal logging interface for testing
type mockLogger struct{}

func (m *mockLogger) Infof(format string, args ...any) {}

func (m *mockLogger) Errorf(format string, args ...any) {}

func (m *mockLogger) Debugf(format string, args ...any) {}

func TestNewContainerAttestor(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}

	t.Run("with default config", func(t *testing.T) {
		attestor, err := NewContainerAttestor(tpm, nil, logger)
		require.NoError(t, err)
		require.NotNil(t, attestor)
	})

	t.Run("with custom config", func(t *testing.T) {
		config := &AttestorConfig{
			PCRIndex:      10,
			EnableSigning: true,
		}
		attestor, err := NewContainerAttestor(tpm, config, logger)
		require.NoError(t, err)
		require.NotNil(t, attestor)
	})

	t.Run("with nil TPM", func(t *testing.T) {
		attestor, err := NewContainerAttestor(nil, nil, logger)
		require.NoError(t, err)
		require.NotNil(t, attestor)
	})

	t.Run("with nil logger", func(t *testing.T) {
		attestor, err := NewContainerAttestor(tpm, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, attestor)
	})
}

func TestDefaultAttestorConfig(t *testing.T) {
	config := DefaultAttestorConfig()

	assert.Equal(t, ContainerPCRIndex, config.PCRIndex)
	assert.False(t, config.EnableSigning)
}

func TestContainerAttestor_OnContainerStart(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("successful attestation", func(t *testing.T) {
		container := &Container{
			ID:        "test-container-123",
			Name:      "test-container",
			Image:     "alpine:latest",
			CreatedAt: time.Now(),
		}

		err := attestor.OnContainerStart(ctx, container)
		assert.NoError(t, err)

		// Verify PCR was extended
		assert.Len(t, tpm.extendCalls, 1)
		assert.Equal(t, ContainerPCRIndex, tpm.extendCalls[0].pcrIndex)
	})

	t.Run("nil container", func(t *testing.T) {
		err := attestor.OnContainerStart(ctx, nil)
		assert.Error(t, err)
	})
}

func TestContainerAttestor_OnContainerStart_WithoutTPM(t *testing.T) {
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(nil, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()
	container := &Container{
		ID:        "test-container-123",
		Name:      "test-container",
		Image:     "alpine:latest",
		CreatedAt: time.Now(),
	}

	// Should succeed even without TPM (just records measurement)
	err = attestor.OnContainerStart(ctx, container)
	assert.NoError(t, err)
}

func TestContainerAttestor_OnContainerStop(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("successful stop attestation", func(t *testing.T) {
		now := time.Now()
		container := &Container{
			ID:         "test-container-123",
			Name:       "test-container",
			ExitCode:   0,
			FinishedAt: &now,
		}

		err := attestor.OnContainerStop(ctx, container)
		assert.NoError(t, err)
	})

	t.Run("nil container", func(t *testing.T) {
		err := attestor.OnContainerStop(ctx, nil)
		assert.Error(t, err)
	})
}

func TestContainerAttestor_GetContainerQuote(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// First, record a measurement
	container := &Container{
		ID:        "test-container-123",
		Name:      "test-container",
		Image:     "alpine:latest",
		CreatedAt: time.Now(),
	}
	err = attestor.OnContainerStart(ctx, container)
	require.NoError(t, err)

	t.Run("get quote with nonce", func(t *testing.T) {
		nonce := []byte("test-nonce-12345")
		quote, err := attestor.GetContainerQuote(ctx, "test-container-123", nonce)
		require.NoError(t, err)
		require.NotNil(t, quote)

		assert.Equal(t, "test-container-123", quote.ContainerID)
		assert.Equal(t, ContainerPCRIndex, quote.PCRIndex)
		assert.NotEmpty(t, quote.PCRValue)
		assert.NotEmpty(t, quote.Signature)
		assert.Equal(t, nonce, quote.Nonce)
	})

	t.Run("get quote without nonce", func(t *testing.T) {
		quote, err := attestor.GetContainerQuote(ctx, "test-container-123", nil)
		require.NoError(t, err)
		require.NotNil(t, quote)

		assert.Empty(t, quote.Signature)
	})

	t.Run("empty container ID", func(t *testing.T) {
		_, err := attestor.GetContainerQuote(ctx, "", nil)
		assert.Error(t, err)
	})
}

func TestContainerAttestor_GetMeasurementLog(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Record some measurements
	container := &Container{
		ID:        "test-container-123",
		Name:      "test-container",
		Image:     "alpine:latest",
		CreatedAt: time.Now(),
	}
	err = attestor.OnContainerStart(ctx, container)
	require.NoError(t, err)

	now := time.Now()
	container.FinishedAt = &now
	err = attestor.OnContainerStop(ctx, container)
	require.NoError(t, err)

	t.Run("get measurement log", func(t *testing.T) {
		log, err := attestor.GetMeasurementLog(ctx, "test-container-123")
		require.NoError(t, err)
		require.NotNil(t, log)

		assert.Len(t, log, 2) // start + stop
		assert.Equal(t, "container_start", log[0].EventType)
		assert.Equal(t, "container_stop", log[1].EventType)
	})

	t.Run("empty container ID", func(t *testing.T) {
		_, err := attestor.GetMeasurementLog(ctx, "")
		assert.Error(t, err)
	})

	t.Run("nonexistent container", func(t *testing.T) {
		log, err := attestor.GetMeasurementLog(ctx, "nonexistent")
		assert.NoError(t, err)
		assert.Nil(t, log)
	})
}

func TestContainerAttestor_VerifyQuote(t *testing.T) {
	tpm := newMockTPMExtender()
	logger := &mockLogger{}
	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("nil quote", func(t *testing.T) {
		err := attestor.VerifyQuote(ctx, nil, nil)
		assert.Error(t, err)
	})

	t.Run("verify with matching PCR", func(t *testing.T) {
		quote := &ContainerQuote{
			ContainerID: "test",
			PCRIndex:    14,
			PCRValue:    make([]byte, 32),
		}

		// Should succeed when PCRs match
		err := attestor.VerifyQuote(ctx, quote, make([]byte, 32))
		assert.NoError(t, err)
	})

	t.Run("verify with mismatched PCR", func(t *testing.T) {
		quote := &ContainerQuote{
			ContainerID: "test",
			PCRIndex:    14,
			PCRValue:    make([]byte, 32),
		}

		expectedPCR := make([]byte, 32)
		expectedPCR[0] = 1 // Different value

		err := attestor.VerifyQuote(ctx, quote, expectedPCR)
		assert.Error(t, err)
	})
}

func TestBuildContainerMeasurement(t *testing.T) {
	container := &Container{
		ID:        "abc123",
		Name:      "test-container",
		Image:     "alpine:latest",
		Command:   []string{"sleep", "infinity"},
		CreatedAt: time.Now(),
	}

	data := buildContainerMeasurement(container)

	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "abc123")
	assert.Contains(t, string(data), "test-container")
	assert.Contains(t, string(data), "alpine:latest")
}

func TestBuildStopMeasurement(t *testing.T) {
	now := time.Now()
	container := &Container{
		ID:         "abc123",
		ExitCode:   0,
		FinishedAt: &now,
	}

	data := buildStopMeasurement(container)

	assert.NotEmpty(t, data)
	assert.Contains(t, string(data), "container_stop")
	assert.Contains(t, string(data), "abc123")
}

func TestComputeExpectedPCR(t *testing.T) {
	measurements := []*ContainerMeasurement{
		{
			ContainerID: "test1",
			EventType:   "container_start",
			Digest:      make([]byte, 32),
		},
		{
			ContainerID: "test1",
			EventType:   "container_stop",
			Digest:      make([]byte, 32),
		},
	}

	pcr := ComputeExpectedPCR(measurements)

	assert.Len(t, pcr, 32)
}

func TestFormatPCRValue(t *testing.T) {
	pcr := make([]byte, 32)
	pcr[0] = 0xAB
	pcr[1] = 0xCD

	formatted := FormatPCRValue(pcr)

	assert.Equal(t, "abcd000000000000000000000000000000000000000000000000000000000000", formatted)
}

func TestParsePCRValue(t *testing.T) {
	t.Run("valid hex string", func(t *testing.T) {
		hexStr := "abcd000000000000000000000000000000000000000000000000000000000000"
		pcr, err := ParsePCRValue(hexStr)
		require.NoError(t, err)
		assert.Len(t, pcr, 32)
		assert.Equal(t, byte(0xAB), pcr[0])
		assert.Equal(t, byte(0xCD), pcr[1])
	})

	t.Run("invalid hex string", func(t *testing.T) {
		_, err := ParsePCRValue("invalid")
		assert.Error(t, err)
	})
}

func TestCompareBytes(t *testing.T) {
	t.Run("equal slices", func(t *testing.T) {
		a := []byte{1, 2, 3, 4}
		b := []byte{1, 2, 3, 4}
		assert.True(t, compareBytes(a, b))
	})

	t.Run("different lengths", func(t *testing.T) {
		a := []byte{1, 2, 3}
		b := []byte{1, 2, 3, 4}
		assert.False(t, compareBytes(a, b))
	})

	t.Run("different values", func(t *testing.T) {
		a := []byte{1, 2, 3, 4}
		b := []byte{1, 2, 3, 5}
		assert.False(t, compareBytes(a, b))
	})

	t.Run("empty slices", func(t *testing.T) {
		a := []byte{}
		b := []byte{}
		assert.True(t, compareBytes(a, b))
	})
}

func TestContainerQuote_Fields(t *testing.T) {
	now := time.Now()
	quote := &ContainerQuote{
		ContainerID:    "abc123",
		ContainerName:  "test-container",
		ImageRef:       "alpine:latest",
		ImageDigest:    "sha256:abc",
		PCRIndex:       14,
		PCRValue:       make([]byte, 32),
		MeasurementLog: make([]byte, 64),
		Timestamp:      now,
		Signature:      make([]byte, 256),
		Nonce:          make([]byte, 16),
	}

	assert.Equal(t, "abc123", quote.ContainerID)
	assert.Equal(t, "test-container", quote.ContainerName)
	assert.Equal(t, "alpine:latest", quote.ImageRef)
	assert.Equal(t, "sha256:abc", quote.ImageDigest)
	assert.Equal(t, 14, quote.PCRIndex)
	assert.Len(t, quote.PCRValue, 32)
	assert.Len(t, quote.MeasurementLog, 64)
	assert.Equal(t, now, quote.Timestamp)
	assert.Len(t, quote.Signature, 256)
	assert.Len(t, quote.Nonce, 16)
}

func TestContainerMeasurement_Fields(t *testing.T) {
	now := time.Now()
	measurement := &ContainerMeasurement{
		ContainerID: "abc123",
		EventType:   "container_start",
		EventData:   []byte("test data"),
		Digest:      make([]byte, 32),
		Timestamp:   now,
	}

	assert.Equal(t, "abc123", measurement.ContainerID)
	assert.Equal(t, "container_start", measurement.EventType)
	assert.Equal(t, "test data", string(measurement.EventData))
	assert.Len(t, measurement.Digest, 32)
	assert.Equal(t, now, measurement.Timestamp)
}

func TestAttestorConfig_Fields(t *testing.T) {
	config := &AttestorConfig{
		PCRIndex:      10,
		EnableSigning: true,
	}

	assert.Equal(t, 10, config.PCRIndex)
	assert.True(t, config.EnableSigning)
}

func TestContainerPCRIndex(t *testing.T) {
	assert.Equal(t, 14, ContainerPCRIndex)
}

func TestContainerAttestor_TPMExtendError(t *testing.T) {
	tpm := newMockTPMExtender()
	tpm.extendErr = ErrTPMNotAvailable
	logger := &mockLogger{}

	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()
	container := &Container{
		ID:        "test-container-123",
		Name:      "test-container",
		Image:     "alpine:latest",
		CreatedAt: time.Now(),
	}

	err = attestor.OnContainerStart(ctx, container)
	assert.Error(t, err)
}

func TestContainerAttestor_TPMReadError(t *testing.T) {
	tpm := newMockTPMExtender()
	tpm.readErr = ErrTPMNotAvailable
	logger := &mockLogger{}

	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = attestor.GetContainerQuote(ctx, "test-container", nil)
	assert.Error(t, err)
}

func TestContainerAttestor_TPMQuoteError(t *testing.T) {
	tpm := newMockTPMExtender()
	tpm.quoteErr = ErrTPMNotAvailable
	logger := &mockLogger{}

	attestor, err := NewContainerAttestor(tpm, nil, logger)
	require.NoError(t, err)

	ctx := context.Background()
	nonce := []byte("test-nonce")

	_, err = attestor.GetContainerQuote(ctx, "test-container", nonce)
	assert.Error(t, err)
}
