package tpm2

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// Helper function to create mock event log data for testing
func createMockEventLog() []byte {
	var buf bytes.Buffer

	// Event 1: Standard EV_IPL event with ASCII content
	binary.Write(&buf, binary.LittleEndian, uint32(8))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0001)) // EventType (EV_IPL)
	binary.Write(&buf, binary.LittleEndian, uint32(2))      // DigestCount
	binary.Write(&buf, binary.LittleEndian, uint16(0x0004)) // AlgorithmId (SHA-1)
	buf.Write(make([]byte, 20))                             // SHA-1 Digest
	binary.Write(&buf, binary.LittleEndian, uint16(0x000b)) // AlgorithmId (SHA-256)
	buf.Write(make([]byte, 32))                             // SHA-256 Digest
	binary.Write(&buf, binary.LittleEndian, uint32(22))     // EventSize
	buf.WriteString("grub_cmd: test command")               // EventString

	// Event 2: EV_UNDEFINED event with no EventString
	binary.Write(&buf, binary.LittleEndian, uint32(9))      // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0000)) // EventType (EV_UNDEFINED)
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // DigestCount
	binary.Write(&buf, binary.LittleEndian, uint16(0x000b)) // AlgorithmId (SHA-256)
	buf.Write(make([]byte, 32))                             // SHA-256 Digest
	binary.Write(&buf, binary.LittleEndian, uint32(0))      // EventSize

	// Event 3: EV_EFI_BOOT_SERVICES_APPLICATION with "Example" as EventString
	binary.Write(&buf, binary.LittleEndian, uint32(10))     // PCRIndex
	binary.Write(&buf, binary.LittleEndian, uint32(0x0006)) // EventType
	binary.Write(&buf, binary.LittleEndian, uint32(1))      // DigestCount
	binary.Write(&buf, binary.LittleEndian, uint16(0x0004)) // AlgorithmId
	buf.Write(make([]byte, 20))                             // SHA-1 Digest
	binary.Write(&buf, binary.LittleEndian, uint32(7))      // EventSize
	buf.WriteString("Example")                              // Cleaned EventString

	return buf.Bytes()
}

func TestParseEventLog_Success(t *testing.T) {
	// Create mock event log file
	data := createMockEventLog()
	tmpFile, err := os.CreateTemp("", "mock_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// Parse the mock event log file
	events, err := ParseEventLog(tmpFile.Name())
	if err != nil {
		t.Fatalf("Error parsing event log: %v", err)
	}

	// Validate parsed events
	if len(events) != 3 {
		t.Fatalf("Expected 3 events, got %d", len(events))
	}

	// Check individual event properties
	// Event 1 checks
	if events[0].EventType != "EV_IPL" || events[0].PCRIndex != 8 {
		t.Errorf("Event 1 type or PCRIndex mismatch, got %v, %d", events[0].EventType, events[0].PCRIndex)
	}
	if events[0].DigestCount != 2 || len(events[0].Digests) != 2 {
		t.Errorf("Event 1 DigestCount or Digests length mismatch, got %d", events[0].DigestCount)
	}
	if events[0].EventString != "grub_cmd: test command" {
		t.Errorf("Event 1 EventString mismatch, got %v", events[0].EventString)
	}

	// Event 2 checks
	if events[1].EventType != "EV_UNDEFINED" || events[1].PCRIndex != 9 {
		t.Errorf("Event 2 type or PCRIndex mismatch, got %v, %d", events[1].EventType, events[1].PCRIndex)
	}
	if events[1].DigestCount != 1 || len(events[1].Digests) != 1 {
		t.Errorf("Event 2 DigestCount or Digests length mismatch, got %d", events[1].DigestCount)
	}
	if events[1].EventString != "" {
		t.Errorf("Event 2 EventString mismatch, expected empty string, got %v", events[1].EventString)
	}

	// Event 3 checks
	if events[2].EventType != "EV_EFI_BOOT_SERVICES_APPLICATION" || events[2].PCRIndex != 10 {
		t.Errorf("Event 3 type or PCRIndex mismatch, got %v, %d", events[2].EventType, events[2].PCRIndex)
	}
	if events[2].DigestCount != 1 || len(events[2].Digests) != 1 {
		t.Errorf("Event 3 DigestCount or Digests length mismatch, got %d", events[2].DigestCount)
	}
	if events[2].EventString != "Example" { // Expected cleaned-up string
		t.Errorf("Event 3 EventString mismatch, got %v", events[2].EventString)
	}
}

func TestParseEventLog_ErrorHandling(t *testing.T) {
	// Test with a non-existent file
	_, err := ParseEventLog("non_existent_file")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}

	// Test with a corrupted event log
	corruptedData := []byte{0x00, 0x01, 0x02}
	tmpFile, err := os.CreateTemp("", "corrupted_event_log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(corruptedData); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	_, err = ParseEventLog(tmpFile.Name())
	if err == nil {
		t.Error("Expected error for corrupted event log, got nil")
	}
}
