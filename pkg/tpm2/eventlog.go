package tpm2

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"regexp"
	"sort"
)

// Event represents a single parsed TPM event.
type Event struct {
	EventNum    int
	PCRIndex    int
	EventType   string
	DigestCount int
	Digests     []Digest
	EventSize   int
	EventString string
}

// Digest represents a single hash digest in a TPM event.
type Digest struct {
	AlgorithmId string
	Digest      string
}

// Parses the TPM event log and returns a slice of Events for each event in the log.
func ParseEventLog(filePath string) ([]Event, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var events []Event
	eventIndex := 1

	for {
		var e Event
		e.EventNum = eventIndex
		eventIndex++

		// Read PCR index
		var pcrIndex uint32
		if err := binary.Read(file, binary.LittleEndian, &pcrIndex); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("error reading PCR index: %v", err)
		}
		e.PCRIndex = int(pcrIndex)

		// Read event type
		var eventType uint32
		if err := binary.Read(file, binary.LittleEndian, &eventType); err != nil {
			return nil, fmt.Errorf("error reading event type: %v", err)
		}
		e.EventType = parseEventType(eventType)

		// Read digest count
		var digestCount uint32
		if err := binary.Read(file, binary.LittleEndian, &digestCount); err != nil {
			return nil, fmt.Errorf("error reading digest count: %v", err)
		}
		e.DigestCount = int(digestCount)

		// Parse each digest
		for i := 0; i < e.DigestCount; i++ {
			var digest Digest
			var algID uint16
			if err := binary.Read(file, binary.LittleEndian, &algID); err != nil {
				return nil, fmt.Errorf("error reading digest algorithm ID: %v", err)
			}
			digest.AlgorithmId = parseAlgorithmId(algID)

			// Parse digest based on algorithm
			var digestSize int
			switch algID {
			case 0x0004: // SHA-1
				digestSize = 20
			case 0x000b: // SHA-256
				digestSize = 32
			case 0x000c: // SHA-384
				digestSize = 48
			case 0x000d: // SHA-512
				digestSize = 64
			default:
				return nil, fmt.Errorf("unknown algorithm ID: 0x%x", algID)
			}

			digestBytes := make([]byte, digestSize)
			if _, err := file.Read(digestBytes); err != nil {
				return nil, fmt.Errorf("error reading digest: %v", err)
			}
			digest.Digest = hex.EncodeToString(digestBytes)
			e.Digests = append(e.Digests, digest)
		}

		// Read event size
		var eventSize uint32
		if err := binary.Read(file, binary.LittleEndian, &eventSize); err != nil {
			return nil, fmt.Errorf("error reading event size: %v", err)
		}
		e.EventSize = int(eventSize)

		// Read event data if eventSize is greater than zero
		if eventSize > 0 {
			eventBytes := make([]byte, eventSize)
			if _, err := file.Read(eventBytes); err != nil {
				return nil, fmt.Errorf("error reading event data: %v", err)
			}
			e.EventString = parseEventString(eventBytes)
		}

		events = append(events, e)
	}

	return events, nil
}

// parseEventType translates event type codes to string representations.
func parseEventType(eventType uint32) string {
	switch eventType {
	case 0x00000000:
		return "EV_UNDEFINED"
	case 0x00000001:
		return "EV_IPL"
	case 0x00000002:
		return "EV_EVENT_TAG"
	case 0x00000003:
		return "EV_NO_ACTION"
	case 0x00000004:
		return "EV_SEPARATOR"
	case 0x00000008:
		return "EV_ACTION"
	case 0x0000000D:
		return "EV_EFI_VARIABLE_DRIVER_CONFIG"
	case 0x00000006:
		return "EV_EFI_BOOT_SERVICES_APPLICATION"
	case 0x80000001:
		return "EV_S_CRTM_CONTENTS"
	case 0x80000002:
		return "EV_S_CRTM_VERSION"
	case 0x80000003:
		return "EV_S_CPU_MICROCODE"
	case 0x80000008:
		return "EV_S_CRTM_SEPARATOR"
	case 0x80000006:
		return "EV_S_POST_CODE"
	case 0x800000E0:
		return "EV_PLATFORM_CONFIG_FLAGS"
	default:
		return fmt.Sprintf("Unknown (0x%x)", eventType)
	}
}

// parseAlgorithmId translates algorithm IDs to string representations.
func parseAlgorithmId(algID uint16) string {
	switch algID {
	case 0x0004:
		return "sha1"
	case 0x000b:
		return "sha256"
	case 0x000c:
		return "sha384"
	case 0x000d:
		return "sha512"
	default:
		return fmt.Sprintf("Unknown (0x%x)", algID)
	}
}

// readDigest reads and returns a hex-encoded digest from the file.
func readDigest(file *os.File, size int) string {
	digestBytes := make([]byte, size)
	if _, err := file.Read(digestBytes); err != nil {
		return ""
	}
	return hex.EncodeToString(digestBytes)
}

// parseEventString finds the longest ASCII sequence in the event data, treating it as the primary string.
func parseEventString(data []byte) string {
	dataStr := string(data)

	// Regex to capture all printable ASCII text sequences
	re := regexp.MustCompile(`[ -~]+`)
	matches := re.FindAllString(dataStr, -1)

	// Return the longest match if available
	if len(matches) > 0 {
		longest := matches[0]
		for _, match := range matches {
			if len(match) > len(longest) {
				longest = match
			}
		}
		return longest
	}
	return ""
}

// Calculate PCR values by processing each event and extending a mirror software PCR value
func CalculatePCRs(events []Event) map[string]map[int][]byte {
	pcrs := initializePCRs()

	for _, event := range events {
		for _, digest := range event.Digests {
			// Initialize PCR if it doesn't already exist
			if _, exists := pcrs[digest.AlgorithmId][event.PCRIndex]; !exists {
				pcrs[digest.AlgorithmId][event.PCRIndex] = make([]byte, getDigestSize(digest.AlgorithmId))
			}

			// Convert the digest hex string to bytes
			digestBytes, err := hex.DecodeString(digest.Digest)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding digest: %v\n", err)
				continue
			}

			// Extend the PCR
			newPCR, err := extendPCR(pcrs[digest.AlgorithmId][event.PCRIndex], digestBytes, digest.AlgorithmId)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error extending PCR: %v\n", err)
				continue
			}
			pcrs[digest.AlgorithmId][event.PCRIndex] = newPCR
		}
	}

	return pcrs
}

// Initialize a map to store cumulative PCR values by algorithm and index
func initializePCRs() map[string]map[int][]byte {
	return map[string]map[int][]byte{
		"sha1":   make(map[int][]byte),
		"sha256": make(map[int][]byte),
		"sha384": make(map[int][]byte),
		"sha512": make(map[int][]byte),
	}
}

// Get hash function based on algorithm ID
func getHashFunction(algorithmId string) (hash.Hash, error) {
	switch algorithmId {
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithmId)
	}
}

// Extend the PCR by hashing the current PCR value and the event digest
func extendPCR(currentPCR []byte, digest []byte, algorithmId string) ([]byte, error) {
	hasher, err := getHashFunction(algorithmId)
	if err != nil {
		return nil, err
	}

	// Concatenate the current PCR value with the event digest and hash the result
	hasher.Write(currentPCR)
	hasher.Write(digest)
	return hasher.Sum(nil), nil
}

// Helper function to get the digest size based on the algorithm
func getDigestSize(algorithmId string) int {
	switch algorithmId {
	case "sha1":
		return sha1.Size
	case "sha256":
		return sha256.Size
	case "sha384":
		return sha512.Size384
	case "sha512":
		return sha512.Size
	default:
		return 0
	}
}

// Print PCR summary with sorted indices and skip empty PCR banks
func printPCRSummary(events []Event) {
	pcrValues := CalculatePCRs(events)

	fmt.Println("pcrs:")

	for alg, pcrMap := range pcrValues {
		// Skip the algorithm if there are no PCR values
		if len(pcrMap) == 0 {
			continue
		}

		fmt.Printf("  %s:\n", alg)

		// Collect and sort PCR indices
		var indices []int
		for index := range pcrMap {
			indices = append(indices, index)
		}
		sort.Ints(indices)

		// Print each PCR index and digest with aligned colons
		for _, index := range indices {
			// Align single and double digit indices with two spaces before the colon
			fmt.Printf("    %2d : 0x%s\n", index, hex.EncodeToString(pcrMap[index]))
		}
	}
}

// PrintEvents outputs parsed events in a structured format.
func PrintEvents(events []Event) {
	for _, e := range events {
		fmt.Printf("- EventNum: %d\n", e.EventNum)
		fmt.Printf("  PCRIndex: %d\n", e.PCRIndex)
		fmt.Printf("  EventType: %s\n", e.EventType)
		fmt.Printf("  DigestCount: %d\n", e.DigestCount)
		fmt.Printf("  Digests:\n")
		for _, d := range e.Digests {
			fmt.Printf("  - AlgorithmId: %s\n", d.AlgorithmId)
			fmt.Printf("    Digest: \"%s\"\n", d.Digest)
		}
		fmt.Printf("  EventSize: %d\n", e.EventSize)
		fmt.Printf("  Event:\n    String: \"%s\"\n", e.EventString)
	}
	printPCRSummary(events)
}
