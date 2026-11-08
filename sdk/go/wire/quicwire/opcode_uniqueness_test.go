package quicwire

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Opcode values repeat legitimately in this package, and that is documented
// design rather than an accident: docs/daemon/api.md §"This is why opcode
// values repeat" records OpOverlayStatus, OpGatewayStatus and OpLiveness all
// being 0x01 — the first two sub-opcodes inside their categories, the third a
// top-level opcode — and OpVMMetrics (0xCC under 0x69) being unrelated to
// OpSwitchCategory (0xCC at top level). vm_ops_opcodes.go states the rule for
// its own range: sub-opcode values "only need to be unique among the
// sub-opcodes routed under that category".
//
// So a guard asserting that no two Op* constants share a value would fail on
// the design. This one asserts uniqueness WITHIN a dispatch namespace, which
// is the invariant protocol.go actually needs:
//
//	"must multiplex as sub-opcodes under an existing category opcode"
//	                                            — protocol.go, opcode space
//
// WHY A TABLE AND NOT PARSED FROM THE DISPATCH SWITCHES. The namespace of a
// constant is decided by which switch reads it, and the code does not carry
// that as data — it is prose in file headers. Deriving it would mean parsing
// every handler's switch and following req.Opcode versus payload[0], which is
// materially more machinery than the invariant is worth today. The table below
// is the classification, each entry carrying the evidence for it. If the table
// starts drifting from the code, replace it with that parse; until then the
// completeness check below is what stops it drifting silently.
const (
	nsTopLevel = "top-level (req.Opcode)"
	nsCompute  = "sub-opcode under compute extended category 0x69"
	nsGateway  = "sub-opcode under the gateway category"
	nsOverlay  = "sub-opcode under the overlay category"
	nsDNS      = "sub-opcode under the DNS category"
)

// opcodeNamespaces classifies every file in this package that declares an
// `Op<name> byte = 0x..` constant. Evidence for each is the file's own header
// unless noted.
var opcodeNamespaces = map[string]string{
	"protocol.go":              nsTopLevel,
	"kms_opcodes.go":           nsTopLevel, // "KMS extended and Secrets category opcodes" — category markers are top-level
	"ntp_opcodes.go":           nsTopLevel, // "NTP (time synchronization) category opcode"
	"cluster_opcodes.go":       nsTopLevel, // "Cluster category opcode"
	"iam_opcodes.go":           nsTopLevel, // "IAM category opcode"
	"vpn_opcodes.go":           nsTopLevel, // "VPN category opcode"
	"appservice_opcodes.go":    nsTopLevel, // "Application service category opcodes"
	"phase35_opcodes.go":       nsTopLevel, // "Phase 3.5 category opcodes"
	"provisioning_opcodes.go":  nsTopLevel, // "Provisioning (config delivery) category opcode"
	"attestation_opcodes.go":   nsTopLevel, // no header claim; measured — handleRequest switches on req.Opcode
	"container_opcodes.go":     nsCompute,  // "sub-opcodes carried in payload[0] under the compute extended category"
	"container_ops_opcodes.go": nsCompute,  // "carried only as compute extended category (0x69)"
	"vm_opcodes.go":            nsCompute,  // "reach them as sub-opcodes carried in payload[0] under"
	"vm_ops_opcodes.go":        nsCompute,  // "(OpVMExtendedCategory, 0x69) sub-opcodes in payload[0]"
	"gateway_opcodes.go":       nsGateway,  // "Extended gateway opcode category marker"
	"gateway_lb_opcodes.go":    nsGateway,  // "Load balancer sub-opcodes ... under OpGatewayCategory"
	"gateway_perf_opcodes.go":  nsGateway,  // "Performance verification sub-opcodes ... under"
	"gateway_nat64.go":         nsGateway,  // "NAT64 sub-opcodes ... takes the next free slot"
	"overlay_opcodes.go":       nsOverlay,  // "Extended overlay opcode category marker"
	"dns_opcodes.go":           nsDNS,      // "DNS sub-opcodes, carried in payload[0] under OpDNSCategory"
}

// knownCollisions is a RATCHET, not a suppression list. Seven same-namespace
// collisions exist today and are recorded on #386, which is blocked on an
// owner ruling about reallocating the attestation block. Asserting uniqueness
// outright would redden main and block every merge behind a gate nobody reads.
//
// Each entry must STILL collide: TestQUICOpcodes_KnownCollisionsAreStillReal
// fails when one stops, so fixing a collision forces its entry out rather than
// leaving a stale exemption behind.
var knownCollisions = map[string]string{
	// Refs #386. Attestation constants allocated flat into occupied top-level
	// space. docs/daemon/api.md already records the first two as "Two dead
	// opcode names" whose presence in OpcodeNames makes logs mislabel them.
	"OpAttestGetManifest":       "OpAttestGetReport",
	"OpAttestGetReportByID":     "OpAttestGetPCRs",
	"OpAttestContainerWorkload": "OpPXEGetDevice",
	"OpAttestDeviceWorkload":    "OpPXERegisterDevice",
	"OpAttestListReports":       "OpPXEUpdateState",
	"OpAttestCreatePolicy":      "OpIAMUserDelete",
	"OpAttestListPolicies":      "OpIAMUserGet",
}

type opcodeConst struct {
	name  string
	value byte
	file  string
}

// parseOpcodeConstants reads the package's own source rather than using
// reflection, which cannot enumerate constants.
func parseOpcodeConstants(t *testing.T) []opcodeConst {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var out []opcodeConst
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Values) != len(vs.Names) {
					continue
				}
				for i, id := range vs.Names {
					if !strings.HasPrefix(id.Name, "Op") {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.INT {
						continue
					}
					v, err := strconv.ParseUint(lit.Value, 0, 8)
					if err != nil {
						continue // not a byte-valued opcode
					}
					out = append(out, opcodeConst{name: id.Name, value: byte(v), file: name})
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("parsed zero Op* constants — the enumeration is broken, not the package")
	}
	return out
}

// TestQUICOpcodes_EveryDeclaringFileIsClassified is the completeness half.
// Without it, an eighth collision arriving in a NEW file would be invisible:
// the uniqueness check below only looks at namespaces the table names, so it
// would pass by not looking. Adding opcodes anywhere now forces a
// classification decision, which is the cost this guard is meant to impose.
func TestQUICOpcodes_EveryDeclaringFileIsClassified(t *testing.T) {
	declaring := map[string]bool{}
	for _, c := range parseOpcodeConstants(t) {
		declaring[c.file] = true
	}

	var unclassified []string
	for file := range declaring {
		if _, ok := opcodeNamespaces[file]; !ok {
			unclassified = append(unclassified, file)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Fatalf("%d file(s) declare Op* constants but are not classified in opcodeNamespaces: %v\n"+
			"Classify each as top-level or as a sub-opcode namespace, citing the file's own header "+
			"or the switch its constants reach. An unclassified file is invisible to the uniqueness check.",
			len(unclassified), unclassified)
	}

	var stale []string
	for file := range opcodeNamespaces {
		if !declaring[file] {
			stale = append(stale, file)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("opcodeNamespaces classifies %d file(s) that declare no Op* constants: %v — remove them",
			len(stale), stale)
	}
}

// collisionsByNamespace returns, per namespace, the value -> constant names
// that share it, for values shared by more than one name.
func collisionsByNamespace(consts []opcodeConst) map[string]map[byte][]string {
	grouped := map[string]map[byte][]string{}
	for _, c := range consts {
		ns, ok := opcodeNamespaces[c.file]
		if !ok {
			continue // reported by the completeness test
		}
		if grouped[ns] == nil {
			grouped[ns] = map[byte][]string{}
		}
		grouped[ns][c.value] = append(grouped[ns][c.value], c.name)
	}
	out := map[string]map[byte][]string{}
	for ns, byValue := range grouped {
		for v, names := range byValue {
			if len(names) < 2 {
				continue
			}
			sort.Strings(names)
			if out[ns] == nil {
				out[ns] = map[byte][]string{}
			}
			out[ns][v] = names
		}
	}
	return out
}

func isKnown(names []string) bool {
	for _, a := range names {
		for _, b := range names {
			if a == b {
				continue
			}
			if knownCollisions[a] == b {
				return true
			}
		}
	}
	return false
}

// TestQUICOpcodes_UniqueWithinNamespace is the forward direction: a NEW
// collision inside one dispatch namespace fails, naming both constants, the
// value and the namespace. Values repeating ACROSS namespaces are design and
// are not reported.
func TestQUICOpcodes_UniqueWithinNamespace(t *testing.T) {
	var unexpected []string
	for ns, byValue := range collisionsByNamespace(parseOpcodeConstants(t)) {
		values := make([]int, 0, len(byValue))
		for v := range byValue {
			values = append(values, int(v))
		}
		sort.Ints(values)
		for _, v := range values {
			names := byValue[byte(v)]
			if isKnown(names) {
				continue
			}
			unexpected = append(unexpected, fmt.Sprintf("0x%02X in %s: %s", v, ns, strings.Join(names, " == ")))
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) > 0 {
		t.Fatalf("%d opcode collision(s) within a single dispatch namespace:\n  %s\n\n"+
			"Two constants reachable by the same switch cannot both be dispatched. "+
			"protocol.go's rule is that new operations \"must multiplex as sub-opcodes under an "+
			"existing category opcode\" — allocate there rather than into occupied top-level space. "+
			"If the collision is deliberate and the two are in different namespaces, classify the "+
			"declaring file in opcodeNamespaces instead of adding an exemption.",
			len(unexpected), strings.Join(unexpected, "\n  "))
	}
}

// TestQUICOpcodes_KnownCollisionsAreStillReal is the reverse direction, and it
// is what makes the baseline a ratchet. An entry that no longer collides is a
// stale exemption: it must be deleted, so the list can only shrink.
func TestQUICOpcodes_KnownCollisionsAreStillReal(t *testing.T) {
	live := map[string]bool{}
	for _, byValue := range collisionsByNamespace(parseOpcodeConstants(t)) {
		for _, names := range byValue {
			for _, a := range names {
				for _, b := range names {
					if a != b {
						live[a+"=="+b] = true
					}
				}
			}
		}
	}

	var stale []string
	for a, b := range knownCollisions {
		if !live[a+"=="+b] {
			stale = append(stale, fmt.Sprintf("%s == %s", a, b))
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Fatalf("%d knownCollisions entr(ies) no longer collide: %v\n\n"+
			"The collision was fixed but its exemption was left behind. Delete the entry — "+
			"this list is a ratchet over #386 and may only shrink.",
			len(stale), stale)
	}
}

// retiredTopLevelOpcodes are top-level bytes retired unimplemented. A new
// constant on one would make an old client's request reach a different
// operation, so they stay free (DNS UpdateConfig and FlushCache, #317).
var retiredTopLevelOpcodes = map[byte]string{
	0x2B: "DNSUpdateConfig",
	0x2D: "DNSFlushCache",
}

// TestQUICOpcodes_RetiredBytesStayFree fails when a top-level constant takes
// a retired byte.
func TestQUICOpcodes_RetiredBytesStayFree(t *testing.T) {
	for _, c := range parseOpcodeConstants(t) {
		if opcodeNamespaces[c.file] != nsTopLevel {
			continue
		}
		if retired, ok := retiredTopLevelOpcodes[c.value]; ok {
			t.Errorf("%s (%s) takes 0x%02X, retired with %s: allocate a sub-opcode under a category instead",
				c.name, c.file, c.value, retired)
		}
	}
}

// TestQUICOpcodes_DNSCategoryLayout pins the DNS category byte and its
// sub-opcodes: the category is a top-level byte of its own and UpdateZone is
// sub-opcode 0x30 (CA m1094).
func TestQUICOpcodes_DNSCategoryLayout(t *testing.T) {
	topLevel := map[byte][]string{}
	var dnsSubs []opcodeConst
	for _, c := range parseOpcodeConstants(t) {
		switch opcodeNamespaces[c.file] {
		case nsTopLevel:
			topLevel[c.value] = append(topLevel[c.value], c.name)
		case nsDNS:
			dnsSubs = append(dnsSubs, c)
		}
	}

	if OpDNSCategory != 0x61 {
		t.Errorf("OpDNSCategory = 0x%02X, want 0x61", OpDNSCategory)
	}
	if names := topLevel[OpDNSCategory]; len(names) != 1 || names[0] != "OpDNSCategory" {
		t.Errorf("top-level 0x%02X is held by %v, want only OpDNSCategory", OpDNSCategory, names)
	}
	if OpDNSUpdateZone != 0x30 {
		t.Errorf("OpDNSUpdateZone = 0x%02X, want 0x30", OpDNSUpdateZone)
	}
	if len(dnsSubs) == 0 {
		t.Fatal("no DNS sub-opcodes parsed from dns_opcodes.go")
	}
	for _, c := range dnsSubs {
		if c.value < 0x30 || c.value > 0x3F {
			t.Errorf("%s = 0x%02X is outside the DNS sub-opcode range 0x30-0x3F", c.name, c.value)
		}
	}
}
