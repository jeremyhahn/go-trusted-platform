package measure

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func sum256(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// The digests UEFI TCG2 event logs carry for these events. The separator,
// the boot-option action and SecureBoot=1 are the values firmware logs show;
// they pin the event encodings. The ExitBootServices values pin the TCG PC
// Client PFP strings.
func TestEventDigestsMatchKnownLogValues(t *testing.T) {
	cases := []struct {
		name string
		got  func() ([]byte, error)
		want string
	}{
		{"separator", func() ([]byte, error) { return SeparatorDigest(crypto.SHA256) }, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"},
		{"calling EFI application", func() ([]byte, error) { return ActionDigest(crypto.SHA256, ActionCallingEFIApplication) }, "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba"},
		{"exit boot services", func() ([]byte, error) { return ActionDigest(crypto.SHA256, ActionExitBootServices) }, "d8043d6b7b85ad358eb3b6ae6a873ab7ef23a26352c5dc4faa5aeedacf5eb41b"},
		{"exit boot services ok", func() ([]byte, error) { return ActionDigest(crypto.SHA256, ActionExitBootServicesOK) }, "b54f7542cbd872a81a9d9dea839b2b8d747c7ebd5ea6615c40f42f44a6dbeba0"},
		{"SecureBoot=1", func() ([]byte, error) {
			return Digest(crypto.SHA256, VariableData(EFIGlobalVariable, "SecureBoot", []byte{1}))
		}, "ccfc4bb32888a345bc8aeadaba552b627d99348c767681ab3141f5b01e40a40e"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.got()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != c.want {
				t.Fatalf("digest %x, want %s", got, c.want)
			}
		})
	}
}

func TestNewGUIDWireEncoding(t *testing.T) {
	want := mustHex(t, "61dfe48bca93d211aa0d00e098032b8c")
	if !bytes.Equal(EFIGlobalVariable[:], want) {
		t.Fatalf("EFI_GLOBAL_VARIABLE %x, want %x", EFIGlobalVariable[:], want)
	}
	want = mustHex(t, "cbb219d73a3d9645a3bcdad00e67656f")
	if !bytes.Equal(EFIImageSecurityDatabase[:], want) {
		t.Fatalf("EFI_IMAGE_SECURITY_DATABASE_GUID %x, want %x", EFIImageSecurityDatabase[:], want)
	}
}

func TestVariableDataLayout(t *testing.T) {
	got := VariableData(EFIImageSecurityDatabase, "db", []byte{0xaa, 0xbb, 0xcc})
	var want []byte
	want = append(want, EFIImageSecurityDatabase[:]...)
	want = append(want, 2, 0, 0, 0, 0, 0, 0, 0) // two UTF-16 code units
	want = append(want, 3, 0, 0, 0, 0, 0, 0, 0) // three data bytes
	want = append(want, 'd', 0, 'b', 0)         // UTF-16LE, no terminator
	want = append(want, 0xaa, 0xbb, 0xcc)
	if !bytes.Equal(got, want) {
		t.Fatalf("UEFI_VARIABLE_DATA %x, want %x", got, want)
	}
}

func TestSignatureData(t *testing.T) {
	owner := NewGUID(1, 2, 3, [8]byte{4, 5, 6, 7, 8, 9, 10, 11})
	got := SignatureData(owner, []byte{0x30, 0x82})
	if !bytes.Equal(got[:16], owner[:]) || !bytes.Equal(got[16:], []byte{0x30, 0x82}) {
		t.Fatalf("EFI_SIGNATURE_DATA %x", got)
	}
}

func TestReplay(t *testing.T) {
	d1, d2 := sum256([]byte("one")), sum256([]byte("two"))
	got, err := Replay(crypto.SHA256, d1, d2)
	if err != nil {
		t.Fatal(err)
	}
	want := sum256(sum256(make([]byte, 32), d1), d2)
	if !bytes.Equal(got, want) {
		t.Fatalf("replay %x, want %x", got, want)
	}

	empty, err := Replay(crypto.SHA384)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, make([]byte, 48)) {
		t.Fatalf("an unextended SHA-384 PCR is %x, want zeros", empty)
	}
}

func TestReplayRefusesWrongDigestSize(t *testing.T) {
	_, err := Replay(crypto.SHA256, sum256(nil), make([]byte, 20))
	var de *DigestSizeError
	if !errors.As(err, &de) || de.Index != 1 || de.Got != 20 {
		t.Fatalf("err %v, want a DigestSizeError for digest 1", err)
	}
}

func TestUnsupportedBank(t *testing.T) {
	var ue *UnsupportedBankError
	if _, err := Digest(crypto.MD4, nil); !errors.As(err, &ue) {
		t.Fatalf("Digest: err %v, want an UnsupportedBankError", err)
	}
	if _, err := Replay(crypto.Hash(0)); !errors.As(err, &ue) {
		t.Fatalf("Replay: err %v, want an UnsupportedBankError", err)
	}
	if _, err := PredictPCR5(crypto.MD4); !errors.As(err, &ue) {
		t.Fatalf("PredictPCR5: err %v, want an UnsupportedBankError", err)
	}
}

func TestPredictPCR5(t *testing.T) {
	got, err := PredictPCR5(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := Replay(crypto.SHA256,
		mustHex(t, "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"),
		mustHex(t, "d8043d6b7b85ad358eb3b6ae6a873ab7ef23a26352c5dc4faa5aeedacf5eb41b"),
		mustHex(t, "b54f7542cbd872a81a9d9dea839b2b8d747c7ebd5ea6615c40f42f44a6dbeba0"))
	if !bytes.Equal(got, want) {
		t.Fatalf("PCR 5 %x, want %x", got, want)
	}
}

func testVars() SecureBootVariables {
	return SecureBootVariables{PK: []byte("pk-esl"), KEK: []byte("kek-esl"), DB: []byte("db-esl")}
}

func TestPredictPCR7(t *testing.T) {
	v := testVars()
	auth := SignatureData(NewGUID(9, 9, 9, [8]byte{}), []byte("db-cert"))
	got, err := PredictPCR7(crypto.SHA256, v, auth)
	if err != nil {
		t.Fatal(err)
	}
	gv, sdb := EFIGlobalVariable, EFIImageSecurityDatabase
	want := make([]byte, 32)
	for _, ev := range [][]byte{
		VariableData(gv, "SecureBoot", []byte{1}),
		VariableData(gv, "PK", v.PK),
		VariableData(gv, "KEK", v.KEK),
		VariableData(sdb, "db", v.DB),
		VariableData(sdb, "dbx", nil),
		{0, 0, 0, 0},
		VariableData(sdb, "db", auth),
	} {
		want = sum256(want, sum256(ev))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("PCR 7 %x, want %x", got, want)
	}

	// Each input changes the value: a swapped key set or authority is visible.
	noAuth, _ := PredictPCR7(crypto.SHA256, v)
	v.DBX = []byte("dbx-esl")
	withDBX, _ := PredictPCR7(crypto.SHA256, v, auth)
	if bytes.Equal(noAuth, got) || bytes.Equal(withDBX, got) {
		t.Fatal("PCR 7 did not change with its inputs")
	}
}

func TestPredictPCR7RefusesMissingInputs(t *testing.T) {
	for _, c := range []struct {
		input string
		edit  func(*SecureBootVariables)
	}{
		{"PK", func(v *SecureBootVariables) { v.PK = nil }},
		{"KEK", func(v *SecureBootVariables) { v.KEK = nil }},
		{"db", func(v *SecureBootVariables) { v.DB = nil }},
	} {
		v := testVars()
		c.edit(&v)
		_, err := PredictPCR7(crypto.SHA256, v)
		var me *MissingInputError
		if !errors.As(err, &me) || me.PCR != 7 || me.Input != c.input {
			t.Fatalf("without %s: err %v", c.input, err)
		}
	}
	_, err := PredictPCR7(crypto.SHA256, testVars(), nil)
	var me *MissingInputError
	if !errors.As(err, &me) || me.Input != "authority" {
		t.Fatalf("empty authority: err %v", err)
	}
}

func TestPredictPCR9(t *testing.T) {
	initrd, opts := []byte("initrd"), []byte("o\x00p\x00")
	got, err := PredictPCR9(crypto.SHA256, nil, initrd)
	if err != nil {
		t.Fatal(err)
	}
	if want := sum256(make([]byte, 32), sum256(initrd)); !bytes.Equal(got, want) {
		t.Fatalf("PCR 9 without load options %x, want %x", got, want)
	}
	got, err = PredictPCR9(crypto.SHA256, opts, initrd)
	if err != nil {
		t.Fatal(err)
	}
	if want := sum256(sum256(make([]byte, 32), sum256(opts)), sum256(initrd)); !bytes.Equal(got, want) {
		t.Fatalf("PCR 9 with load options %x, want %x", got, want)
	}
	var me *MissingInputError
	if _, err := PredictPCR9(crypto.SHA256, opts, nil); !errors.As(err, &me) || me.PCR != 9 {
		t.Fatalf("without an initrd: err %v", err)
	}
}

func TestErrorMessages(t *testing.T) {
	for _, err := range []error{
		&UnsupportedBankError{Hash: crypto.MD4},
		&DigestSizeError{Hash: crypto.SHA256, Index: 2, Got: 20},
		&MissingInputError{PCR: 7, Input: "PK"},
	} {
		if err.Error() == "" {
			t.Fatalf("%T has an empty message", err)
		}
	}
}
