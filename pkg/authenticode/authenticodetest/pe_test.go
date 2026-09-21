package authenticodetest

import (
	"bytes"
	"debug/pe"
	"testing"
)

func TestMinimalPEParsesWithTheRequestedMachine(t *testing.T) {
	for _, machine := range []uint16{MachineAMD64, MachineARM64, MachineRISCV64} {
		img := MinimalPE(machine)
		f, err := pe.NewFile(bytes.NewReader(img))
		if err != nil {
			t.Fatalf("machine %#x: %v", machine, err)
		}
		if f.Machine != machine {
			t.Errorf("machine = %#x, want %#x", f.Machine, machine)
		}
		if len(f.Sections) != 1 || f.Sections[0].Name != ".text" {
			t.Errorf("sections = %v", f.Sections)
		}
		opt, ok := f.OptionalHeader.(*pe.OptionalHeader64)
		if !ok {
			t.Fatalf("optional header is %T, want PE32+", f.OptionalHeader)
		}
		if opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].Size != 0 {
			t.Error("a fresh image must be unsigned")
		}
	}
}

func TestMinimalPEIsFreshEachCall(t *testing.T) {
	a := MinimalPE(MachineARM64)
	b := MinimalPE(MachineARM64)
	a[0x200] = 0xff
	if b[0x200] == 0xff {
		t.Error("calls share a buffer")
	}
}
