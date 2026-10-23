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

func TestSectionedPEParsesWithTheRequestedSections(t *testing.T) {
	for _, n := range []int{1, 3, 7} {
		f, err := pe.NewFile(bytes.NewReader(SectionedPE(n, 200)))
		if err != nil {
			t.Fatalf("%d sections: %v", n, err)
		}
		if len(f.Sections) != n {
			t.Fatalf("sections = %d, want %d", len(f.Sections), n)
		}
		for i, s := range f.Sections {
			data, err := s.Data()
			if err != nil {
				t.Fatalf("section %d data: %v", i, err)
			}
			if len(data) != sectionDataSize || data[0] != 0xCC || data[len(data)-1] != 0xCC {
				t.Errorf("section %d is not %d bytes of 0xCC", i, sectionDataSize)
			}
		}
	}
}

func TestSectionedPEHeaderPaddingSetsTheRoomForMoreHeaders(t *testing.T) {
	const tableEnd = dosHeaderSize + peSignatureSize + coffHeaderSize + optionalHeaderSize + sectionHeaderSize
	for _, tc := range []struct{ padding, wantRoom int }{
		{padding: 0, wantRoom: fileAlignment - tableEnd},
		{padding: 400, wantRoom: 2*fileAlignment - tableEnd},
	} {
		f, err := pe.NewFile(bytes.NewReader(SectionedPE(1, tc.padding)))
		if err != nil {
			t.Fatalf("padding %d: %v", tc.padding, err)
		}
		if room := int(f.Sections[0].Offset) - tableEnd; room != tc.wantRoom {
			t.Errorf("padding %d: room before first section = %d, want %d", tc.padding, room, tc.wantRoom)
		}
	}
}

func TestSectionedPEWithoutSectionsHasNone(t *testing.T) {
	f, err := pe.NewFile(bytes.NewReader(SectionedPE(0, 100)))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Sections) != 0 {
		t.Errorf("sections = %d, want 0", len(f.Sections))
	}
}
