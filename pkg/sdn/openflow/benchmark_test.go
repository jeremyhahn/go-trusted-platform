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

package openflow

import (
	"fmt"
	"net"
	"testing"
)

// Header Benchmarks

func BenchmarkHeader_MarshalBinary(b *testing.B) {
	headers := []Header{
		{Version: DefaultVersion, Type: OFPTHello, Length: HeaderSize, Xid: 1},
		{Version: DefaultVersion, Type: OFPTFlowMod, Length: 100, Xid: 12345},
		{Version: DefaultVersion, Type: OFPTPacketOut, Length: 200, Xid: 99999},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := headers[i%len(headers)]
		_, _ = header.MarshalBinary()
	}
}

func BenchmarkHeader_UnmarshalBinary(b *testing.B) {
	data := []byte{0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var header Header
		_ = header.UnmarshalBinary(data)
	}
}

// Hello Message Benchmarks

func BenchmarkHello_MarshalBinary(b *testing.B) {
	hello := NewHello(1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = hello.MarshalBinary()
	}
}

func BenchmarkHello_UnmarshalBinary(b *testing.B) {
	data := []byte{0x04, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var hello Hello
		_ = hello.UnmarshalBinary(data)
	}
}

func BenchmarkNewHello(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewHello(uint32(i))
	}
}

// FeaturesRequest Benchmarks

func BenchmarkFeaturesRequest_MarshalBinary(b *testing.B) {
	req := NewFeaturesRequest(1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = req.MarshalBinary()
	}
}

func BenchmarkNewFeaturesRequest(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewFeaturesRequest(uint32(i))
	}
}

// FeaturesReply Benchmarks

func BenchmarkFeaturesReply_UnmarshalBinary(b *testing.B) {
	data := make([]byte, 32)
	// Header
	data[0] = 0x04 // Version
	data[1] = 0x06 // Type: Features Reply
	data[2] = 0x00 // Length high
	data[3] = 0x20 // Length low = 32
	data[4] = 0x00 // Xid
	data[5] = 0x00
	data[6] = 0x00
	data[7] = 0x01
	// Datapath ID
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00
	data[12] = 0x00
	data[13] = 0x00
	data[14] = 0x00
	data[15] = 0x01
	// NBuffers
	data[16] = 0x00
	data[17] = 0x00
	data[18] = 0x01
	data[19] = 0x00
	// NTables
	data[20] = 0xFF
	// AuxiliaryID
	data[21] = 0x00
	// Pad (2 bytes)
	// Capabilities
	data[24] = 0x00
	data[25] = 0x00
	data[26] = 0x00
	data[27] = 0x47
	// Reserved
	data[28] = 0x00
	data[29] = 0x00
	data[30] = 0x00
	data[31] = 0x00

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var reply FeaturesReply
		_ = reply.UnmarshalBinary(data)
	}
}

// EchoRequest Benchmarks

func BenchmarkEchoRequest_MarshalBinary(b *testing.B) {
	echoData := []byte("benchmark")
	req := NewEchoRequest(1, echoData)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = req.MarshalBinary()
	}
}

func BenchmarkNewEchoRequest(b *testing.B) {
	echoData := []byte("benchmark")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewEchoRequest(uint32(i), echoData)
	}
}

// EchoReply Benchmarks

func BenchmarkEchoReply_MarshalBinary(b *testing.B) {
	echoData := []byte("benchmark")
	reply := NewEchoReply(1, echoData)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = reply.MarshalBinary()
	}
}

func BenchmarkNewEchoReply(b *testing.B) {
	echoData := []byte("benchmark")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewEchoReply(uint32(i), echoData)
	}
}

// BarrierRequest Benchmarks

func BenchmarkBarrierRequest_MarshalBinary(b *testing.B) {
	req := NewBarrierRequest(1)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = req.MarshalBinary()
	}
}

func BenchmarkNewBarrierRequest(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewBarrierRequest(uint32(i))
	}
}

// Match Benchmarks

func BenchmarkNewMatch(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMatch()
	}
}

func BenchmarkMatch_AddInPort(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddInPort(uint32(i % 100))
	}
}

func BenchmarkMatch_AddEthDst(b *testing.B) {
	mac := net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddEthDst(mac)
	}
}

func BenchmarkMatch_AddEthSrc(b *testing.B) {
	mac := net.HardwareAddr{0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddEthSrc(mac)
	}
}

func BenchmarkMatch_AddEthType(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddEthType(0x0800) // IPv4
	}
}

func BenchmarkMatch_AddVLANVid(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddVLANVid(uint16(i % 4094))
	}
}

func BenchmarkMatch_AddIPv4Src(b *testing.B) {
	ip := net.ParseIP("10.0.0.1")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddIPv4Src(ip)
	}
}

func BenchmarkMatch_AddIPv4Dst(b *testing.B) {
	ip := net.ParseIP("10.0.0.2")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddIPv4Dst(ip)
	}
}

func BenchmarkMatch_AddIPv4SrcMasked(b *testing.B) {
	ip := net.ParseIP("10.0.0.0")
	mask := net.IPMask{255, 255, 255, 0}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddIPv4SrcMasked(ip, mask)
	}
}

func BenchmarkMatch_AddIPProto(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddIPProto(6) // TCP
	}
}

func BenchmarkMatch_AddTCPDst(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddTCPDst(80)
	}
}

func BenchmarkMatch_AddUDPDst(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		m := NewMatch()
		b.StartTimer()
		m.AddUDPDst(53)
	}
}

func BenchmarkMatch_MarshalBinary(b *testing.B) {
	m := NewMatch()
	m.AddInPort(1)
	m.AddEthType(0x0800)
	m.AddIPv4Src(net.ParseIP("10.0.0.1"))
	m.AddIPv4Dst(net.ParseIP("10.0.0.2"))
	m.AddIPProto(6)
	m.AddTCPDst(80)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = m.MarshalBinary()
	}
}

// Sub-benchmarks for Match with different field counts
func BenchmarkMatch_MarshalBinary_Sizes(b *testing.B) {
	sizes := []int{1, 3, 6, 10}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("fields_%d", size), func(b *testing.B) {
			m := NewMatch()
			for i := 0; i < size; i++ {
				switch i % 6 {
				case 0:
					m.AddInPort(uint32(i + 1))
				case 1:
					m.AddEthType(0x0800)
				case 2:
					m.AddIPv4Src(net.ParseIP(fmt.Sprintf("10.0.0.%d", i)))
				case 3:
					m.AddIPv4Dst(net.ParseIP(fmt.Sprintf("10.0.1.%d", i)))
				case 4:
					m.AddIPProto(6)
				case 5:
					m.AddTCPDst(uint16(80 + i))
				}
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = m.MarshalBinary()
			}
		})
	}
}

// ActionOutput Benchmarks

func BenchmarkNewActionOutput(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewActionOutput(uint32(i%100), 128)
	}
}

func BenchmarkActionOutput_MarshalBinary(b *testing.B) {
	action := NewActionOutput(1, 128)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = action.MarshalBinary()
	}
}

func BenchmarkActionOutput_Length(b *testing.B) {
	action := NewActionOutput(1, 128)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = action.Length()
	}
}

// ActionSetField Benchmarks

func BenchmarkNewActionSetField(b *testing.B) {
	value := []byte{0x10, 0x64}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewActionSetField(OFPXMCOpenflowBasic, OFPXMTOFBVlanVid, value)
	}
}

func BenchmarkActionSetField_MarshalBinary(b *testing.B) {
	value := []byte{0x10, 0x64}
	action := NewActionSetField(OFPXMCOpenflowBasic, OFPXMTOFBVlanVid, value)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = action.MarshalBinary()
	}
}

// ActionPushVLAN Benchmarks

func BenchmarkNewActionPushVLAN(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewActionPushVLAN(0x8100)
	}
}

func BenchmarkActionPushVLAN_MarshalBinary(b *testing.B) {
	action := NewActionPushVLAN(0x8100)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = action.MarshalBinary()
	}
}

// ActionPopVLAN Benchmarks

func BenchmarkNewActionPopVLAN(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewActionPopVLAN()
	}
}

func BenchmarkActionPopVLAN_MarshalBinary(b *testing.B) {
	action := NewActionPopVLAN()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = action.MarshalBinary()
	}
}

// FlowMod Benchmarks

func BenchmarkNewFlowMod(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewFlowMod(uint32(i))
	}
}

func BenchmarkFlowMod_MarshalBinary(b *testing.B) {
	fm := NewFlowMod(1)
	fm.Match.AddInPort(1)
	fm.Match.AddEthType(0x0800)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = fm.MarshalBinary()
	}
}

// Parallel Benchmarks

func BenchmarkHeader_MarshalBinary_Parallel(b *testing.B) {
	header := Header{Version: DefaultVersion, Type: OFPTFlowMod, Length: 100, Xid: 1}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = header.MarshalBinary()
		}
	})
}

func BenchmarkMatch_MarshalBinary_Parallel(b *testing.B) {
	m := NewMatch()
	m.AddInPort(1)
	m.AddEthType(0x0800)
	m.AddIPv4Src(net.ParseIP("10.0.0.1"))
	m.AddIPv4Dst(net.ParseIP("10.0.0.2"))

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = m.MarshalBinary()
		}
	})
}

func BenchmarkFlowMod_MarshalBinary_Parallel(b *testing.B) {
	fm := NewFlowMod(1)
	fm.Match.AddInPort(1)
	fm.Match.AddEthType(0x0800)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = fm.MarshalBinary()
		}
	})
}

func BenchmarkActionOutput_MarshalBinary_Parallel(b *testing.B) {
	action := NewActionOutput(1, 128)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = action.MarshalBinary()
		}
	})
}
