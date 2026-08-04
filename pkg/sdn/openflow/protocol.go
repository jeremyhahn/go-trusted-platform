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

// Package openflow provides a pure Go OpenFlow 1.3 protocol implementation
// for communicating directly with OVS bridges without shelling out to ovs-ofctl.
package openflow

import (
	"encoding/binary"
	"fmt"
)

// OpenFlow protocol version
const (
	OFP10 = 0x01 // OpenFlow 1.0
	OFP11 = 0x02 // OpenFlow 1.1
	OFP12 = 0x03 // OpenFlow 1.2
	OFP13 = 0x04 // OpenFlow 1.3
	OFP14 = 0x05 // OpenFlow 1.4
	OFP15 = 0x06 // OpenFlow 1.5
)

// DefaultVersion is the OpenFlow version we support
const DefaultVersion = OFP13

// Header size constants
const (
	HeaderSize       = 8 // OpenFlow header size
	HelloSize        = 8 // HELLO message size (just header)
	FeatureReqSize   = 8 // Features request size
	BarrierReplySize = 8 // Barrier reply size
	MaxMessageSize   = 65535
)

// OpenFlow message types (OFP 1.3)
const (
	// Immutable messages
	OFPTHello        = 0 // OFPT_HELLO
	OFPTError        = 1 // OFPT_ERROR
	OFPTEchoRequest  = 2 // OFPT_ECHO_REQUEST
	OFPTEchoReply    = 3 // OFPT_ECHO_REPLY
	OFPTExperimenter = 4 // OFPT_EXPERIMENTER

	// Switch configuration messages
	OFPTFeaturesRequest  = 5 // OFPT_FEATURES_REQUEST
	OFPTFeaturesReply    = 6 // OFPT_FEATURES_REPLY
	OFPTGetConfigRequest = 7 // OFPT_GET_CONFIG_REQUEST
	OFPTGetConfigReply   = 8 // OFPT_GET_CONFIG_REPLY
	OFPTSetConfig        = 9 // OFPT_SET_CONFIG

	// Asynchronous messages
	OFPTPacketIn    = 10 // OFPT_PACKET_IN
	OFPTFlowRemoved = 11 // OFPT_FLOW_REMOVED
	OFPTPortStatus  = 12 // OFPT_PORT_STATUS

	// Controller command messages
	OFPTPacketOut = 13 // OFPT_PACKET_OUT
	OFPTFlowMod   = 14 // OFPT_FLOW_MOD
	OFPTGroupMod  = 15 // OFPT_GROUP_MOD
	OFPTPortMod   = 16 // OFPT_PORT_MOD
	OFPTTableMod  = 17 // OFPT_TABLE_MOD

	// Multipart messages
	OFPTMultipartRequest = 18 // OFPT_MULTIPART_REQUEST
	OFPTMultipartReply   = 19 // OFPT_MULTIPART_REPLY

	// Barrier messages
	OFPTBarrierRequest = 20 // OFPT_BARRIER_REQUEST
	OFPTBarrierReply   = 21 // OFPT_BARRIER_REPLY

	// Queue configuration messages
	OFPTQueueGetConfigRequest = 22 // OFPT_QUEUE_GET_CONFIG_REQUEST
	OFPTQueueGetConfigReply   = 23 // OFPT_QUEUE_GET_CONFIG_REPLY

	// Controller role change request messages
	OFPTRoleRequest = 24 // OFPT_ROLE_REQUEST
	OFPTRoleReply   = 25 // OFPT_ROLE_REPLY

	// Asynchronous message configuration
	OFPTGetAsyncRequest = 26 // OFPT_GET_ASYNC_REQUEST
	OFPTGetAsyncReply   = 27 // OFPT_GET_ASYNC_REPLY
	OFPTSetAsync        = 28 // OFPT_SET_ASYNC

	// Meters and rate limiters configuration messages
	OFPTMeterMod = 29 // OFPT_METER_MOD
)

// Flow mod commands
const (
	OFPFCAdd          = 0 // OFPFC_ADD: New flow
	OFPFCModify       = 1 // OFPFC_MODIFY: Modify all matching flows
	OFPFCModifyStrict = 2 // OFPFC_MODIFY_STRICT: Modify entry strictly matching wildcards and priority
	OFPFCDelete       = 3 // OFPFC_DELETE: Delete all matching flows
	OFPFCDeleteStrict = 4 // OFPFC_DELETE_STRICT: Delete entry strictly matching wildcards and priority
)

// Flow mod flags
const (
	OFPFFSendFlowRem  = 1 << 0 // OFPFF_SEND_FLOW_REM: Send flow removed message when flow expires or is deleted
	OFPFFCheckOverlap = 1 << 1 // OFPFF_CHECK_OVERLAP: Check for overlapping entries first
	OFPFFResetCounts  = 1 << 2 // OFPFF_RESET_COUNTS: Reset flow packet and byte counts
	OFPFFNoPktCounts  = 1 << 3 // OFPFF_NO_PKT_COUNTS: Don't keep track of packet count
	OFPFFNoBytCounts  = 1 << 4 // OFPFF_NO_BYT_COUNTS: Don't keep track of byte count
)

// Multipart request/reply types
const (
	OFPMPDesc          = 0     // OFPMP_DESC: Description of this OpenFlow switch
	OFPMPFlow          = 1     // OFPMP_FLOW: Individual flow statistics
	OFPMPAggregate     = 2     // OFPMP_AGGREGATE: Aggregate flow statistics
	OFPMPTable         = 3     // OFPMP_TABLE: Flow table statistics
	OFPMPPortStats     = 4     // OFPMP_PORT_STATS: Port statistics
	OFPMPQueue         = 5     // OFPMP_QUEUE: Queue statistics for a port
	OFPMPGroup         = 6     // OFPMP_GROUP: Group counter statistics
	OFPMPGroupDesc     = 7     // OFPMP_GROUP_DESC: Group description
	OFPMPGroupFeatures = 8     // OFPMP_GROUP_FEATURES: Group features
	OFPMPMeter         = 9     // OFPMP_METER: Meter statistics
	OFPMPMeterConfig   = 10    // OFPMP_METER_CONFIG: Meter configuration
	OFPMPMeterFeatures = 11    // OFPMP_METER_FEATURES: Meter features
	OFPMPTableFeatures = 12    // OFPMP_TABLE_FEATURES: Table features
	OFPMPPortDesc      = 13    // OFPMP_PORT_DESC: Port description
	OFPMPExperimenter  = 65535 // OFPMP_EXPERIMENTER: Experimenter extension
)

// Match types
const (
	OFPMTStandard = 0 // OFPMT_STANDARD: Deprecated
	OFPMTOXM      = 1 // OFPMT_OXM: OpenFlow Extensible Match
)

// OXM classes
const (
	OFPXMCNxm0          = 0x0000 // OFPXMC_NXM_0: Backward compatibility with NXM
	OFPXMCNxm1          = 0x0001 // OFPXMC_NXM_1: Backward compatibility with NXM
	OFPXMCOpenflowBasic = 0x8000 // OFPXMC_OPENFLOW_BASIC: Basic class for OpenFlow
	OFPXMCExperimenter  = 0xFFFF // OFPXMC_EXPERIMENTER: Experimenter class
)

// OXM match fields (for OFPXMC_OPENFLOW_BASIC)
const (
	OFPXMTOFBInPort       = 0  // Switch input port
	OFPXMTOFBInPhyPort    = 1  // Switch physical input port
	OFPXMTOFBMetadata     = 2  // Metadata passed between tables
	OFPXMTOFBEthDst       = 3  // Ethernet destination address
	OFPXMTOFBEthSrc       = 4  // Ethernet source address
	OFPXMTOFBEthType      = 5  // Ethernet frame type
	OFPXMTOFBVlanVid      = 6  // VLAN id
	OFPXMTOFBVlanPcp      = 7  // VLAN priority
	OFPXMTOFBIPDscp       = 8  // IP DSCP (6 bits in ToS field)
	OFPXMTOFBIPEcn        = 9  // IP ECN (2 bits in ToS field)
	OFPXMTOFBIPProto      = 10 // IP protocol
	OFPXMTOFBIPv4Src      = 11 // IPv4 source address
	OFPXMTOFBIPv4Dst      = 12 // IPv4 destination address
	OFPXMTOFBTCPSrc       = 13 // TCP source port
	OFPXMTOFBTCPDst       = 14 // TCP destination port
	OFPXMTOFBUDPSrc       = 15 // UDP source port
	OFPXMTOFBUDPDst       = 16 // UDP destination port
	OFPXMTOFBSCTPSrc      = 17 // SCTP source port
	OFPXMTOFBSCTPDst      = 18 // SCTP destination port
	OFPXMTOFBICMPv4Type   = 19 // ICMP type
	OFPXMTOFBICMPv4Code   = 20 // ICMP code
	OFPXMTOFBArpOp        = 21 // ARP opcode
	OFPXMTOFBArpSpa       = 22 // ARP source IPv4 address
	OFPXMTOFBArpTpa       = 23 // ARP target IPv4 address
	OFPXMTOFBArpSha       = 24 // ARP source hardware address
	OFPXMTOFBArpTha       = 25 // ARP target hardware address
	OFPXMTOFBIPv6Src      = 26 // IPv6 source address
	OFPXMTOFBIPv6Dst      = 27 // IPv6 destination address
	OFPXMTOFBIPv6Flabel   = 28 // IPv6 Flow Label
	OFPXMTOFBICMPv6Type   = 29 // ICMPv6 type
	OFPXMTOFBICMPv6Code   = 30 // ICMPv6 code
	OFPXMTOFBIPv6NdTarget = 31 // Target address for ND
	OFPXMTOFBIPv6NdSll    = 32 // Source link-layer for ND
	OFPXMTOFBIPv6NdTll    = 33 // Target link-layer for ND
	OFPXMTOFBMplsLabel    = 34 // MPLS label
	OFPXMTOFBMplsTc       = 35 // MPLS TC
	OFPXMTOFBMplsBos      = 36 // MPLS BoS bit
	OFPXMTOFBPbbIsid      = 37 // PBB I-SID
	OFPXMTOFBTunnelId     = 38 // Logical Port Metadata
	OFPXMTOFBIPv6Exthdr   = 39 // IPv6 Extension Header pseudo-field
)

// Action types
const (
	OFPATOutput       = 0     // OFPAT_OUTPUT: Output to switch port
	OFPATCopyTTLOut   = 11    // OFPAT_COPY_TTL_OUT: Copy TTL "outwards"
	OFPATCopyTTLIn    = 12    // OFPAT_COPY_TTL_IN: Copy TTL "inwards"
	OFPATSetMplsTTL   = 15    // OFPAT_SET_MPLS_TTL: MPLS TTL
	OFPATDecMplsTTL   = 16    // OFPAT_DEC_MPLS_TTL: Decrement MPLS TTL
	OFPATPushVlan     = 17    // OFPAT_PUSH_VLAN: Push a new VLAN tag
	OFPATPopVlan      = 18    // OFPAT_POP_VLAN: Pop the outer VLAN tag
	OFPATPushMpls     = 19    // OFPAT_PUSH_MPLS: Push a new MPLS tag
	OFPATPopMpls      = 20    // OFPAT_POP_MPLS: Pop the outer MPLS tag
	OFPATSetQueue     = 21    // OFPAT_SET_QUEUE: Set queue id when outputting to a port
	OFPATGroup        = 22    // OFPAT_GROUP: Apply group
	OFPATSetNwTTL     = 23    // OFPAT_SET_NW_TTL: IP TTL
	OFPATDecNwTTL     = 24    // OFPAT_DEC_NW_TTL: Decrement IP TTL
	OFPATSetField     = 25    // OFPAT_SET_FIELD: Set a header field using OXM TLV format
	OFPATPushPbb      = 26    // OFPAT_PUSH_PBB: Push a new PBB service tag (I-TAG)
	OFPATPopPbb       = 27    // OFPAT_POP_PBB: Pop the outer PBB service tag (I-TAG)
	OFPATExperimenter = 65535 // OFPAT_EXPERIMENTER: Experimenter action
)

// Instruction types
const (
	OFPITGotoTable     = 1     // OFPIT_GOTO_TABLE: Setup the next table in the lookup pipeline
	OFPITWriteMetadata = 2     // OFPIT_WRITE_METADATA: Setup the metadata field for use later in pipeline
	OFPITWriteActions  = 3     // OFPIT_WRITE_ACTIONS: Write the action(s) onto the datapath action set
	OFPITApplyActions  = 4     // OFPIT_APPLY_ACTIONS: Applies the action(s) immediately
	OFPITClearActions  = 5     // OFPIT_CLEAR_ACTIONS: Clears all actions from the datapath action set
	OFPITMeter         = 6     // OFPIT_METER: Apply meter (rate limiter)
	OFPITExperimenter  = 65535 // OFPIT_EXPERIMENTER: Experimenter instruction
)

// Special port numbers
const (
	OFPPMax        = 0xffffff00 // Maximum number of physical and logical switch ports
	OFPPInPort     = 0xfffffff8 // Send the packet out the input port
	OFPPTable      = 0xfffffff9 // Submit the packet to the first flow table
	OFPPNormal     = 0xfffffffa // Process with normal L2/L3 switching
	OFPPFlood      = 0xfffffffb // All physical ports in VLAN, except input port and those blocked or link down
	OFPPAll        = 0xfffffffc // All physical ports except input port
	OFPPController = 0xfffffffd // Send to controller
	OFPPLocal      = 0xfffffffe // Local openflow "port"
	OFPPAny        = 0xffffffff // Wildcard port used only for flow mod (delete) and flow stats requests
)

// Table numbers
const (
	OFPTTMax = 0xfe // OFPTT_MAX: Last usable table number
	OFPTTAll = 0xff // OFPTT_ALL: Wildcard table used for table config, flow stats and flow deletes
)

// Error types
const (
	OFPETHelloFailed         = 0     // OFPET_HELLO_FAILED: Hello protocol failed
	OFPETBadRequest          = 1     // OFPET_BAD_REQUEST: Request was not understood
	OFPETBadAction           = 2     // OFPET_BAD_ACTION: Error in action description
	OFPETBadInstruction      = 3     // OFPET_BAD_INSTRUCTION: Error in instruction list
	OFPETBadMatch            = 4     // OFPET_BAD_MATCH: Error in match
	OFPETFlowModFailed       = 5     // OFPET_FLOW_MOD_FAILED: Problem modifying flow entry
	OFPETGroupModFailed      = 6     // OFPET_GROUP_MOD_FAILED: Problem modifying group entry
	OFPETPortModFailed       = 7     // OFPET_PORT_MOD_FAILED: Port mod request failed
	OFPETTableModFailed      = 8     // OFPET_TABLE_MOD_FAILED: Table mod request failed
	OFPETQueueOpFailed       = 9     // OFPET_QUEUE_OP_FAILED: Queue operation failed
	OFPETSwitchConfigFailed  = 10    // OFPET_SWITCH_CONFIG_FAILED: Switch config request failed
	OFPETRoleRequestFailed   = 11    // OFPET_ROLE_REQUEST_FAILED: Controller Role request failed
	OFPETMeterModFailed      = 12    // OFPET_METER_MOD_FAILED: Error in meter
	OFPETTableFeaturesFailed = 13    // OFPET_TABLE_FEATURES_FAILED: Setting table features failed
	OFPETExperimenter        = 65535 // OFPET_EXPERIMENTER: Experimenter error messages
)

// ByteOrder is the byte order used for OpenFlow protocol
var ByteOrder = binary.BigEndian

// Header represents an OpenFlow message header
type Header struct {
	Version uint8  // OFP_VERSION
	Type    uint8  // One of the OFPT_ constants
	Length  uint16 // Length including this header
	Xid     uint32 // Transaction id associated with this packet
}

// Size returns the size of the header
func (h *Header) Size() int {
	return HeaderSize
}

// MarshalBinary encodes the header to binary
func (h *Header) MarshalBinary() ([]byte, error) {
	data := make([]byte, HeaderSize)
	data[0] = h.Version
	data[1] = h.Type
	ByteOrder.PutUint16(data[2:4], h.Length)
	ByteOrder.PutUint32(data[4:8], h.Xid)
	return data, nil
}

// UnmarshalBinary decodes the header from binary
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return &MessageError{Msg: fmt.Sprintf("header too short: got %d, need %d", len(data), HeaderSize)}
	}
	h.Version = data[0]
	h.Type = data[1]
	h.Length = ByteOrder.Uint16(data[2:4])
	h.Xid = ByteOrder.Uint32(data[4:8])
	return nil
}

// NewHeader creates a new OpenFlow header
func NewHeader(msgType uint8, length uint16, xid uint32) *Header {
	return &Header{
		Version: DefaultVersion,
		Type:    msgType,
		Length:  length,
		Xid:     xid,
	}
}
