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

// Group mod commands
const (
	OFPGCAdd    = 0 // OFPGC_ADD: New group
	OFPGCModify = 1 // OFPGC_MODIFY: Modify all matching groups
	OFPGCDelete = 2 // OFPGC_DELETE: Delete all matching groups
)

// Group types
const (
	OFPGTAll      = 0 // OFPGT_ALL: All (multicast/broadcast) group
	OFPGTSelect   = 1 // OFPGT_SELECT: Select group
	OFPGTIndirect = 2 // OFPGT_INDIRECT: Indirect group
	OFPGTFF       = 3 // OFPGT_FF: Fast failover group
)

// Special group numbers
const (
	OFPGAny = 0xffffffff // OFPG_ANY: Wildcard group used only for flow stats requests
	OFPGAll = 0xfffffffc // OFPG_ALL: All groups, for group delete commands
)

// groupModFixedLength is the group mod body length (excluding OF header and buckets)
const groupModFixedLength = 8

// bucketFixedLength is the fixed portion of a bucket (excluding actions)
const bucketFixedLength = 16

// Bucket represents an action bucket within a group. For non-fast-failover
// groups WatchPort and WatchGroup must be OFPPAny / OFPGAny.
type Bucket struct {
	Weight     uint16 // Relative weight, only defined for select groups
	WatchPort  uint32 // Port whose state affects this bucket, only for fast failover groups
	WatchGroup uint32 // Group whose state affects this bucket, only for fast failover groups
	Actions    []Action
}

// bucketLength returns the encoded bucket length (fixed part plus actions)
func (b *Bucket) bucketLength() uint16 {
	length := bucketFixedLength
	for _, action := range b.Actions {
		length += int(action.Length())
	}
	return uint16((length + 7) & ^7)
}

// MarshalBinary encodes the bucket
func (b *Bucket) MarshalBinary() ([]byte, error) {
	length := b.bucketLength()
	data := make([]byte, length)

	ByteOrder.PutUint16(data[0:2], length)
	ByteOrder.PutUint16(data[2:4], b.Weight)
	ByteOrder.PutUint32(data[4:8], b.WatchPort)
	ByteOrder.PutUint32(data[8:12], b.WatchGroup)
	// 4 bytes padding (data[12:16])

	offset := bucketFixedLength
	for _, action := range b.Actions {
		actionData, err := action.MarshalBinary()
		if err != nil {
			return nil, err
		}
		copy(data[offset:], actionData)
		offset += len(actionData)
	}

	return data, nil
}

// GroupMod represents a Group Modification message
type GroupMod struct {
	Header  Header
	Command uint16 // One of OFPGC_*
	Type    uint8  // One of OFPGT_*
	GroupID uint32 // Group identifier
	Buckets []Bucket
}

// NewGroupMod creates a new GroupMod message
func NewGroupMod(command uint16, groupType uint8, groupID uint32) *GroupMod {
	return &GroupMod{
		Header: Header{
			Version: DefaultVersion,
			Type:    OFPTGroupMod,
		},
		Command: command,
		Type:    groupType,
		GroupID: groupID,
	}
}

// AddBucket appends a bucket with the given weight and actions. WatchPort and
// WatchGroup are set to OFPPAny / OFPGAny (unused for non-fast-failover groups).
func (g *GroupMod) AddBucket(weight uint16, actions ...Action) *GroupMod {
	g.Buckets = append(g.Buckets, Bucket{
		Weight:     weight,
		WatchPort:  OFPPAny,
		WatchGroup: OFPGAny,
		Actions:    actions,
	})
	return g
}

// MarshalBinary encodes the GroupMod
func (g *GroupMod) MarshalBinary() ([]byte, error) {
	bucketsData := make([]byte, 0)
	for i := range g.Buckets {
		bucketData, err := g.Buckets[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		bucketsData = append(bucketsData, bucketData...)
	}

	// Total length: header (8) + body (8) + buckets
	length := HeaderSize + groupModFixedLength + len(bucketsData)
	g.Header.Length = uint16(length)

	data := make([]byte, length)

	headerData, err := g.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(data[0:8], headerData)

	ByteOrder.PutUint16(data[8:10], g.Command)
	data[10] = g.Type
	// 1 byte padding (data[11])
	ByteOrder.PutUint32(data[12:16], g.GroupID)

	copy(data[16:], bucketsData)

	return data, nil
}

// ActionGroup represents an apply-group action (OFPAT_GROUP)
type ActionGroup struct {
	GroupID uint32
}

// NewActionGroup creates a new apply-group action
func NewActionGroup(groupID uint32) *ActionGroup {
	return &ActionGroup{GroupID: groupID}
}

// Length returns the action length
func (a *ActionGroup) Length() uint16 {
	return 8
}

// MarshalBinary encodes the apply-group action
func (a *ActionGroup) MarshalBinary() ([]byte, error) {
	data := make([]byte, 8)
	ByteOrder.PutUint16(data[0:2], OFPATGroup)
	ByteOrder.PutUint16(data[2:4], 8)
	ByteOrder.PutUint32(data[4:8], a.GroupID)
	return data, nil
}

// ActionRaw preserves an action whose type has no dedicated decoder. Data
// holds the complete action bytes including the action header so the action
// round-trips losslessly.
type ActionRaw struct {
	ActionType uint16
	Data       []byte
}

// Length returns the action length
func (a *ActionRaw) Length() uint16 {
	return uint16(len(a.Data))
}

// MarshalBinary encodes the raw action
func (a *ActionRaw) MarshalBinary() ([]byte, error) {
	if len(a.Data) < 4 {
		return nil, ErrInvalidAction
	}
	return append([]byte(nil), a.Data...), nil
}

// GroupDesc describes a single group from an OFPMP_GROUP_DESC multipart reply
type GroupDesc struct {
	Type    uint8  // One of OFPGT_*
	GroupID uint32 // Group identifier
	Buckets []Bucket
}

// ParseGroupDesc parses group descriptions from a multipart reply body
func ParseGroupDesc(data []byte) ([]GroupDesc, error) {
	var groups []GroupDesc
	offset := 0

	for offset < len(data) {
		if len(data)-offset < groupModFixedLength {
			return nil, &MessageError{Msg: "group desc entry too short"}
		}

		length := int(ByteOrder.Uint16(data[offset : offset+2]))
		if length < groupModFixedLength || length > len(data)-offset {
			return nil, &MessageError{Msg: "invalid group desc length"}
		}

		desc := GroupDesc{
			Type:    data[offset+2],
			GroupID: ByteOrder.Uint32(data[offset+4 : offset+8]),
		}

		buckets, err := parseBuckets(data[offset+groupModFixedLength : offset+length])
		if err != nil {
			return nil, err
		}
		desc.Buckets = buckets

		groups = append(groups, desc)
		offset += length
	}

	return groups, nil
}

// parseBuckets parses a sequence of encoded buckets
func parseBuckets(data []byte) ([]Bucket, error) {
	var buckets []Bucket
	offset := 0

	for offset < len(data) {
		if len(data)-offset < bucketFixedLength {
			return nil, &MessageError{Msg: "bucket too short"}
		}

		length := int(ByteOrder.Uint16(data[offset : offset+2]))
		if length < bucketFixedLength || length > len(data)-offset {
			return nil, &MessageError{Msg: "invalid bucket length"}
		}

		bucket := Bucket{
			Weight:     ByteOrder.Uint16(data[offset+2 : offset+4]),
			WatchPort:  ByteOrder.Uint32(data[offset+4 : offset+8]),
			WatchGroup: ByteOrder.Uint32(data[offset+8 : offset+12]),
		}

		actions, err := parseActions(data[offset+bucketFixedLength : offset+length])
		if err != nil {
			return nil, err
		}
		bucket.Actions = actions

		buckets = append(buckets, bucket)
		offset += length
	}

	return buckets, nil
}

// parseActions parses a sequence of encoded actions. Output and group actions
// decode to their concrete types; all other action types are preserved as
// ActionRaw for lossless round-tripping.
func parseActions(data []byte) ([]Action, error) {
	var actions []Action
	offset := 0

	for offset < len(data) {
		if len(data)-offset < 4 {
			return nil, &MessageError{Msg: "action too short"}
		}

		actionType := ByteOrder.Uint16(data[offset : offset+2])
		length := int(ByteOrder.Uint16(data[offset+2 : offset+4]))
		if length < 8 || length > len(data)-offset {
			return nil, &MessageError{Msg: "invalid action length"}
		}

		switch actionType {
		case OFPATOutput:
			if length < 10 {
				return nil, &MessageError{Msg: "output action too short"}
			}
			actions = append(actions, &ActionOutput{
				Port:   ByteOrder.Uint32(data[offset+4 : offset+8]),
				MaxLen: ByteOrder.Uint16(data[offset+8 : offset+10]),
			})

		case OFPATGroup:
			actions = append(actions, &ActionGroup{
				GroupID: ByteOrder.Uint32(data[offset+4 : offset+8]),
			})

		default:
			actions = append(actions, &ActionRaw{
				ActionType: actionType,
				Data:       append([]byte(nil), data[offset:offset+length]...),
			})
		}

		offset += length
	}

	return actions, nil
}
