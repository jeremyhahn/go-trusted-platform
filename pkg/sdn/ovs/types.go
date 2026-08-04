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

package ovs

import (
	"encoding/json"
	"fmt"
)

// Bridge represents an OVS bridge
type Bridge struct {
	UUID          string
	Name          string
	DatapathType  string
	Ports         []string
	FailMode      string
	FlowProtocols []string
	Controller    []string
	ExternalIDs   map[string]string
	OtherConfig   map[string]string
	Status        map[string]string
	STP           bool
	RSTP          bool
	McastSnooping bool
	Netflow       string
	Sflow         string
	Ipfix         string
	FloodVLANs    []int64
	AutoAttach    string
}

// Port represents an OVS port
type Port struct {
	UUID        string
	Name        string
	Interfaces  []string
	Tag         int64
	Trunks      []int64
	VLANMode    string
	QoS         string
	MAC         string
	BondMode    string
	BondUpDelay int64
	ExternalIDs map[string]string
	OtherConfig map[string]string
	Statistics  map[string]int64
}

// Interface represents an OVS interface
type Interface struct {
	UUID        string
	Name        string
	Type        string
	MAC         string
	MTU         int64
	OFPort      int32 // OpenFlow port number (ofport in OVSDB)
	AdminState  string
	LinkState   string
	Duplex      string
	Speed       int64
	Statistics  map[string]int64
	ExternalIDs map[string]string
	OtherConfig map[string]string
}

// Flow represents an OpenFlow rule
type Flow struct {
	Table       int
	Priority    int
	Match       string
	Actions     string
	IdleAge     int
	HardAge     int
	Cookie      string
	Duration    int
	PacketCount int64
	ByteCount   int64
}

// FlowMod represents a flow modification operation
type FlowMod struct {
	Table       int
	Priority    int
	Match       string
	Actions     string
	Cookie      string
	IdleTimeout int
	HardTimeout int
}

// PortState represents the operational state of a port
type PortState string

const (
	// PortStateUp indicates the port is up
	PortStateUp PortState = "up"

	// PortStateDown indicates the port is down
	PortStateDown PortState = "down"
)

// UUID represents an OVSDB UUID
type UUID struct {
	UUID string `json:"uuid"`
}

// NamedUUID represents an OVSDB named-uuid
type NamedUUID struct {
	NamedUUID string `json:"named-uuid"`
}

// Set represents an OVSDB set
type Set struct {
	Set []interface{}
}

// MarshalJSON implements json.Marshaler for Set
// OVSDB expects ["set", [...]] format
func (s Set) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"set", s.Set})
}

// Map represents an OVSDB map
type Map struct {
	Map [][]interface{}
}

// MarshalJSON implements json.Marshaler for Map
// OVSDB expects ["map", [[k1,v1], [k2,v2], ...]] format
func (m Map) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{"map", m.Map})
}

// OVSDBValue represents a value in OVSDB format
type OVSDBValue interface{}

// MarshalSet marshals a slice into an OVSDB set
func MarshalSet(values []interface{}) OVSDBValue {
	if len(values) == 0 {
		return Set{Set: []interface{}{}}
	}
	if len(values) == 1 {
		return values[0]
	}
	return Set{Set: values}
}

// MarshalMap marshals a map into an OVSDB map
func MarshalMap(m map[string]string) OVSDBValue {
	if len(m) == 0 {
		return Map{Map: [][]interface{}{}}
	}
	pairs := make([][]interface{}, 0, len(m))
	for k, v := range m {
		pairs = append(pairs, []interface{}{k, v})
	}
	return Map{Map: pairs}
}

// UnmarshalSet unmarshals an OVSDB set
func UnmarshalSet(value interface{}) ([]interface{}, error) {
	switch v := value.(type) {
	case []interface{}:
		return v, nil
	case map[string]interface{}:
		if set, ok := v["set"].([]interface{}); ok {
			return set, nil
		}
	}
	return nil, &MessageError{Msg: fmt.Sprintf("cannot unmarshal set from %T", value)}
}

// UnmarshalMap unmarshals an OVSDB map
func UnmarshalMap(value interface{}) (map[string]string, error) {
	result := make(map[string]string)

	switch v := value.(type) {
	case map[string]interface{}:
		if mapData, ok := v["map"].([]interface{}); ok {
			for _, pair := range mapData {
				if p, ok := pair.([]interface{}); ok && len(p) == 2 {
					if key, ok := p[0].(string); ok {
						if val, ok := p[1].(string); ok {
							result[key] = val
						}
					}
				}
			}
			return result, nil
		}
	}

	return result, nil
}

// UnmarshalUUID extracts a UUID from an OVSDB value
func UnmarshalUUID(value interface{}) (string, error) {
	switch v := value.(type) {
	case string:
		return v, nil
	case []interface{}:
		if len(v) == 2 && v[0] == "uuid" {
			if uuid, ok := v[1].(string); ok {
				return uuid, nil
			}
		}
	case map[string]interface{}:
		if uuid, ok := v["uuid"].(string); ok {
			return uuid, nil
		}
	}
	return "", ErrInvalidUUID
}

// MarshalJSON implements json.Marshaler for UUID
func (u UUID) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string{"uuid", u.UUID})
}

// UnmarshalJSON implements json.Unmarshaler for UUID
func (u *UUID) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as array first ["uuid", "actual-uuid"]
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) == 2 && arr[0] == "uuid" {
			u.UUID = arr[1]
			return nil
		}
	}

	// Try to unmarshal as simple object {"uuid": "actual-uuid"}
	type plainUUID UUID
	var plain plainUUID
	if err := json.Unmarshal(data, &plain); err == nil {
		*u = UUID(plain)
		return nil
	}

	return ErrInvalidUUID
}

// MarshalJSON implements json.Marshaler for NamedUUID
func (n NamedUUID) MarshalJSON() ([]byte, error) {
	return json.Marshal([]string{"named-uuid", n.NamedUUID})
}
