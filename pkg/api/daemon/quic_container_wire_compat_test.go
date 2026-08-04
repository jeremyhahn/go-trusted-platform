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

package daemon

import (
	"testing"

	"google.golang.org/protobuf/proto"

	quic "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The tests in this file guard the QUIC wire contract for the container
// surface between the platform SDK client and the daemon. The canonical
// contract is the platform.v1 ComputeService protobuf messages themselves:
// the SDK QUIC transport adapter encodes the pb request structs directly and
// the daemon decodes the payload into the same pb types (and vice versa for
// responses). Every message is round-tripped through the payload codec
// (encode SDK-side shape -> decode daemon-side shape) and compared with
// proto.Equal so a codec or field-shape regression on either side fails here
// first. The probe that proved these messages are codec-safe (no protobuf
// oneofs, unlike the DNS Record message) is captured by these round-trips.

// roundTripPBWire encodes src through the QUIC payload codec and decodes it
// into dst, asserting proto.Equal. It is the shared wire-compat helper for
// the pb-delegated QUIC surfaces (container, attestation, DNS zone ops).
func roundTripPBWire(t *testing.T, src, dst proto.Message) {
	t.Helper()
	payload, err := quic.EncodePayload(src)
	if err != nil {
		t.Fatalf("encode %T: %v", src, err)
	}
	if err := quic.DecodePayload(payload, dst); err != nil {
		t.Fatalf("decode %T into %T: %v", src, dst, err)
	}
	if !proto.Equal(src, dst) {
		t.Fatalf("round trip mismatch:\n src: %+v\n dst: %+v", src, dst)
	}
}

// compatTestContainerConfig builds a fully-populated ContainerConfig covering
// the fields a flat {Name,Image} decode would have dropped (the config lives
// one level down under CreateContainerRequest.Config).
func compatTestContainerConfig() *platformv1.ContainerConfig {
	return &platformv1.ContainerConfig{
		Name:         "web-01",
		Image:        "docker.io/library/nginx",
		ImageHash:    "sha256:deadbeef",
		Command:      []string{"/usr/sbin/nginx"},
		Args:         []string{"-g", "daemon off;"},
		Env:          []*platformv1.EnvVar{{Name: "TZ", Value: "UTC"}},
		WorkingDir:   "/srv",
		Privileged:   true,
		Capabilities: []string{"NET_ADMIN"},
		TpmAccess:    true,
		Network:      "trusted",
		Labels:       map[string]string{"tier": "edge"},
		Metadata:     map[string]string{"owner": "platform"},
		User:         "www-data",
	}
}

func compatTestContainer() *platformv1.Container {
	return &platformv1.Container{
		Id:     "ctr-5001",
		Config: compatTestContainerConfig(),
		State:  platformv1.ContainerState_CONTAINER_STATE_RUNNING,
		HostId: "lab-node-2",
	}
}

// TestQUICContainerWireCompatCreate round-trips CreateContainer, the message
// whose nested Config field a flat decode silently dropped.
func TestQUICContainerWireCompatCreate(t *testing.T) {
	roundTripPBWire(t,
		&platformv1.CreateContainerRequest{
			Config:         compatTestContainerConfig(),
			Start:          true,
			AttestOnCreate: true,
		},
		&platformv1.CreateContainerRequest{})
	roundTripPBWire(t,
		&platformv1.CreateContainerResponse{
			Status:    &platformv1.Status{Success: true, Message: "Container created successfully"},
			Container: compatTestContainer(),
		},
		&platformv1.CreateContainerResponse{})
}

// TestQUICContainerWireCompatStartStop round-trips Start/Stop.
func TestQUICContainerWireCompatStartStop(t *testing.T) {
	roundTripPBWire(t, &platformv1.StartContainerRequest{Id: "ctr-5001"}, &platformv1.StartContainerRequest{})
	roundTripPBWire(t,
		&platformv1.StartContainerResponse{Status: &platformv1.Status{Success: true}},
		&platformv1.StartContainerResponse{})

	roundTripPBWire(t,
		&platformv1.StopContainerRequest{Id: "ctr-5001", TimeoutSeconds: 30},
		&platformv1.StopContainerRequest{})
	roundTripPBWire(t,
		&platformv1.StopContainerResponse{Status: &platformv1.Status{Success: true}},
		&platformv1.StopContainerResponse{})
}

// TestQUICContainerWireCompatDelete round-trips DeleteContainer (mapped to
// OpContainerRemove) with its force / delete_volumes flags.
func TestQUICContainerWireCompatDelete(t *testing.T) {
	roundTripPBWire(t,
		&platformv1.DeleteContainerRequest{Id: "ctr-5001", Force: true, DeleteVolumes: true},
		&platformv1.DeleteContainerRequest{})
	roundTripPBWire(t,
		&platformv1.DeleteContainerResponse{Status: &platformv1.Status{Success: true}},
		&platformv1.DeleteContainerResponse{})
}

// TestQUICContainerWireCompatGet round-trips GetContainer.
func TestQUICContainerWireCompatGet(t *testing.T) {
	roundTripPBWire(t, &platformv1.GetContainerRequest{Id: "ctr-5001"}, &platformv1.GetContainerRequest{})
	roundTripPBWire(t,
		&platformv1.GetContainerResponse{Container: compatTestContainer()},
		&platformv1.GetContainerResponse{})
}

// TestQUICContainerWireCompatList round-trips ListContainers with a selector,
// pagination, and state filter.
func TestQUICContainerWireCompatList(t *testing.T) {
	roundTripPBWire(t,
		&platformv1.ListContainersRequest{
			Selector:   &platformv1.LabelSelector{MatchLabels: map[string]string{"tier": "edge"}},
			Pagination: &platformv1.PaginationRequest{Page: 1, PageSize: 25},
			States:     []platformv1.ContainerState{platformv1.ContainerState_CONTAINER_STATE_RUNNING},
			NameFilter: "web",
		},
		&platformv1.ListContainersRequest{})
	roundTripPBWire(t,
		&platformv1.ListContainersResponse{
			Containers: []*platformv1.Container{compatTestContainer()},
			Pagination: &platformv1.PaginationResponse{Page: 1, PageSize: 25, TotalPages: 1, TotalItems: 1},
		},
		&platformv1.ListContainersResponse{})
}
