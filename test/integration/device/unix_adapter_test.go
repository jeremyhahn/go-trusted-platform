//go:build integration

package device

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// assignClient answers AssignProfileToDevice with resp and records the
// request; every other DeviceServiceClient method is left unimplemented.
type assignClient struct {
	pb.DeviceServiceClient
	resp *pb.AssignProfileToDeviceResponse
	req  *pb.AssignProfileToDeviceRequest
}

func (c *assignClient) AssignProfileToDevice(_ context.Context, req *pb.AssignProfileToDeviceRequest, _ ...grpc.CallOption) (*pb.AssignProfileToDeviceResponse, error) {
	c.req = req
	return c.resp, nil
}

func TestUnixAssignProfileToDevice_ReturnsTheDeviceBinding(t *testing.T) {
	assignedAt := time.Date(2026, 10, 17, 22, 36, 38, 0, time.UTC)
	client := &assignClient{resp: &pb.AssignProfileToDeviceResponse{Profile: &pb.DeviceProfile{
		Id:         554110910726213,
		Name:       "assign-me",
		EkSerial:   "ASSIGN-EK-d28b1c6b",
		MacAddress: "aa:bb:cc:dd:ee:ff",
		Assigned:   true,
		AssignedAt: timestamppb.New(assignedAt),
	}}}
	adapter := &UnixAdapter{client: client}

	result, err := adapter.AssignProfileToDevice(context.Background(), AssignProfileToDeviceOptions{
		ProfileID: "554110910726213",
		EKSerial:  "ASSIGN-EK-d28b1c6b",
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(554110910726213), client.req.GetProfileId())
	assert.Equal(t, "ASSIGN-EK-d28b1c6b", client.req.GetEkSerial())

	profile := result.Profile
	require.NotNil(t, profile)
	assert.Equal(t, uint64(554110910726213), profile.ID)
	assert.Equal(t, "ASSIGN-EK-d28b1c6b", profile.EKSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", profile.MACAddress)
	assert.True(t, profile.Assigned)
	assert.True(t, assignedAt.Equal(profile.AssignedAt), "assigned_at = %v", profile.AssignedAt)
}

func TestUnixAssignProfileToDevice_RejectsBadInput(t *testing.T) {
	t.Run("non-numeric profile id", func(t *testing.T) {
		adapter := &UnixAdapter{client: &assignClient{}}
		_, err := adapter.AssignProfileToDevice(context.Background(), AssignProfileToDeviceOptions{ProfileID: "abc"})
		var rpcErr ErrUnixRPCFailed
		require.True(t, errors.As(err, &rpcErr), "got %v", err)
		assert.Equal(t, "AssignProfileToDevice", rpcErr.Method)
	})

	t.Run("no profile in the response", func(t *testing.T) {
		adapter := &UnixAdapter{client: &assignClient{resp: &pb.AssignProfileToDeviceResponse{}}}
		_, err := adapter.AssignProfileToDevice(context.Background(), AssignProfileToDeviceOptions{ProfileID: "1", EKSerial: "EK-1"})
		var rpcErr ErrUnixRPCFailed
		require.True(t, errors.As(err, &rpcErr), "got %v", err)
		assert.Equal(t, "AssignProfileToDevice", rpcErr.Method)
	})
}
