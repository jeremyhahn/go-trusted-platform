//go:build awscompute

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

package aws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	smithy "github.com/aws/smithy-go"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeEC2 implements ec2API with per-method function seams. A nil seam
// returns a benign empty output so tests set only the calls they exercise.
type fakeEC2 struct {
	runInstances       func(context.Context, *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error)
	startInstances     func(context.Context, *ec2.StartInstancesInput) (*ec2.StartInstancesOutput, error)
	stopInstances      func(context.Context, *ec2.StopInstancesInput) (*ec2.StopInstancesOutput, error)
	terminateInstances func(context.Context, *ec2.TerminateInstancesInput) (*ec2.TerminateInstancesOutput, error)
	describeInstances  func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error)
	describeImages     func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error)
	attachNIC          func(context.Context, *ec2.AttachNetworkInterfaceInput) (*ec2.AttachNetworkInterfaceOutput, error)
	detachNIC          func(context.Context, *ec2.DetachNetworkInterfaceInput) (*ec2.DetachNetworkInterfaceOutput, error)
	getEK              func(context.Context, *ec2.GetInstanceTpmEkPubInput) (*ec2.GetInstanceTpmEkPubOutput, error)
	createSnapshot     func(context.Context, *ec2.CreateSnapshotInput) (*ec2.CreateSnapshotOutput, error)
	deleteSnapshot     func(context.Context, *ec2.DeleteSnapshotInput) (*ec2.DeleteSnapshotOutput, error)
	describeSnapshots  func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error)
	createVolume       func(context.Context, *ec2.CreateVolumeInput) (*ec2.CreateVolumeOutput, error)
	deleteVolume       func(context.Context, *ec2.DeleteVolumeInput) (*ec2.DeleteVolumeOutput, error)
	attachVolume       func(context.Context, *ec2.AttachVolumeInput) (*ec2.AttachVolumeOutput, error)
	detachVolume       func(context.Context, *ec2.DetachVolumeInput) (*ec2.DetachVolumeOutput, error)
	describeVolumes    func(context.Context, *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error)
}

func (f *fakeEC2) RunInstances(ctx context.Context, in *ec2.RunInstancesInput, _ ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error) {
	if f.runInstances != nil {
		return f.runInstances(ctx, in)
	}
	return &ec2.RunInstancesOutput{}, nil
}

func (f *fakeEC2) StartInstances(ctx context.Context, in *ec2.StartInstancesInput, _ ...func(*ec2.Options)) (*ec2.StartInstancesOutput, error) {
	if f.startInstances != nil {
		return f.startInstances(ctx, in)
	}
	return &ec2.StartInstancesOutput{}, nil
}

func (f *fakeEC2) StopInstances(ctx context.Context, in *ec2.StopInstancesInput, _ ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error) {
	if f.stopInstances != nil {
		return f.stopInstances(ctx, in)
	}
	return &ec2.StopInstancesOutput{}, nil
}

func (f *fakeEC2) TerminateInstances(ctx context.Context, in *ec2.TerminateInstancesInput, _ ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error) {
	if f.terminateInstances != nil {
		return f.terminateInstances(ctx, in)
	}
	return &ec2.TerminateInstancesOutput{}, nil
}

func (f *fakeEC2) DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, _ ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	if f.describeInstances != nil {
		return f.describeInstances(ctx, in)
	}
	return &ec2.DescribeInstancesOutput{}, nil
}

func (f *fakeEC2) DescribeImages(ctx context.Context, in *ec2.DescribeImagesInput, _ ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error) {
	if f.describeImages != nil {
		return f.describeImages(ctx, in)
	}
	return &ec2.DescribeImagesOutput{}, nil
}

func (f *fakeEC2) AttachNetworkInterface(ctx context.Context, in *ec2.AttachNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error) {
	if f.attachNIC != nil {
		return f.attachNIC(ctx, in)
	}
	return &ec2.AttachNetworkInterfaceOutput{}, nil
}

func (f *fakeEC2) DetachNetworkInterface(ctx context.Context, in *ec2.DetachNetworkInterfaceInput, _ ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error) {
	if f.detachNIC != nil {
		return f.detachNIC(ctx, in)
	}
	return &ec2.DetachNetworkInterfaceOutput{}, nil
}

func (f *fakeEC2) GetInstanceTpmEkPub(ctx context.Context, in *ec2.GetInstanceTpmEkPubInput, _ ...func(*ec2.Options)) (*ec2.GetInstanceTpmEkPubOutput, error) {
	if f.getEK != nil {
		return f.getEK(ctx, in)
	}
	return &ec2.GetInstanceTpmEkPubOutput{}, nil
}

func (f *fakeEC2) CreateSnapshot(ctx context.Context, in *ec2.CreateSnapshotInput, _ ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error) {
	if f.createSnapshot != nil {
		return f.createSnapshot(ctx, in)
	}
	return &ec2.CreateSnapshotOutput{}, nil
}

func (f *fakeEC2) DeleteSnapshot(ctx context.Context, in *ec2.DeleteSnapshotInput, _ ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error) {
	if f.deleteSnapshot != nil {
		return f.deleteSnapshot(ctx, in)
	}
	return &ec2.DeleteSnapshotOutput{}, nil
}

func (f *fakeEC2) DescribeSnapshots(ctx context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	if f.describeSnapshots != nil {
		return f.describeSnapshots(ctx, in)
	}
	return &ec2.DescribeSnapshotsOutput{}, nil
}

func (f *fakeEC2) CreateVolume(ctx context.Context, in *ec2.CreateVolumeInput, _ ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error) {
	if f.createVolume != nil {
		return f.createVolume(ctx, in)
	}
	return &ec2.CreateVolumeOutput{}, nil
}

func (f *fakeEC2) DeleteVolume(ctx context.Context, in *ec2.DeleteVolumeInput, _ ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error) {
	if f.deleteVolume != nil {
		return f.deleteVolume(ctx, in)
	}
	return &ec2.DeleteVolumeOutput{}, nil
}

func (f *fakeEC2) AttachVolume(ctx context.Context, in *ec2.AttachVolumeInput, _ ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error) {
	if f.attachVolume != nil {
		return f.attachVolume(ctx, in)
	}
	return &ec2.AttachVolumeOutput{}, nil
}

func (f *fakeEC2) DetachVolume(ctx context.Context, in *ec2.DetachVolumeInput, _ ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error) {
	if f.detachVolume != nil {
		return f.detachVolume(ctx, in)
	}
	return &ec2.DetachVolumeOutput{}, nil
}

func (f *fakeEC2) DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, _ ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error) {
	if f.describeVolumes != nil {
		return f.describeVolumes(ctx, in)
	}
	return &ec2.DescribeVolumesOutput{}, nil
}

// newTestOrchestrator builds an orchestrator over a fake client with tiny
// poll intervals so waits complete instantly and never touch the network.
func newTestOrchestrator(t *testing.T, client ec2API) *AWSOrchestrator {
	t.Helper()
	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderAWS,
		WorkDir:      t.TempDir(),
		MaxInstances: 10,
		AWS: &compute.AWSProviderConfig{
			Region:       "us-east-1",
			AMIID:        "ami-nitrotpm",
			InstanceType: "m5.large",
		},
	}
	o := newOrchestrator(cfg, logging.DefaultLogger(), client)
	o.pollInterval = time.Millisecond
	o.pollTimeout = 2 * time.Second
	return o
}

// runningInstance returns a fake EC2 instance in the running state with a
// tagged name and an EBS root volume.
func runningInstance(id string) ec2types.Instance {
	return ec2types.Instance{
		InstanceId:     awssdk.String(id),
		ImageId:        awssdk.String("ami-nitrotpm"),
		InstanceType:   ec2types.InstanceType("m5.large"),
		State:          &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		RootDeviceName: awssdk.String("/dev/xvda"),
		Placement:      &ec2types.Placement{AvailabilityZone: awssdk.String("us-east-1a")},
		BlockDeviceMappings: []ec2types.InstanceBlockDeviceMapping{{
			DeviceName: awssdk.String("/dev/xvda"),
			Ebs:        &ec2types.EbsInstanceBlockDevice{VolumeId: awssdk.String("vol-root")},
		}},
		Tags: []ec2types.Tag{{Key: awssdk.String(nameTagKey), Value: awssdk.String("node-01")}},
	}
}

// describeOutput wraps instances in a single reservation.
func describeOutput(instances ...ec2types.Instance) *ec2.DescribeInstancesOutput {
	return &ec2.DescribeInstancesOutput{
		Reservations: []ec2types.Reservation{{Instances: instances}},
	}
}

// nitroTPMImages returns a DescribeImages output for a NitroTPM-capable AMI.
func nitroTPMImages() *ec2.DescribeImagesOutput {
	return &ec2.DescribeImagesOutput{
		Images: []ec2types.Image{{
			ImageId:    awssdk.String("ami-nitrotpm"),
			TpmSupport: ec2types.TpmSupportValuesV20,
		}},
	}
}

// base64EKPub returns a base64-encoded DER PKIX RSA public key suitable for
// a fake GetInstanceTpmEkPub response.
func base64EKPub(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// notFoundErr is a smithy APIError whose code marks a not-found condition.
type notFoundErr struct{}

func (notFoundErr) Error() string                 { return "InvalidInstanceID.NotFound: nope" }
func (notFoundErr) ErrorCode() string             { return "InvalidInstanceID.NotFound" }
func (notFoundErr) ErrorMessage() string          { return "nope" }
func (notFoundErr) ErrorFault() smithy.ErrorFault { return smithy.FaultClient }
