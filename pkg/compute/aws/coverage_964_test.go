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
	"errors"
	"path/filepath"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// errFakeAPI is the typed failure the fake EC2 client returns to drive the
// orchestrator's API-error paths.
type errFakeAPI struct{}

func (errFakeAPI) Error() string { return "fake ec2 failure" }

// assertAPIError checks err is an *APIError for op that wraps errFakeAPI.
func assertAPIError(t *testing.T, err error, op string) {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want *APIError", err)
	}
	if apiErr.Op != op {
		t.Fatalf("APIError.Op = %q, want %q", apiErr.Op, op)
	}
	if !errors.Is(err, errFakeAPI{}) {
		t.Fatalf("err = %v, want it to wrap errFakeAPI", err)
	}
}

func TestErrorTypes_MessagesAndUnwrap(t *testing.T) {
	cfgErr := &ConfigError{Msg: "region is required"}
	if got, want := cfgErr.Error(), "aws compute: invalid configuration: region is required"; got != want {
		t.Fatalf("ConfigError.Error() = %q, want %q", got, want)
	}

	apiErr := &APIError{Op: "RunInstances", Err: errFakeAPI{}}
	if got, want := apiErr.Error(), "aws compute: EC2 RunInstances failed: fake ec2 failure"; got != want {
		t.Fatalf("APIError.Error() = %q, want %q", got, want)
	}
	if !errors.Is(apiErr, errFakeAPI{}) {
		t.Fatal("APIError does not unwrap to its cause")
	}

	sc := &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: errFakeAPI{}}
	if got, want := sc.Error(), ErrEndorsementKey.Error()+": fake ec2 failure"; got != want {
		t.Fatalf("SentinelCauseError.Error() = %q, want %q", got, want)
	}
	if !errors.Is(sc, ErrEndorsementKey) || !errors.Is(sc, errFakeAPI{}) {
		t.Fatal("SentinelCauseError does not unwrap to both sentinel and cause")
	}
}

func TestIsNotFound(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"smithy not-found code", notFoundErr{}, true},
		{"plain error with NotFound text", &compute.MessageError{Msg: "InvalidVolume.NotFound"}, true},
		{"plain error without NotFound text", errFakeAPI{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.want {
				t.Fatalf("isNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNew_BuildsClientFromStaticCredentialsAndEndpoint(t *testing.T) {
	// Point the SDK's shared config at files that do not exist so the
	// host's ~/.aws never leaks into the test.
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))

	logger := logging.DefaultLogger()
	cfg := &compute.OrchestratorConfig{
		Provider: compute.ProviderAWS,
		AWS: &compute.AWSProviderConfig{
			Region:          "eu-west-1",
			AMIID:           "ami-1",
			InstanceType:    "m5.large",
			AccessKeyID:     "AKIDEXAMPLE",
			SecretAccessKey: "secret",
			SessionToken:    "token",
			Endpoint:        "http://127.0.0.1:4566",
		},
	}
	orch, err := New(context.Background(), cfg, &compute.Deps{Logger: logger})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	o, ok := orch.(*AWSOrchestrator)
	if !ok {
		t.Fatalf("New returned %T, want *AWSOrchestrator", orch)
	}
	if o.logger != logger {
		t.Fatal("New did not use the logger from deps")
	}
	client, ok := o.client.(*ec2.Client)
	if !ok {
		t.Fatalf("client is %T, want *ec2.Client", o.client)
	}
	opts := client.Options()
	if opts.Region != "eu-west-1" {
		t.Fatalf("region = %q, want eu-west-1", opts.Region)
	}
	if awssdk.ToString(opts.BaseEndpoint) != "http://127.0.0.1:4566" {
		t.Fatalf("endpoint = %q, want the configured endpoint", awssdk.ToString(opts.BaseEndpoint))
	}
	creds, err := opts.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve credentials: %v", err)
	}
	if creds.AccessKeyID != "AKIDEXAMPLE" || creds.SessionToken != "token" {
		t.Fatalf("credentials = %+v, want the static credentials", creds)
	}
}

func TestNewOrchestrator_NilLoggerUsesDefault(t *testing.T) {
	cfg := &compute.OrchestratorConfig{AWS: &compute.AWSProviderConfig{Region: "us-east-1"}}
	o := newOrchestrator(cfg, nil, &fakeEC2{})
	if o.logger == nil {
		t.Fatal("logger is nil, want the default logger")
	}
	if o.pollInterval != defaultPollInterval || o.pollTimeout != defaultPollTimeout {
		t.Fatalf("poll = %v/%v, want defaults", o.pollInterval, o.pollTimeout)
	}
}

func TestCreate_OptionalRunInputFields(t *testing.T) {
	var got *ec2.RunInstancesInput
	fake := &fakeEC2{
		runInstances: func(_ context.Context, in *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) {
			got = in
			return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{runningInstance("i-opt")}}, nil
		},
		describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
			t.Fatal("DescribeImages called although the NitroTPM assertion is skipped")
			return nil, nil
		},
	}
	o := newTestOrchestrator(t, fake)
	o.aws.SkipNitroTPMAssertion = true
	o.aws.SubnetID = "subnet-1"
	o.aws.SecurityGroupIDs = []string{"sg-1", "sg-2"}
	o.aws.KeyName = "key-1"
	o.aws.IAMInstanceProfile = "profile-1"
	o.aws.RootVolumeSizeGiB = 40

	inst, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-opt"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if inst.ID != "i-opt" || inst.Name != "node-opt" {
		t.Fatalf("instance = %+v, want i-opt/node-opt", inst)
	}
	if awssdk.ToString(got.SubnetId) != "subnet-1" {
		t.Fatalf("SubnetId = %q", awssdk.ToString(got.SubnetId))
	}
	if len(got.SecurityGroupIds) != 2 {
		t.Fatalf("SecurityGroupIds = %v", got.SecurityGroupIds)
	}
	if awssdk.ToString(got.KeyName) != "key-1" {
		t.Fatalf("KeyName = %q", awssdk.ToString(got.KeyName))
	}
	if got.IamInstanceProfile == nil || awssdk.ToString(got.IamInstanceProfile.Name) != "profile-1" {
		t.Fatalf("IamInstanceProfile = %+v", got.IamInstanceProfile)
	}
	if len(got.BlockDeviceMappings) != 1 || awssdk.ToInt32(got.BlockDeviceMappings[0].Ebs.VolumeSize) != 40 {
		t.Fatalf("BlockDeviceMappings = %+v, want a 40 GiB root volume", got.BlockDeviceMappings)
	}
}

func TestCreate_Failures(t *testing.T) {
	cases := []struct {
		name   string
		fake   *fakeEC2
		assert func(t *testing.T, err error)
	}{
		{
			name: "DescribeImages error",
			fake: &fakeEC2{describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
				return nil, errFakeAPI{}
			}},
			assert: func(t *testing.T, err error) { assertAPIError(t, err, "DescribeImages") },
		},
		{
			name: "AMI not found",
			fake: &fakeEC2{describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
				return &ec2.DescribeImagesOutput{}, nil
			}},
			assert: func(t *testing.T, err error) {
				if !errors.Is(err, ErrNitroTPMUnsupported) {
					t.Fatalf("err = %v, want ErrNitroTPMUnsupported", err)
				}
			},
		},
		{
			name: "RunInstances returns no instance",
			fake: &fakeEC2{
				describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
					return nitroTPMImages(), nil
				},
				runInstances: func(context.Context, *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) {
					return &ec2.RunInstancesOutput{}, nil
				},
			},
			assert: func(t *testing.T, err error) {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.Op != "RunInstances" || !errors.Is(err, ErrWaitTimeout) {
					t.Fatalf("err = %v, want RunInstances APIError wrapping ErrWaitTimeout", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := newTestOrchestrator(t, tc.fake)
			_, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "n"})
			tc.assert(t, err)
		})
	}
}

func TestStopDelete_APIErrors(t *testing.T) {
	fake := &fakeEC2{
		stopInstances: func(context.Context, *ec2.StopInstancesInput) (*ec2.StopInstancesOutput, error) {
			return nil, errFakeAPI{}
		},
		terminateInstances: func(context.Context, *ec2.TerminateInstancesInput) (*ec2.TerminateInstancesOutput, error) {
			return nil, errFakeAPI{}
		},
	}
	o := newTestOrchestrator(t, fake)
	assertAPIError(t, o.Stop(context.Background(), "i-1"), "StopInstances")
	assertAPIError(t, o.Delete(context.Background(), "i-1"), "TerminateInstances")
}

// describeFails returns a fake whose DescribeInstances fails with err.
func describeFails(err error) *fakeEC2 {
	return &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return nil, err
	}}
}

func TestDescribeInstance_Errors(t *testing.T) {
	ctx := context.Background()

	o := newTestOrchestrator(t, describeFails(errFakeAPI{}))
	_, err := o.Get(ctx, "i-1")
	assertAPIError(t, err, "DescribeInstances")
	state, err := o.GetState(ctx, "i-1")
	assertAPIError(t, err, "DescribeInstances")
	if state != compute.StateUnknown {
		t.Fatalf("state = %v, want StateUnknown", state)
	}

	empty := newTestOrchestrator(t, &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return &ec2.DescribeInstancesOutput{Reservations: []ec2types.Reservation{{}}}, nil
	}})
	if _, err := empty.Get(ctx, "i-1"); !errors.Is(err, compute.ErrInstanceNotFound) {
		t.Fatalf("err = %v, want ErrInstanceNotFound for empty reservations", err)
	}
	if _, err := empty.describeInstance(ctx, ""); !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestNetwork_ValidationAndAPIErrors(t *testing.T) {
	ctx := context.Background()
	o := newTestOrchestrator(t, describeFails(errFakeAPI{}))

	if err := o.AttachNetwork(ctx, "i-1", ""); !errors.Is(err, compute.ErrNetworkAttachmentFailed) {
		t.Fatalf("attach empty port: err = %v, want ErrNetworkAttachmentFailed", err)
	}
	assertAPIError(t, o.AttachNetwork(ctx, "i-1", "eni-1"), "DescribeInstances")

	if err := o.DetachNetwork(ctx, "", "eni-1"); !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("detach empty instance: err = %v, want ErrInvalidInstanceID", err)
	}
	if err := o.DetachNetwork(ctx, "i-1", ""); !errors.Is(err, compute.ErrNetworkDetachmentFailed) {
		t.Fatalf("detach empty port: err = %v, want ErrNetworkDetachmentFailed", err)
	}
	assertAPIError(t, o.DetachNetwork(ctx, "i-1", "eni-1"), "DescribeInstances")

	attached := runningInstance("i-1")
	attached.NetworkInterfaces = []ec2types.InstanceNetworkInterface{{
		NetworkInterfaceId: awssdk.String("eni-1"),
		Attachment:         &ec2types.InstanceNetworkInterfaceAttachment{AttachmentId: awssdk.String("attach-1")},
	}}
	detachFails := newTestOrchestrator(t, &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(attached), nil
		},
		detachNIC: func(context.Context, *ec2.DetachNetworkInterfaceInput) (*ec2.DetachNetworkInterfaceOutput, error) {
			return nil, errFakeAPI{}
		},
	})
	err := detachFails.DetachNetwork(ctx, "i-1", "eni-1")
	if !errors.Is(err, compute.ErrNetworkDetachmentFailed) {
		t.Fatalf("err = %v, want ErrNetworkDetachmentFailed", err)
	}
	assertAPIError(t, err, "DetachNetworkInterface")
}

func TestPollInstanceUntil(t *testing.T) {
	ctx := context.Background()
	never := func(ec2types.InstanceStateName) bool { return false }

	t.Run("timeout", func(t *testing.T) {
		o := newTestOrchestrator(t, &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(runningInstance("i-1")), nil
		}})
		o.pollTimeout = 5 * time.Millisecond
		if err := o.pollInstanceUntil(ctx, "i-1", never); !errors.Is(err, ErrWaitTimeout) {
			t.Fatalf("err = %v, want ErrWaitTimeout", err)
		}
	})

	t.Run("describe error on a later tick", func(t *testing.T) {
		calls := 0
		o := newTestOrchestrator(t, &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			calls++
			if calls > 1 {
				return nil, errFakeAPI{}
			}
			return describeOutput(runningInstance("i-1")), nil
		}})
		assertAPIError(t, o.pollInstanceUntil(ctx, "i-1", never), "DescribeInstances")
	})
}

func TestToInstance_IPMetadata(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	ec2Inst := runningInstance("i-1")
	ec2Inst.PrivateIpAddress = awssdk.String("10.0.0.5")
	ec2Inst.PublicIpAddress = awssdk.String("203.0.113.9")
	inst := o.toInstance(&ec2Inst, "node-01")
	if inst.Metadata["private_ip"] != "10.0.0.5" || inst.Metadata["public_ip"] != "203.0.113.9" {
		t.Fatalf("metadata = %v, want private and public IPs", inst.Metadata)
	}
	if inst.Metadata["availability_zone"] != "us-east-1a" {
		t.Fatalf("availability_zone = %q", inst.Metadata["availability_zone"])
	}
}

func TestMapInstanceState_EdgeCases(t *testing.T) {
	cases := []struct {
		name string
		inst *ec2types.Instance
		want compute.InstanceState
	}{
		{"nil instance", nil, compute.StateUnknown},
		{"nil state", &ec2types.Instance{}, compute.StateUnknown},
		{"stopping", &ec2types.Instance{State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopping}}, compute.StateStopping},
		{"unrecognised", &ec2types.Instance{State: &ec2types.InstanceState{Name: "rebooting"}}, compute.StateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mapInstanceState(tc.inst); got != tc.want {
				t.Fatalf("mapInstanceState = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTagValue_Missing(t *testing.T) {
	tags := []ec2types.Tag{{Key: awssdk.String("a"), Value: awssdk.String("1")}}
	if got := tagValue(tags, "b"); got != "" {
		t.Fatalf("tagValue = %q, want empty for a missing key", got)
	}
}

func TestCreateSnapshot_Failures(t *testing.T) {
	ctx := context.Background()
	if _, err := newTestOrchestrator(t, &fakeEC2{}).CreateSnapshot(ctx, "", "s"); !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
	_, err := newTestOrchestrator(t, describeFails(errFakeAPI{})).CreateSnapshot(ctx, "i-1", "s")
	assertAPIError(t, err, "DescribeInstances")

	fake := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(runningInstance("i-1")), nil
		},
		createSnapshot: func(context.Context, *ec2.CreateSnapshotInput) (*ec2.CreateSnapshotOutput, error) {
			return nil, errFakeAPI{}
		},
	}
	_, err = newTestOrchestrator(t, fake).CreateSnapshot(ctx, "i-1", "s")
	assertAPIError(t, err, "CreateSnapshot")
}

func TestCreateSnapshot_ZeroStartTimeDefaultsToNow(t *testing.T) {
	before := time.Now().UTC()
	fake := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(runningInstance("i-1")), nil
		},
		createSnapshot: func(context.Context, *ec2.CreateSnapshotInput) (*ec2.CreateSnapshotOutput, error) {
			return &ec2.CreateSnapshotOutput{SnapshotId: awssdk.String("snap-1"), VolumeSize: awssdk.Int32(2)}, nil
		},
	}
	snap, err := newTestOrchestrator(t, fake).CreateSnapshot(context.Background(), "i-1", "s")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if snap.CreatedAt.Before(before) {
		t.Fatalf("CreatedAt = %v, want now or later than %v", snap.CreatedAt, before)
	}
	if snap.SizeBytes != 2*gibiBytes {
		t.Fatalf("SizeBytes = %d, want 2 GiB", snap.SizeBytes)
	}
}

func TestDeleteListSnapshot_Failures(t *testing.T) {
	ctx := context.Background()
	o := newTestOrchestrator(t, &fakeEC2{})
	if err := o.DeleteSnapshot(ctx, "", "s"); !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
	if err := o.DeleteSnapshot(ctx, "i-1", ""); !errors.Is(err, compute.ErrInvalidSnapshotName) {
		t.Fatalf("err = %v, want ErrInvalidSnapshotName", err)
	}

	describeErr := newTestOrchestrator(t, &fakeEC2{describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
		return nil, errFakeAPI{}
	}})
	assertAPIError(t, describeErr.DeleteSnapshot(ctx, "i-1", "s"), "DescribeSnapshots")
	_, err := describeErr.ListSnapshots(ctx, "i-1")
	assertAPIError(t, err, "DescribeSnapshots")

	deleteErr := newTestOrchestrator(t, &fakeEC2{
		describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{{SnapshotId: awssdk.String("snap-1")}}}, nil
		},
		deleteSnapshot: func(context.Context, *ec2.DeleteSnapshotInput) (*ec2.DeleteSnapshotOutput, error) {
			return nil, errFakeAPI{}
		},
	})
	assertAPIError(t, deleteErr.DeleteSnapshot(ctx, "i-1", "s"), "DeleteSnapshot")
}

// restoreFake returns a fake on which every RestoreSnapshot step succeeds:
// the snapshot resolves, the instance reports stopped and every volume
// reports available.
func restoreFake() *fakeEC2 {
	stopped := runningInstance("i-1")
	stopped.State = &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}
	return &fakeEC2{
		describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{{SnapshotId: awssdk.String("snap-1")}}}, nil
		},
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(stopped), nil
		},
		describeVolumes: func(context.Context, *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{State: ec2types.VolumeStateAvailable}}}, nil
		},
		createVolume: func(context.Context, *ec2.CreateVolumeInput) (*ec2.CreateVolumeOutput, error) {
			return &ec2.CreateVolumeOutput{VolumeId: awssdk.String("vol-new")}, nil
		},
	}
}

func TestRestoreSnapshot_StepFailures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *fakeEC2)
		op     string
	}{
		{"DescribeSnapshots", func(f *fakeEC2) {
			f.describeSnapshots = func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "DescribeSnapshots"},
		{"DescribeInstances", func(f *fakeEC2) {
			f.describeInstances = func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "DescribeInstances"},
		{"StopInstances", func(f *fakeEC2) {
			f.stopInstances = func(context.Context, *ec2.StopInstancesInput) (*ec2.StopInstancesOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "StopInstances"},
		{"DetachVolume", func(f *fakeEC2) {
			f.detachVolume = func(context.Context, *ec2.DetachVolumeInput) (*ec2.DetachVolumeOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "DetachVolume"},
		{"DescribeVolumes", func(f *fakeEC2) {
			f.describeVolumes = func(context.Context, *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "DescribeVolumes"},
		{"CreateVolume", func(f *fakeEC2) {
			f.createVolume = func(context.Context, *ec2.CreateVolumeInput) (*ec2.CreateVolumeOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "CreateVolume"},
		{"AttachVolume", func(f *fakeEC2) {
			f.attachVolume = func(context.Context, *ec2.AttachVolumeInput) (*ec2.AttachVolumeOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "AttachVolume"},
		{"StartInstances", func(f *fakeEC2) {
			f.startInstances = func(context.Context, *ec2.StartInstancesInput) (*ec2.StartInstancesOutput, error) {
				return nil, errFakeAPI{}
			}
		}, "StartInstances"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := restoreFake()
			tc.mutate(fake)
			err := newTestOrchestrator(t, fake).RestoreSnapshot(context.Background(), "i-1", "s")
			assertAPIError(t, err, tc.op)
		})
	}
}

func TestRestoreSnapshot_PreconditionFailures(t *testing.T) {
	ctx := context.Background()
	o := newTestOrchestrator(t, restoreFake())
	if err := o.RestoreSnapshot(ctx, "", "s"); !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
	if err := o.RestoreSnapshot(ctx, "i-1", ""); !errors.Is(err, compute.ErrInvalidSnapshotName) {
		t.Fatalf("err = %v, want ErrInvalidSnapshotName", err)
	}

	instanceWith := func(inst ec2types.Instance) *fakeEC2 {
		f := restoreFake()
		f.describeInstances = func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		}
		return f
	}
	noRoot := runningInstance("i-1")
	noRoot.BlockDeviceMappings = nil
	noAZ := runningInstance("i-1")
	noAZ.Placement = nil
	for name, inst := range map[string]ec2types.Instance{"no root volume": noRoot, "no availability zone": noAZ} {
		t.Run(name, func(t *testing.T) {
			err := newTestOrchestrator(t, instanceWith(inst)).RestoreSnapshot(ctx, "i-1", "s")
			if !errors.Is(err, ErrCapabilityNotSupported) {
				t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
			}
		})
	}

	t.Run("instance never stops", func(t *testing.T) {
		o := newTestOrchestrator(t, instanceWith(runningInstance("i-1")))
		o.pollTimeout = 5 * time.Millisecond
		if err := o.RestoreSnapshot(ctx, "i-1", "s"); !errors.Is(err, ErrWaitTimeout) {
			t.Fatalf("err = %v, want ErrWaitTimeout", err)
		}
	})
}

func TestPollVolumeUntil(t *testing.T) {
	inUse := &fakeEC2{describeVolumes: func(context.Context, *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
		return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{State: ec2types.VolumeStateInUse}}}, nil
	}}

	t.Run("timeout", func(t *testing.T) {
		o := newTestOrchestrator(t, inUse)
		o.pollTimeout = 5 * time.Millisecond
		if err := o.pollVolumeUntil(context.Background(), "vol-1", ec2types.VolumeStateAvailable); !errors.Is(err, ErrWaitTimeout) {
			t.Fatalf("err = %v, want ErrWaitTimeout", err)
		}
	})

	t.Run("context cancelled", func(t *testing.T) {
		o := newTestOrchestrator(t, inUse)
		o.pollInterval = time.Hour
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := o.pollVolumeUntil(ctx, "vol-1", ec2types.VolumeStateAvailable); !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})

	t.Run("reaches state on a later tick", func(t *testing.T) {
		calls := 0
		o := newTestOrchestrator(t, &fakeEC2{describeVolumes: func(context.Context, *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
			calls++
			state := ec2types.VolumeStateInUse
			if calls > 1 {
				state = ec2types.VolumeStateAvailable
			}
			return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{State: state}}}, nil
		}})
		if err := o.pollVolumeUntil(context.Background(), "vol-1", ec2types.VolumeStateAvailable); err != nil {
			t.Fatalf("pollVolumeUntil: %v", err)
		}
		if calls < 2 {
			t.Fatalf("DescribeVolumes calls = %d, want at least 2", calls)
		}
	})
}

func TestAttestVM_GeneratesNonceWhenEmpty(t *testing.T) {
	fake := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(runningInstance("i-1")), nil
		},
		getEK: func(context.Context, *ec2.GetInstanceTpmEkPubInput) (*ec2.GetInstanceTpmEkPubOutput, error) {
			return &ec2.GetInstanceTpmEkPubOutput{KeyValue: awssdk.String(base64EKPub(t))}, nil
		},
	}
	report, err := newTestOrchestrator(t, fake).AttestVM(context.Background(), "i-1", nil, nil)
	if err != nil {
		t.Fatalf("AttestVM: %v", err)
	}
	if len(report.Nonce) != attestNonceSize {
		t.Fatalf("nonce length = %d, want %d", len(report.Nonce), attestNonceSize)
	}
}

func TestAttestVM_Failures(t *testing.T) {
	ctx := context.Background()
	_, err := newTestOrchestrator(t, describeFails(errFakeAPI{})).AttestVM(ctx, "i-1", []byte("n"), nil)
	assertAPIError(t, err, "DescribeInstances")

	ekReturns := func(out *ec2.GetInstanceTpmEkPubOutput, ekErr error) *fakeEC2 {
		return &fakeEC2{
			describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
				return describeOutput(runningInstance("i-1")), nil
			},
			getEK: func(context.Context, *ec2.GetInstanceTpmEkPubInput) (*ec2.GetInstanceTpmEkPubOutput, error) {
				return out, ekErr
			},
		}
	}
	cases := []struct {
		name string
		fake *fakeEC2
	}{
		{"GetInstanceTpmEkPub error", ekReturns(nil, errFakeAPI{})},
		{"empty key", ekReturns(&ec2.GetInstanceTpmEkPubOutput{KeyValue: awssdk.String("")}, nil)},
		{"nil key", ekReturns(&ec2.GetInstanceTpmEkPubOutput{}, nil)},
		{"not base64", ekReturns(&ec2.GetInstanceTpmEkPubOutput{KeyValue: awssdk.String("!!not-base64!!")}, nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newTestOrchestrator(t, tc.fake).AttestVM(ctx, "i-1", []byte("n"), nil)
			if !errors.Is(err, ErrEndorsementKey) {
				t.Fatalf("err = %v, want ErrEndorsementKey", err)
			}
		})
	}
}
