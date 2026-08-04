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
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

func TestAWSOrchestrator_ImplementsContracts(t *testing.T) {
	var _ compute.Orchestrator = (*AWSOrchestrator)(nil)
	var _ compute.VMSnapshotter = (*AWSOrchestrator)(nil)
	var _ compute.VMAttester = (*AWSOrchestrator)(nil)
}

func TestProviderRegistered_UnderTag(t *testing.T) {
	if !compute.IsProviderCompiled(compute.ProviderAWS) {
		t.Fatal("ProviderAWS must be registered when the awscompute tag is built")
	}
}

func TestCreate_HappyPath(t *testing.T) {
	client := &fakeEC2{
		describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
			return nitroTPMImages(), nil
		},
		runInstances: func(_ context.Context, in *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) {
			if in.TagSpecifications == nil {
				t.Error("expected tag specifications on launch")
			}
			return &ec2.RunInstancesOutput{Instances: []ec2types.Instance{runningInstance("i-123")}}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	inst, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-01"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if inst.ID != "i-123" {
		t.Errorf("ID = %q, want i-123", inst.ID)
	}
	if inst.Type != compute.ComputeTypeVM {
		t.Errorf("Type = %q, want vm", inst.Type)
	}
	if inst.Metadata["provider"] != string(compute.ProviderAWS) {
		t.Errorf("provider metadata = %q", inst.Metadata["provider"])
	}
}

func TestCreate_NitroTPMUnsupported(t *testing.T) {
	client := &fakeEC2{
		describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
			return &ec2.DescribeImagesOutput{Images: []ec2types.Image{{
				ImageId:    awssdk.String("ami-nitrotpm"),
				TpmSupport: "", // not v2.0
			}}}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	_, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-01"})
	if !errors.Is(err, ErrNitroTPMUnsupported) {
		t.Fatalf("err = %v, want ErrNitroTPMUnsupported", err)
	}
}

func TestCreate_NilProfile(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	_, err := o.Create(context.Background(), nil)
	if !errors.Is(err, compute.ErrInvalidProfile) {
		t.Fatalf("err = %v, want ErrInvalidProfile", err)
	}
}

func TestCreate_RunInstancesError(t *testing.T) {
	client := &fakeEC2{
		describeImages: func(context.Context, *ec2.DescribeImagesInput) (*ec2.DescribeImagesOutput, error) {
			return nitroTPMImages(), nil
		},
		runInstances: func(context.Context, *ec2.RunInstancesInput) (*ec2.RunInstancesOutput, error) {
			return nil, errors.New("throttled")
		},
	}
	o := newTestOrchestrator(t, client)

	_, err := o.Create(context.Background(), &entities.DeviceProfile{Name: "node-01"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "RunInstances" {
		t.Fatalf("err = %v, want APIError{RunInstances}", err)
	}
}

func TestStartStopDelete(t *testing.T) {
	var started, stopped, terminated bool
	client := &fakeEC2{
		startInstances: func(context.Context, *ec2.StartInstancesInput) (*ec2.StartInstancesOutput, error) {
			started = true
			return &ec2.StartInstancesOutput{}, nil
		},
		stopInstances: func(context.Context, *ec2.StopInstancesInput) (*ec2.StopInstancesOutput, error) {
			stopped = true
			return &ec2.StopInstancesOutput{}, nil
		},
		terminateInstances: func(context.Context, *ec2.TerminateInstancesInput) (*ec2.TerminateInstancesOutput, error) {
			terminated = true
			return &ec2.TerminateInstancesOutput{}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	ctx := context.Background()

	if err := o.Start(ctx, "i-1"); err != nil || !started {
		t.Fatalf("Start: %v started=%v", err, started)
	}
	if err := o.Stop(ctx, "i-1"); err != nil || !stopped {
		t.Fatalf("Stop: %v stopped=%v", err, stopped)
	}
	if err := o.Delete(ctx, "i-1"); err != nil || !terminated {
		t.Fatalf("Delete: %v terminated=%v", err, terminated)
	}
}

func TestLifecycle_EmptyInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	ctx := context.Background()
	for name, fn := range map[string]func() error{
		"Start":  func() error { return o.Start(ctx, "") },
		"Stop":   func() error { return o.Stop(ctx, "") },
		"Delete": func() error { return o.Delete(ctx, "") },
		"Wait":   func() error { return o.Wait(ctx, "") },
	} {
		if err := fn(); !errors.Is(err, compute.ErrInvalidInstanceID) {
			t.Errorf("%s: err = %v, want ErrInvalidInstanceID", name, err)
		}
	}
}

func TestStart_APIError(t *testing.T) {
	client := &fakeEC2{startInstances: func(context.Context, *ec2.StartInstancesInput) (*ec2.StartInstancesOutput, error) {
		return nil, errors.New("boom")
	}}
	o := newTestOrchestrator(t, client)
	err := o.Start(context.Background(), "i-1")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Op != "StartInstances" {
		t.Fatalf("err = %v, want APIError{StartInstances}", err)
	}
}

func TestGetState_Mapping(t *testing.T) {
	cases := []struct {
		ec2State ec2types.InstanceStateName
		want     compute.InstanceState
	}{
		{ec2types.InstanceStateNamePending, compute.StateCreating},
		{ec2types.InstanceStateNameRunning, compute.StateRunning},
		{ec2types.InstanceStateNameStopping, compute.StateStopping},
		{ec2types.InstanceStateNameStopped, compute.StateStopped},
		{ec2types.InstanceStateNameTerminated, compute.StateDeleting},
	}
	for _, tc := range cases {
		inst := runningInstance("i-1")
		inst.State = &ec2types.InstanceState{Name: tc.ec2State}
		client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		}}
		o := newTestOrchestrator(t, client)
		got, err := o.GetState(context.Background(), "i-1")
		if err != nil {
			t.Fatalf("GetState(%s): %v", tc.ec2State, err)
		}
		if got != tc.want {
			t.Errorf("state %s -> %q, want %q", tc.ec2State, got, tc.want)
		}
	}
}

func TestGet_NotFound(t *testing.T) {
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return &ec2.DescribeInstancesOutput{}, nil
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.Get(context.Background(), "i-missing")
	if !errors.Is(err, compute.ErrInstanceNotFound) {
		t.Fatalf("err = %v, want ErrInstanceNotFound", err)
	}
}

func TestGet_NotFoundFromAPICode(t *testing.T) {
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return nil, notFoundErr{}
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.Get(context.Background(), "i-missing")
	if !errors.Is(err, compute.ErrInstanceNotFound) {
		t.Fatalf("err = %v, want ErrInstanceNotFound", err)
	}
}

func TestList_FiltersByName(t *testing.T) {
	a := runningInstance("i-a")
	a.Tags = []ec2types.Tag{{Key: awssdk.String(nameTagKey), Value: awssdk.String("keep")}}
	b := runningInstance("i-b")
	b.Tags = []ec2types.Tag{{Key: awssdk.String(nameTagKey), Value: awssdk.String("drop")}}
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return describeOutput(a, b), nil
	}}
	o := newTestOrchestrator(t, client)

	list, err := o.List(context.Background(), &compute.InstanceFilter{Name: "keep"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].ID != "i-a" {
		t.Fatalf("list = %+v, want single i-a", list)
	}
}

func TestList_APIError(t *testing.T) {
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return nil, errors.New("boom")
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.List(context.Background(), nil)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("err = %v, want APIError", err)
	}
}

func TestWait_ReachesTerminal(t *testing.T) {
	inst := runningInstance("i-1")
	inst.State = &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return describeOutput(inst), nil
	}}
	o := newTestOrchestrator(t, client)
	if err := o.Wait(context.Background(), "i-1"); err != nil {
		t.Fatalf("Wait: %v", err)
	}
}

func TestWait_ContextCancelled(t *testing.T) {
	inst := runningInstance("i-1") // never terminal
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return describeOutput(inst), nil
	}}
	o := newTestOrchestrator(t, client)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := o.Wait(ctx, "i-1"); err == nil {
		t.Fatal("Wait: expected error on cancelled context")
	}
}

func TestAttachNetwork_HappyAndError(t *testing.T) {
	inst := runningInstance("i-1")
	var attached bool
	client := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		attachNIC: func(_ context.Context, in *ec2.AttachNetworkInterfaceInput) (*ec2.AttachNetworkInterfaceOutput, error) {
			if awssdk.ToString(in.NetworkInterfaceId) != "eni-1" {
				t.Errorf("eni = %q", awssdk.ToString(in.NetworkInterfaceId))
			}
			attached = true
			return &ec2.AttachNetworkInterfaceOutput{}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	if err := o.AttachNetwork(context.Background(), "i-1", "eni-1"); err != nil || !attached {
		t.Fatalf("AttachNetwork: %v attached=%v", err, attached)
	}

	if err := o.AttachNetwork(context.Background(), "i-1", ""); !errors.Is(err, compute.ErrNetworkAttachmentFailed) {
		t.Fatalf("empty port err = %v, want ErrNetworkAttachmentFailed", err)
	}
}

func TestDetachNetwork_NotAttached(t *testing.T) {
	inst := runningInstance("i-1") // no network interfaces
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return describeOutput(inst), nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.DetachNetwork(context.Background(), "i-1", "eni-x")
	if !errors.Is(err, compute.ErrNetworkDetachmentFailed) {
		t.Fatalf("err = %v, want ErrNetworkDetachmentFailed", err)
	}
}

func TestDetachNetwork_Happy(t *testing.T) {
	inst := runningInstance("i-1")
	inst.NetworkInterfaces = []ec2types.InstanceNetworkInterface{{
		NetworkInterfaceId: awssdk.String("eni-1"),
		Attachment:         &ec2types.InstanceNetworkInterfaceAttachment{AttachmentId: awssdk.String("eni-attach-1")},
	}}
	var detached bool
	client := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		detachNIC: func(_ context.Context, in *ec2.DetachNetworkInterfaceInput) (*ec2.DetachNetworkInterfaceOutput, error) {
			if awssdk.ToString(in.AttachmentId) != "eni-attach-1" {
				t.Errorf("attachment = %q", awssdk.ToString(in.AttachmentId))
			}
			detached = true
			return &ec2.DetachNetworkInterfaceOutput{}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	if err := o.DetachNetwork(context.Background(), "i-1", "eni-1"); err != nil || !detached {
		t.Fatalf("DetachNetwork: %v detached=%v", err, detached)
	}
}

func TestActivateInstance_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	err := o.ActivateInstance(context.Background(), "i-1", &policy.PortPolicy{})
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}

func TestClose(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	if err := o.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNew_ConfigValidation(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		cfg  *compute.OrchestratorConfig
	}{
		{"nil config", nil},
		{"nil aws block", &compute.OrchestratorConfig{Provider: compute.ProviderAWS}},
		{"missing region", &compute.OrchestratorConfig{Provider: compute.ProviderAWS, AWS: &compute.AWSProviderConfig{AMIID: "ami-1", InstanceType: "m5.large"}}},
		{"missing ami", &compute.OrchestratorConfig{Provider: compute.ProviderAWS, AWS: &compute.AWSProviderConfig{Region: "us-east-1", InstanceType: "m5.large"}}},
		{"missing instance type", &compute.OrchestratorConfig{Provider: compute.ProviderAWS, AWS: &compute.AWSProviderConfig{Region: "us-east-1", AMIID: "ami-1"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(ctx, tc.cfg, nil)
			var cfgErr *ConfigError
			if !errors.As(err, &cfgErr) {
				t.Fatalf("err = %v, want ConfigError", err)
			}
		})
	}
}
