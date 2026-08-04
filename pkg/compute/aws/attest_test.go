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
	"bytes"
	"context"
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

func TestAttestVM_Happy(t *testing.T) {
	ek := base64EKPub(t)
	inst := runningInstance("i-1")
	client := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		getEK: func(_ context.Context, in *ec2.GetInstanceTpmEkPubInput) (*ec2.GetInstanceTpmEkPubOutput, error) {
			if in.KeyFormat != ec2types.EkPubKeyFormatDer {
				t.Errorf("KeyFormat = %v, want der", in.KeyFormat)
			}
			return &ec2.GetInstanceTpmEkPubOutput{KeyValue: awssdk.String(ek)}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	report, err := o.AttestVM(context.Background(), "i-1", nil, nil)
	if err != nil {
		t.Fatalf("AttestVM: %v", err)
	}
	if len(report.AKPublicKey) == 0 {
		t.Error("expected EK public key in report")
	}
	if len(report.Nonce) == 0 {
		t.Error("expected generated nonce")
	}
	if report.VMID != "i-1" || report.VMName != "node-01" {
		t.Errorf("report identity = %+v", report)
	}
}

func TestAttestVM_EchoesNonce(t *testing.T) {
	ek := base64EKPub(t)
	inst := runningInstance("i-1")
	client := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		getEK: func(context.Context, *ec2.GetInstanceTpmEkPubInput) (*ec2.GetInstanceTpmEkPubOutput, error) {
			return &ec2.GetInstanceTpmEkPubOutput{KeyValue: awssdk.String(ek)}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	nonce := []byte("caller-supplied-nonce")
	report, err := o.AttestVM(context.Background(), "i-1", nonce, nil)
	if err != nil {
		t.Fatalf("AttestVM: %v", err)
	}
	if !bytes.Equal(report.Nonce, nonce) {
		t.Errorf("nonce = %x, want %x", report.Nonce, nonce)
	}
}

func TestAttestVM_NotRunning(t *testing.T) {
	inst := runningInstance("i-1")
	inst.State = &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return describeOutput(inst), nil
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.AttestVM(context.Background(), "i-1", nil, nil)
	if !errors.Is(err, compute.ErrVTPMNotAvailable) {
		t.Fatalf("err = %v, want ErrVTPMNotAvailable", err)
	}
}

func TestAttestVM_BadEK(t *testing.T) {
	inst := runningInstance("i-1")
	client := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		getEK: func(context.Context, *ec2.GetInstanceTpmEkPubInput) (*ec2.GetInstanceTpmEkPubOutput, error) {
			return &ec2.GetInstanceTpmEkPubOutput{KeyValue: awssdk.String("!!!not-base64!!!")}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	_, err := o.AttestVM(context.Background(), "i-1", nil, nil)
	if !errors.Is(err, ErrEndorsementKey) {
		t.Fatalf("err = %v, want ErrEndorsementKey", err)
	}
}

func TestAttestVM_EmptyInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	_, err := o.AttestVM(context.Background(), "", nil, nil)
	if !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestVerifyVMAttestation_NotSupported(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	_, err := o.VerifyVMAttestation(context.Background(), "i-1", &compute.VMAttestationEvidence{})
	if !errors.Is(err, ErrCapabilityNotSupported) {
		t.Fatalf("err = %v, want ErrCapabilityNotSupported", err)
	}
}
