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

// Package aws implements the platform compute Orchestrator over AWS EC2,
// launching and managing NitroTPM 2.0-enabled instances. It is compiled only
// when the awscompute build tag is present; without the tag a stub keeps the
// package buildable and the provider factory fails closed with a typed
// ErrComputeProviderNotCompiled.
//
// The orchestrator provides full lifecycle parity with the local QEMU
// orchestrator (create/start/stop/delete/list/get/wait/state), EBS-backed VM
// snapshots (VMSnapshotter), and NitroTPM endorsement-key attestation
// (VMAttester). Capabilities that have no honest EC2 equivalent — 802.1X OVS
// port activation and control-plane PCR-quote verification — return the typed
// ErrCapabilityNotSupported and are documented in docs/compute/cloud-providers.md.
//
// All EC2 access flows through the narrow ec2API interface so unit tests fake
// the cloud at the seam; there are no live AWS calls in unit tests.
package aws

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// managedTagKey marks instances, volumes, and snapshots created by the
// platform so List/ListSnapshots can filter to platform-managed resources.
const (
	managedTagKey   = "trusted-platform:managed"
	managedTagValue = "true"
	vmIDTagKey      = "trusted-platform:vm-id"
	nameTagKey      = "Name"
)

// defaultPollInterval and defaultPollTimeout bound the state-transition
// polling used by Wait and RestoreSnapshot. They are overridable on the
// orchestrator for tests.
const (
	defaultPollInterval = 5 * time.Second
	defaultPollTimeout  = 10 * time.Minute
)

// ec2API is the narrow slice of the EC2 client used by the orchestrator. The
// concrete *ec2.Client satisfies it; unit tests provide a fake.
type ec2API interface {
	RunInstances(ctx context.Context, in *ec2.RunInstancesInput, optFns ...func(*ec2.Options)) (*ec2.RunInstancesOutput, error)
	StartInstances(ctx context.Context, in *ec2.StartInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StartInstancesOutput, error)
	StopInstances(ctx context.Context, in *ec2.StopInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error)
	TerminateInstances(ctx context.Context, in *ec2.TerminateInstancesInput, optFns ...func(*ec2.Options)) (*ec2.TerminateInstancesOutput, error)
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeImages(ctx context.Context, in *ec2.DescribeImagesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeImagesOutput, error)
	AttachNetworkInterface(ctx context.Context, in *ec2.AttachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.AttachNetworkInterfaceOutput, error)
	DetachNetworkInterface(ctx context.Context, in *ec2.DetachNetworkInterfaceInput, optFns ...func(*ec2.Options)) (*ec2.DetachNetworkInterfaceOutput, error)
	GetInstanceTpmEkPub(ctx context.Context, in *ec2.GetInstanceTpmEkPubInput, optFns ...func(*ec2.Options)) (*ec2.GetInstanceTpmEkPubOutput, error)
	CreateSnapshot(ctx context.Context, in *ec2.CreateSnapshotInput, optFns ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error)
	DeleteSnapshot(ctx context.Context, in *ec2.DeleteSnapshotInput, optFns ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
	DescribeSnapshots(ctx context.Context, in *ec2.DescribeSnapshotsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
	CreateVolume(ctx context.Context, in *ec2.CreateVolumeInput, optFns ...func(*ec2.Options)) (*ec2.CreateVolumeOutput, error)
	DeleteVolume(ctx context.Context, in *ec2.DeleteVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DeleteVolumeOutput, error)
	AttachVolume(ctx context.Context, in *ec2.AttachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.AttachVolumeOutput, error)
	DetachVolume(ctx context.Context, in *ec2.DetachVolumeInput, optFns ...func(*ec2.Options)) (*ec2.DetachVolumeOutput, error)
	DescribeVolumes(ctx context.Context, in *ec2.DescribeVolumesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeVolumesOutput, error)
}

// Compile-time proof the orchestrator satisfies the compute contracts.
var (
	_ compute.Orchestrator  = (*AWSOrchestrator)(nil)
	_ compute.VMSnapshotter = (*AWSOrchestrator)(nil)
	_ compute.VMAttester    = (*AWSOrchestrator)(nil)
)

// AWSOrchestrator launches and manages NitroTPM-enabled EC2 instances.
type AWSOrchestrator struct {
	config *compute.OrchestratorConfig
	aws    *compute.AWSProviderConfig
	logger *logging.Logger
	client ec2API

	// verifier validates NitroTPM endorsement-key material during
	// attestation. Reuses the platform VM attestation verifier.
	verifier vm.VMVerifier

	// pollInterval and pollTimeout bound state-transition polling. Tests
	// shrink them so waits complete instantly against the fake API.
	pollInterval time.Duration
	pollTimeout  time.Duration
}

// New constructs an AWSOrchestrator with a live EC2 client built from the
// provider configuration. It is the factory registered with the compute
// provider registry under ProviderAWS.
func New(ctx context.Context, cfg *compute.OrchestratorConfig, deps *compute.Deps) (compute.Orchestrator, error) {
	if cfg == nil {
		return nil, &ConfigError{Msg: "orchestrator config is required"}
	}
	if cfg.AWS == nil {
		return nil, &ConfigError{Msg: "aws provider config is required (set compute.aws)"}
	}
	if err := validateAWSConfig(cfg.AWS); err != nil {
		return nil, err
	}

	logger := logging.DefaultLogger()
	if deps != nil && deps.Logger != nil {
		logger = deps.Logger
	}

	var loadOpts []func(*awsconfig.LoadOptions) error
	loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.AWS.Region))
	if cfg.AWS.AccessKeyID != "" && cfg.AWS.SecretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.AWS.AccessKeyID,
				cfg.AWS.SecretAccessKey,
				cfg.AWS.SessionToken,
			),
		))
	}

	loaded, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrEndorsementKey, Cause: err}
	}

	var clientOpts []func(*ec2.Options)
	if cfg.AWS.Endpoint != "" {
		endpoint := cfg.AWS.Endpoint
		clientOpts = append(clientOpts, func(o *ec2.Options) {
			o.BaseEndpoint = awssdk.String(endpoint)
		})
	}

	client := ec2.NewFromConfig(loaded, clientOpts...)
	return newOrchestrator(cfg, logger, client), nil
}

// newOrchestrator wires an orchestrator around a supplied ec2API. It is the
// seam unit tests use to inject a fake client.
func newOrchestrator(cfg *compute.OrchestratorConfig, logger *logging.Logger, client ec2API) *AWSOrchestrator {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	return &AWSOrchestrator{
		config:       cfg,
		aws:          cfg.AWS,
		logger:       logger,
		client:       client,
		verifier:     vm.NewVMVerifier(vm.WithVerifierLogger(logger.Slog())),
		pollInterval: defaultPollInterval,
		pollTimeout:  defaultPollTimeout,
	}
}

// validateAWSConfig enforces the minimum fields required to launch a
// NitroTPM instance.
func validateAWSConfig(c *compute.AWSProviderConfig) error {
	if c.Region == "" {
		return &ConfigError{Msg: "region is required"}
	}
	if c.AMIID == "" {
		return &ConfigError{Msg: "ami_id is required"}
	}
	if c.InstanceType == "" {
		return &ConfigError{Msg: "instance_type is required"}
	}
	return nil
}

// Create launches an instance from the device profile. Unless the AWS
// provider config sets SkipNitroTPMAssertion, it first verifies the
// configured AMI is registered with TpmSupport=v2.0 so the guest is
// guaranteed a NitroTPM 2.0 device, then runs a single instance on the
// configured instance type. SkipNitroTPMAssertion bypasses that pre-launch
// check for non-attesting deployments and local AWS emulators (e.g. Floci)
// whose DescribeImages does not populate TpmSupport; see AWSProviderConfig.
func (o *AWSOrchestrator) Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error) {
	if profile == nil {
		return nil, compute.ErrInvalidProfile
	}

	if !o.aws.SkipNitroTPMAssertion {
		if err := o.assertNitroTPM(ctx); err != nil {
			return nil, err
		}
	}

	name := profile.Name
	runInput := &ec2.RunInstancesInput{
		ImageId:      awssdk.String(o.aws.AMIID),
		InstanceType: ec2types.InstanceType(o.aws.InstanceType),
		MinCount:     awssdk.Int32(1),
		MaxCount:     awssdk.Int32(1),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeInstance,
			Tags:         o.resourceTags(name, ""),
		}},
	}
	if o.aws.SubnetID != "" {
		runInput.SubnetId = awssdk.String(o.aws.SubnetID)
	}
	if len(o.aws.SecurityGroupIDs) > 0 {
		runInput.SecurityGroupIds = o.aws.SecurityGroupIDs
	}
	if o.aws.KeyName != "" {
		runInput.KeyName = awssdk.String(o.aws.KeyName)
	}
	if o.aws.IAMInstanceProfile != "" {
		runInput.IamInstanceProfile = &ec2types.IamInstanceProfileSpecification{
			Name: awssdk.String(o.aws.IAMInstanceProfile),
		}
	}
	if o.aws.RootVolumeSizeGiB > 0 {
		runInput.BlockDeviceMappings = []ec2types.BlockDeviceMapping{{
			DeviceName: awssdk.String("/dev/xvda"),
			Ebs: &ec2types.EbsBlockDevice{
				VolumeSize:          awssdk.Int32(o.aws.RootVolumeSizeGiB),
				DeleteOnTermination: awssdk.Bool(true),
			},
		}}
	}

	out, err := o.client.RunInstances(ctx, runInput)
	if err != nil {
		return nil, &APIError{Op: "RunInstances", Err: err}
	}
	if len(out.Instances) == 0 {
		return nil, &APIError{Op: "RunInstances", Err: ErrWaitTimeout}
	}

	inst := out.Instances[0]
	// Tag the instance with its own ID for snapshot/list correlation.
	instance := o.toInstance(&inst, name)
	o.logger.Infof("Launched NitroTPM instance %s (type=%s, ami=%s)", instance.ID, o.aws.InstanceType, o.aws.AMIID)
	return instance, nil
}

// assertNitroTPM fails closed unless the configured AMI is registered with
// TpmSupport=v2.0.
func (o *AWSOrchestrator) assertNitroTPM(ctx context.Context) error {
	out, err := o.client.DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{o.aws.AMIID},
	})
	if err != nil {
		return &APIError{Op: "DescribeImages", Err: err}
	}
	if len(out.Images) == 0 {
		return &SentinelCauseError{Sentinel: ErrNitroTPMUnsupported, Cause: &compute.MessageError{Msg: "AMI " + o.aws.AMIID + " not found"}}
	}
	if out.Images[0].TpmSupport != ec2types.TpmSupportValuesV20 {
		return &SentinelCauseError{Sentinel: ErrNitroTPMUnsupported, Cause: &compute.MessageError{Msg: "AMI " + o.aws.AMIID + " TpmSupport=" + string(out.Images[0].TpmSupport)}}
	}
	return nil
}

// Start starts a stopped instance.
func (o *AWSOrchestrator) Start(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	_, err := o.client.StartInstances(ctx, &ec2.StartInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return &APIError{Op: "StartInstances", Err: err}
	}
	o.logger.Infof("Started instance %s", instanceID)
	return nil
}

// Stop stops a running instance.
func (o *AWSOrchestrator) Stop(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	_, err := o.client.StopInstances(ctx, &ec2.StopInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return &APIError{Op: "StopInstances", Err: err}
	}
	o.logger.Infof("Stopped instance %s", instanceID)
	return nil
}

// Delete terminates an instance. EC2 releases the instance's resources on
// termination.
func (o *AWSOrchestrator) Delete(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	_, err := o.client.TerminateInstances(ctx, &ec2.TerminateInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		return &APIError{Op: "TerminateInstances", Err: err}
	}
	o.logger.Infof("Terminated instance %s", instanceID)
	return nil
}

// List returns platform-managed instances, applying the supplied filter
// client-side after fetching by the managed tag.
func (o *AWSOrchestrator) List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error) {
	out, err := o.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		Filters: []ec2types.Filter{{
			Name:   awssdk.String("tag:" + managedTagKey),
			Values: []string{managedTagValue},
		}},
	})
	if err != nil {
		return nil, &APIError{Op: "DescribeInstances", Err: err}
	}

	var instances []*compute.Instance
	for i := range out.Reservations {
		for j := range out.Reservations[i].Instances {
			ec2Inst := out.Reservations[i].Instances[j]
			instance := o.toInstance(&ec2Inst, tagValue(ec2Inst.Tags, nameTagKey))
			if filter == nil || filter.Matches(instance) {
				instances = append(instances, instance)
			}
		}
	}
	return instances, nil
}

// Get retrieves a single instance by ID.
func (o *AWSOrchestrator) Get(ctx context.Context, instanceID string) (*compute.Instance, error) {
	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	return o.toInstance(ec2Inst, tagValue(ec2Inst.Tags, nameTagKey)), nil
}

// GetState returns the current lifecycle state of an instance.
func (o *AWSOrchestrator) GetState(ctx context.Context, instanceID string) (compute.InstanceState, error) {
	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return compute.StateUnknown, err
	}
	return mapInstanceState(ec2Inst), nil
}

// Wait blocks until the instance reaches a terminal lifecycle state (stopped
// or terminated), mirroring the QEMU orchestrator's Wait which blocks until
// the VM exits.
func (o *AWSOrchestrator) Wait(ctx context.Context, instanceID string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	return o.pollInstanceUntil(ctx, instanceID, func(name ec2types.InstanceStateName) bool {
		return name == ec2types.InstanceStateNameStopped || name == ec2types.InstanceStateNameTerminated
	})
}

// AttachNetwork attaches an existing Elastic Network Interface (portName is
// the ENI ID) to the instance at the next available device index. This is the
// EC2 equivalent of attaching an OVS port.
func (o *AWSOrchestrator) AttachNetwork(ctx context.Context, instanceID, portName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if portName == "" {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkAttachmentFailed, Cause: &compute.MessageError{Msg: "portName (ENI ID) is required"}}
	}

	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	deviceIndex := int32(len(ec2Inst.NetworkInterfaces))

	_, err = o.client.AttachNetworkInterface(ctx, &ec2.AttachNetworkInterfaceInput{
		InstanceId:         awssdk.String(instanceID),
		NetworkInterfaceId: awssdk.String(portName),
		DeviceIndex:        awssdk.Int32(deviceIndex),
	})
	if err != nil {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkAttachmentFailed, Cause: &APIError{Op: "AttachNetworkInterface", Err: err}}
	}
	o.logger.Infof("Attached ENI %s to instance %s at index %d", portName, instanceID, deviceIndex)
	return nil
}

// DetachNetwork detaches the ENI (portName is the ENI ID) from the instance.
func (o *AWSOrchestrator) DetachNetwork(ctx context.Context, instanceID, portName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if portName == "" {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkDetachmentFailed, Cause: &compute.MessageError{Msg: "portName (ENI ID) is required"}}
	}

	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return err
	}

	var attachmentID string
	for _, ni := range ec2Inst.NetworkInterfaces {
		if awssdk.ToString(ni.NetworkInterfaceId) == portName && ni.Attachment != nil {
			attachmentID = awssdk.ToString(ni.Attachment.AttachmentId)
			break
		}
	}
	if attachmentID == "" {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkDetachmentFailed, Cause: &compute.MessageError{Msg: "ENI " + portName + " not attached to instance " + instanceID}}
	}

	_, err = o.client.DetachNetworkInterface(ctx, &ec2.DetachNetworkInterfaceInput{
		AttachmentId: awssdk.String(attachmentID),
	})
	if err != nil {
		return &compute.SentinelCauseError{Sentinel: compute.ErrNetworkDetachmentFailed, Cause: &APIError{Op: "DetachNetworkInterface", Err: err}}
	}
	o.logger.Infof("Detached ENI %s from instance %s", portName, instanceID)
	return nil
}

// ActivateInstance has no honest EC2 equivalent: it transitions an OVS port
// from an enrolled (provisioning) to an authorized (production) 802.1X state,
// a construct that does not exist in EC2 networking. The AWS analogue is
// swapping security groups, but the OVS PortPolicy carries no security-group
// mapping, so the operation is honestly rejected with a typed error rather
// than silently succeeding. See docs/compute/cloud-providers.md.
func (o *AWSOrchestrator) ActivateInstance(ctx context.Context, instanceID string, portPolicy *policy.PortPolicy) error {
	return &SentinelCauseError{
		Sentinel: ErrCapabilityNotSupported,
		Cause:    &compute.MessageError{Msg: "ActivateInstance (802.1X OVS port authorization) has no EC2 equivalent; manage instance access via security groups"},
	}
}

// Close releases orchestrator resources. The EC2 client requires no explicit
// close.
func (o *AWSOrchestrator) Close() error {
	return nil
}

// describeInstance fetches a single EC2 instance by ID, mapping an empty
// result to compute.ErrInstanceNotFound so callers can use errors.Is
// uniformly across orchestrators.
func (o *AWSOrchestrator) describeInstance(ctx context.Context, instanceID string) (*ec2types.Instance, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	out, err := o.client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceID},
	})
	if err != nil {
		if isNotFound(err) {
			return nil, compute.ErrInstanceNotFound
		}
		return nil, &APIError{Op: "DescribeInstances", Err: err}
	}
	for i := range out.Reservations {
		if len(out.Reservations[i].Instances) > 0 {
			return &out.Reservations[i].Instances[0], nil
		}
	}
	return nil, compute.ErrInstanceNotFound
}

// pollInstanceUntil polls the instance state on a ticker (never time.Sleep)
// until pred is satisfied, ctx is cancelled, or the poll timeout elapses.
func (o *AWSOrchestrator) pollInstanceUntil(ctx context.Context, instanceID string, pred func(ec2types.InstanceStateName) bool) error {
	deadline := time.NewTimer(o.pollTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	check := func() (bool, error) {
		ec2Inst, err := o.describeInstance(ctx, instanceID)
		if err != nil {
			return false, err
		}
		if ec2Inst.State != nil && pred(ec2Inst.State.Name) {
			return true, nil
		}
		return false, nil
	}

	// Evaluate immediately so an already-terminal instance returns without
	// waiting a full tick.
	if done, err := check(); err != nil || done {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrWaitTimeout
		case <-ticker.C:
			if done, err := check(); err != nil || done {
				return err
			}
		}
	}
}

// resourceTags returns the standard tag set applied to platform-managed
// resources. vmID is included when non-empty.
func (o *AWSOrchestrator) resourceTags(name, vmID string) []ec2types.Tag {
	tags := []ec2types.Tag{
		{Key: awssdk.String(managedTagKey), Value: awssdk.String(managedTagValue)},
	}
	if name != "" {
		tags = append(tags, ec2types.Tag{Key: awssdk.String(nameTagKey), Value: awssdk.String(name)})
	}
	if vmID != "" {
		tags = append(tags, ec2types.Tag{Key: awssdk.String(vmIDTagKey), Value: awssdk.String(vmID)})
	}
	return tags
}

// toInstance maps an EC2 instance to the platform compute.Instance model.
func (o *AWSOrchestrator) toInstance(ec2Inst *ec2types.Instance, name string) *compute.Instance {
	id := awssdk.ToString(ec2Inst.InstanceId)
	instance := &compute.Instance{
		ID:    id,
		Name:  name,
		Type:  compute.ComputeTypeVM,
		State: mapInstanceState(ec2Inst),
		Metadata: map[string]string{
			"provider":      string(compute.ProviderAWS),
			"instance_type": string(ec2Inst.InstanceType),
			"ami_id":        awssdk.ToString(ec2Inst.ImageId),
		},
	}
	if ec2Inst.Placement != nil {
		instance.Metadata["availability_zone"] = awssdk.ToString(ec2Inst.Placement.AvailabilityZone)
	}
	if ec2Inst.PrivateIpAddress != nil {
		instance.Metadata["private_ip"] = awssdk.ToString(ec2Inst.PrivateIpAddress)
	}
	if ec2Inst.PublicIpAddress != nil {
		instance.Metadata["public_ip"] = awssdk.ToString(ec2Inst.PublicIpAddress)
	}
	return instance
}

// mapInstanceState translates an EC2 instance state to the platform lifecycle
// state.
func mapInstanceState(ec2Inst *ec2types.Instance) compute.InstanceState {
	if ec2Inst == nil || ec2Inst.State == nil {
		return compute.StateUnknown
	}
	switch ec2Inst.State.Name {
	case ec2types.InstanceStateNamePending:
		return compute.StateCreating
	case ec2types.InstanceStateNameRunning:
		return compute.StateRunning
	case ec2types.InstanceStateNameStopping:
		return compute.StateStopping
	case ec2types.InstanceStateNameStopped:
		return compute.StateStopped
	case ec2types.InstanceStateNameShuttingDown, ec2types.InstanceStateNameTerminated:
		return compute.StateDeleting
	default:
		return compute.StateUnknown
	}
}

// tagValue returns the value of the named tag, or "" when absent.
func tagValue(tags []ec2types.Tag, key string) string {
	for _, t := range tags {
		if awssdk.ToString(t.Key) == key {
			return awssdk.ToString(t.Value)
		}
	}
	return ""
}
