//go:build floci_integration && awscompute

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
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// defaultFlociEndpoint is the endpoint-URL Floci listens on by default. It is
// used when FLOCI_EC2_ENDPOINT is unset so the test always has a concrete
// target and never has to skip.
const defaultFlociEndpoint = "http://localhost:4566"

// flociUnavailableError is a typed error reported when the Floci EC2 emulator
// cannot be reached. Per the platform testing policy the test never calls
// t.Skip: a missing emulator is a loud failure that names the expected
// container and how to start it, not a silent green.
type flociUnavailableError struct {
	// Endpoint is the endpoint-URL the orchestrator was pointed at.
	Endpoint string

	// Op is the EC2 operation that could not reach the emulator.
	Op string

	// Cause is the underlying transport error.
	Cause error
}

// Error implements the error interface.
func (e *flociUnavailableError) Error() string {
	return fmt.Sprintf(
		"floci EC2 emulator unreachable at %s during %s: expected the Floci container (floci/floci:latest, listening on :4566) — start it with `make integration-test-compute-aws` or `docker compose -f test/integration/compute-aws/docker-compose.yml up -d floci`: %v",
		e.Endpoint, e.Op, e.Cause,
	)
}

// Unwrap returns the underlying transport cause.
func (e *flociUnavailableError) Unwrap() error { return e.Cause }

// TestAWSCompute_Floci exercises the AWS orchestrator's EC2 instance lifecycle
// against a local Floci emulator (an MIT-licensed, endpoint-URL drop-in AWS
// emulator; https://floci.io). It is opt-in: build with `-tags
// 'floci_integration awscompute'` and bring up Floci first (see `make
// integration-test-compute-aws`).
//
// Floci emulates the EC2 instance lifecycle only. It does NOT emulate EBS
// snapshots, NitroTPM (TpmSupport / GetInstanceTpmEkPub), GCP Compute Engine,
// or Azure VMs. This test therefore covers ONLY the lifecycle
// (RunInstances/StartInstances/StopInstances/DescribeInstances/
// TerminateInstances); snapshot and NitroTPM attestation validation stay on
// the faked-client unit tests and the creds-gated live-cloud tests. See
// docs/compute/testing.md.
//
// The orchestrator is pointed at Floci via AWSProviderConfig.Endpoint and
// SkipNitroTPMAssertion=true (Floci's DescribeImages does not populate
// TpmSupport, so the production NitroTPM pre-launch check is bypassed for the
// emulator). Dummy static credentials are used — Floci authenticates nothing.
//
// Per the platform testing policy this test never calls t.Skip: when Floci is
// unreachable it fails with a typed flociUnavailableError naming the expected
// container.
func TestAWSCompute_Floci(t *testing.T) {
	endpoint := os.Getenv("FLOCI_EC2_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultFlociEndpoint
	}

	ami := os.Getenv("FLOCI_EC2_AMI")
	if ami == "" {
		// Floci accepts any AMI ID for RunInstances; it does not validate
		// registration or TpmSupport. A stable placeholder keeps the run
		// deterministic.
		ami = "ami-floci00000000000"
	}
	instanceType := os.Getenv("FLOCI_EC2_INSTANCE_TYPE")
	if instanceType == "" {
		instanceType = "m5.large"
	}

	cfg := &compute.OrchestratorConfig{
		Type:         compute.ComputeTypeVM,
		Provider:     compute.ProviderAWS,
		WorkDir:      t.TempDir(),
		MaxInstances: 4,
		AWS: &compute.AWSProviderConfig{
			Region:       "us-east-1",
			Endpoint:     endpoint,
			AMIID:        ami,
			InstanceType: instanceType,
			// Floci needs no real credentials; static dummy credentials
			// route the orchestrator constructor through its static
			// credential path (New sets a NewStaticCredentialsProvider when
			// AccessKeyID/SecretAccessKey are present).
			AccessKeyID:     "test",
			SecretAccessKey: "test",
			// Floci does not emulate DescribeImages TpmSupport; bypass the
			// production NitroTPM pre-launch assertion for the emulator.
			SkipNitroTPMAssertion: true,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	orch, err := New(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = orch.Close() })

	// Create — RunInstances. The first call also proves Floci is reachable;
	// a transport error here is reported as a typed flociUnavailableError.
	inst, err := orch.Create(ctx, &entities.DeviceProfile{Name: "gtp-floci-it"})
	if err != nil {
		if isTransportError(err) {
			t.Fatalf("%v", &flociUnavailableError{Endpoint: endpoint, Op: "RunInstances (Create)", Cause: err})
		}
		t.Fatalf("Create: %v", err)
	}
	if inst.ID == "" {
		t.Fatal("Create returned an instance with an empty ID")
	}
	// Terminate whatever we launched, regardless of how far the test gets.
	t.Cleanup(func() {
		if err := orch.Delete(context.Background(), inst.ID); err != nil && !errors.Is(err, compute.ErrInstanceNotFound) {
			t.Errorf("cleanup Delete(%s): %v", inst.ID, err)
		}
	})
	t.Logf("launched Floci instance %s", inst.ID)

	if inst.Metadata["provider"] != string(compute.ProviderAWS) {
		t.Errorf("instance provider metadata = %q, want %q", inst.Metadata["provider"], compute.ProviderAWS)
	}

	// The instance should converge to running.
	pollInstanceState(ctx, t, orch, inst.ID, compute.StateRunning, 3*time.Minute)

	// Get — round-trips the same instance by ID.
	got, err := orch.Get(ctx, inst.ID)
	if err != nil {
		t.Fatalf("Get(%s): %v", inst.ID, err)
	}
	if got.ID != inst.ID {
		t.Fatalf("Get returned ID %q, want %q", got.ID, inst.ID)
	}

	// List — the managed instance is discoverable via the platform tag filter.
	list, err := orch.List(ctx, nil)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsInstance(list, inst.ID) {
		t.Fatalf("List did not return launched instance %s (got %d instances)", inst.ID, len(list))
	}

	// Stop — StopInstances, converge to stopped.
	if err := orch.Stop(ctx, inst.ID); err != nil {
		t.Fatalf("Stop(%s): %v", inst.ID, err)
	}
	pollInstanceState(ctx, t, orch, inst.ID, compute.StateStopped, 3*time.Minute)

	// Start — StartInstances, converge back to running.
	if err := orch.Start(ctx, inst.ID); err != nil {
		t.Fatalf("Start(%s): %v", inst.ID, err)
	}
	pollInstanceState(ctx, t, orch, inst.ID, compute.StateRunning, 3*time.Minute)

	// Delete — TerminateInstances, assert the instance is gone.
	if err := orch.Delete(ctx, inst.ID); err != nil {
		t.Fatalf("Delete(%s): %v", inst.ID, err)
	}
	pollInstanceGone(ctx, t, orch, inst.ID, 3*time.Minute)
}

// pollInstanceState polls the instance state on a ticker (never time.Sleep)
// until it reaches want, ctx is cancelled, or the timeout elapses.
func pollInstanceState(ctx context.Context, t *testing.T, orch compute.Orchestrator, id string, want compute.InstanceState, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		state, err := orch.GetState(ctx, id)
		if err != nil {
			t.Fatalf("GetState(%s): %v", id, err)
		}
		if state == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for instance %s to reach %s: %v", id, want, ctx.Err())
		case <-deadline.C:
			t.Fatalf("instance %s did not reach %s within %s (last=%s)", id, want, timeout, state)
		case <-tick.C:
		}
	}
}

// pollInstanceGone polls until the instance is terminated: either the emulator
// stops returning it (ErrInstanceNotFound) or it reports a terminal
// shutting-down/terminated state (mapped to StateDeleting).
func pollInstanceGone(ctx context.Context, t *testing.T, orch compute.Orchestrator, id string, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()

	for {
		_, err := orch.Get(ctx, id)
		if errors.Is(err, compute.ErrInstanceNotFound) {
			return
		}
		if err == nil {
			if state, sErr := orch.GetState(ctx, id); sErr == nil && state == compute.StateDeleting {
				return
			}
		}
		select {
		case <-ctx.Done():
			t.Fatalf("context cancelled waiting for instance %s to terminate: %v", id, ctx.Err())
		case <-deadline.C:
			t.Fatalf("instance %s was not terminated within %s", id, timeout)
		case <-tick.C:
		}
	}
}

// containsInstance reports whether the list contains an instance with the id.
func containsInstance(list []*compute.Instance, id string) bool {
	for _, i := range list {
		if i != nil && i.ID == id {
			return true
		}
	}
	return false
}

// isTransportError reports whether err looks like the emulator was unreachable
// (dial/connection failure) rather than a well-formed EC2 API error. Floci
// returns structured smithy errors when it is up; a raw dial failure indicates
// the container is not running.
func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	// A reachable Floci returns a smithy.APIError (an EC2 error code); an
	// unreachable emulator surfaces a bare transport error with no API code.
	if isNotFound(err) {
		return false
	}
	msg := err.Error()
	for _, needle := range []string{
		"connection refused",
		"no such host",
		"dial tcp",
		"connect: ",
		"i/o timeout",
		"EOF",
		"context deadline exceeded",
	} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}
