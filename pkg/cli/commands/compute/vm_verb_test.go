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

package compute

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
)

// vmVerbCase is one of the reboot, suspend and resume commands driven
// through a MockComputeClient that answers with reply or err.
type vmVerbCase struct {
	name string
	verb vmVerb
	// mock returns a client answering the verb's RPC and the id it was sent.
	mock func(reply *platformv1.Status, err error) (*MockComputeClient, *string)
	// typed reports whether err is the SDK client's typed error for the verb.
	typed func(err error) bool
}

func vmVerbCases(rebootOpts *rebootOptions, rebootForce *bool) []vmVerbCase {
	return []vmVerbCase{
		{
			name: "reboot",
			verb: rebootVerb(rebootOpts),
			mock: func(reply *platformv1.Status, err error) (*MockComputeClient, *string) {
				sent := new(string)
				return &MockComputeClient{RebootVMFunc: func(_ context.Context, in *platformv1.RebootVMRequest, _ ...grpc.CallOption) (*platformv1.RebootVMResponse, error) {
					*sent, *rebootForce = in.GetId(), in.GetForce()
					if err != nil {
						return nil, err
					}
					return &platformv1.RebootVMResponse{Status: reply}, nil
				}}, sent
			},
			typed: func(err error) bool { var e *computesvc.ErrRebootVMFailed; return errors.As(err, &e) },
		},
		{
			name: "suspend",
			verb: suspendVerb,
			mock: func(reply *platformv1.Status, err error) (*MockComputeClient, *string) {
				sent := new(string)
				return &MockComputeClient{SuspendVMFunc: func(_ context.Context, in *platformv1.SuspendVMRequest, _ ...grpc.CallOption) (*platformv1.SuspendVMResponse, error) {
					*sent = in.GetId()
					if err != nil {
						return nil, err
					}
					return &platformv1.SuspendVMResponse{Status: reply}, nil
				}}, sent
			},
			typed: func(err error) bool { var e *computesvc.ErrSuspendVMFailed; return errors.As(err, &e) },
		},
		{
			name: "resume",
			verb: resumeVerb,
			mock: func(reply *platformv1.Status, err error) (*MockComputeClient, *string) {
				sent := new(string)
				return &MockComputeClient{ResumeVMFunc: func(_ context.Context, in *platformv1.ResumeVMRequest, _ ...grpc.CallOption) (*platformv1.ResumeVMResponse, error) {
					*sent = in.GetId()
					if err != nil {
						return nil, err
					}
					return &platformv1.ResumeVMResponse{Status: reply}, nil
				}}, sent
			},
			typed: func(err error) bool { var e *computesvc.ErrResumeVMFailed; return errors.As(err, &e) },
		},
	}
}

// runCase runs the verb against mock and returns what it printed.
func runCase(t *testing.T, verb vmVerb, mock *MockComputeClient, format cli.OutputFormat) (string, error) {
	t.Helper()
	var out bytes.Buffer
	printer := cli.NewPrinterWithWriter(format, true, &out)
	err := verb.run(context.Background(), computesvc.NewClientFromGRPC(mock), printer, format, "vm-1")
	return out.String(), err
}

func TestVMVerb_Success(t *testing.T) {
	var force bool
	want := map[string]string{
		"reboot":  "[SUCCESS] VM rebooted successfully: vm-1\n",
		"suspend": "[SUCCESS] VM suspended successfully: vm-1\n",
		"resume":  "[SUCCESS] VM resumed successfully: vm-1\n",
	}
	for _, tc := range vmVerbCases(&rebootOptions{force: true}, &force) {
		t.Run(tc.name, func(t *testing.T) {
			mock, sent := tc.mock(&platformv1.Status{Success: true}, nil)
			out, err := runCase(t, tc.verb, mock, cli.OutputFormatTable)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if *sent != "vm-1" {
				t.Errorf("sent id = %q, want vm-1", *sent)
			}
			if out != want[tc.name] {
				t.Errorf("output = %q, want %q", out, want[tc.name])
			}
		})
	}
	if !force {
		t.Error("reboot --force did not reach the request")
	}
}

func TestVMVerb_JSONPrintsTheStatus(t *testing.T) {
	var force bool
	for _, tc := range vmVerbCases(&rebootOptions{}, &force) {
		t.Run(tc.name, func(t *testing.T) {
			mock, _ := tc.mock(&platformv1.Status{Success: true, Message: "done"}, nil)
			out, err := runCase(t, tc.verb, mock, cli.OutputFormatJSON)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if want := "{\n  \"success\": true,\n  \"message\": \"done\"\n}\n"; out != want {
				t.Errorf("output = %q, want %q", out, want)
			}
		})
	}
}

// A status the server marks unsuccessful is printed as an error, not a
// success.
func TestVMVerb_UnsuccessfulStatusPrintsTheMessage(t *testing.T) {
	var force bool
	for _, tc := range vmVerbCases(&rebootOptions{}, &force) {
		t.Run(tc.name, func(t *testing.T) {
			mock, _ := tc.mock(&platformv1.Status{Success: false, Message: "busy"}, nil)
			out, err := runCase(t, tc.verb, mock, cli.OutputFormatTable)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if want := "[ERROR] Failed to " + tc.name + " VM: busy\n"; out != want {
				t.Errorf("output = %q, want %q", out, want)
			}
		})
	}
}

func TestVMVerb_ServerErrorIsTyped(t *testing.T) {
	var force bool
	rpcErr := status.Error(codes.FailedPrecondition, "instance is not running")
	for _, tc := range vmVerbCases(&rebootOptions{}, &force) {
		t.Run(tc.name, func(t *testing.T) {
			mock, _ := tc.mock(nil, rpcErr)
			out, err := runCase(t, tc.verb, mock, cli.OutputFormatTable)

			var opErr ErrVMOperationFailed
			if !errors.As(err, &opErr) || opErr.Operation != tc.name || opErr.ID != "vm-1" {
				t.Fatalf("err = %T %v, want ErrVMOperationFailed for %s vm-1", err, err, tc.name)
			}
			if !tc.typed(err) {
				t.Errorf("err does not wrap the SDK's typed %s error: %v", tc.name, err)
			}
			if status.Code(errors.Unwrap(errors.Unwrap(err))) != codes.FailedPrecondition {
				t.Errorf("cause = %v, want FailedPrecondition", err)
			}
			if out != "" {
				t.Errorf("printed %q on error", out)
			}
		})
	}
}

func TestVMVerb_InvalidOutputFormat(t *testing.T) {
	mock := &MockComputeClient{SuspendVMFunc: func(context.Context, *platformv1.SuspendVMRequest, ...grpc.CallOption) (*platformv1.SuspendVMResponse, error) {
		return &platformv1.SuspendVMResponse{Status: &platformv1.Status{Success: true}}, nil
	}}
	_, err := runCase(t, suspendVerb, mock, cli.OutputFormat("xml"))
	if _, ok := err.(cli.ErrInvalidOutputFormat); !ok {
		t.Fatalf("err = %T %v, want cli.ErrInvalidOutputFormat", err, err)
	}
}

func TestRunVMVerb_EmptyVMID(t *testing.T) {
	flags := &cli.CommonFlags{OutputFormat: cli.OutputFormatTable}
	for _, verb := range []vmVerb{rebootVerb(&rebootOptions{}), suspendVerb, resumeVerb} {
		t.Run(verb.operation, func(t *testing.T) {
			err := runVMVerb(flags, "", verb)
			if _, ok := err.(ErrInvalidVMConfig); !ok {
				t.Fatalf("err = %T %v, want ErrInvalidVMConfig", err, err)
			}
		})
	}
}

// vmVerbCommands builds the reboot, suspend and resume commands.
func vmVerbCommands(getFlags func() *cli.CommonFlags) []*cobra.Command {
	return []*cobra.Command{newRebootCommand(getFlags), newSuspendCommand(getFlags), newResumeCommand(getFlags)}
}

// Without a configured context the commands fail at NewBaseCommand.
func TestVMVerbCommands_NoContext(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{OutputFormat: cli.OutputFormatTable} }
	for _, cmd := range vmVerbCommands(getFlags) {
		t.Run(cmd.Name(), func(t *testing.T) {
			err := cmd.RunE(cmd, []string{"vm-1"})
			if _, ok := err.(cli.ErrNoContextSet); !ok {
				t.Fatalf("err = %T %v, want cli.ErrNoContextSet", err, err)
			}
		})
	}
}

func TestVMVerbCommands_Shape(t *testing.T) {
	getFlags := func() *cli.CommonFlags { return &cli.CommonFlags{} }
	for _, cmd := range vmVerbCommands(getFlags) {
		t.Run(cmd.Name(), func(t *testing.T) {
			if err := cmd.Args(cmd, []string{}); err == nil {
				t.Error("accepted no arguments")
			}
			if err := cmd.Args(cmd, []string{"a", "b"}); err == nil {
				t.Error("accepted two arguments")
			}
			if cmd.Long == "" {
				t.Error("has no long description")
			}
			// Only reboot takes a flag: --force.
			if hasForce := cmd.Flags().Lookup("force") != nil; hasForce != (cmd.Name() == "reboot") {
				t.Errorf("--force defined = %v", hasForce)
			}
		})
	}
}
