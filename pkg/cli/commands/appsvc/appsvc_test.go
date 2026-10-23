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

package appsvc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// errNoStreams is returned by fakeConn for a streaming call; no command makes
// one.
type errNoStreams struct{}

func (errNoStreams) Error() string { return "the fake connection has no streams" }

// fakeConn records the one unary call a command makes and answers it with a
// canned reply or an error.
type fakeConn struct {
	method  string
	request proto.Message
	replies map[string]proto.Message
	err     error
}

func (f *fakeConn) Invoke(_ context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	f.method = method
	f.request = proto.Clone(args.(proto.Message))
	if f.err != nil {
		return f.err
	}
	if canned, ok := f.replies[method]; ok {
		proto.Merge(reply.(proto.Message), canned)
	}
	return nil
}

func (f *fakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errNoStreams{}
}

// withFakeConn points the four client factories at conn and captures what
// the commands print.
func withFakeConn(t *testing.T, conn *fakeConn) *any {
	t.Helper()
	origCache, origScheduler, origMessaging, origObjects, origOutput :=
		newCacheClient, newSchedulerClient, newMessagingClient, newObjectStorageClient, output
	noClose := func() error { return nil }
	newCacheClient = func(*cli.CommonFlags) (platformv1.CacheServiceClient, func() error, error) {
		return platformv1.NewCacheServiceClient(conn), noClose, nil
	}
	newSchedulerClient = func(*cli.CommonFlags) (platformv1.SchedulerServiceClient, func() error, error) {
		return platformv1.NewSchedulerServiceClient(conn), noClose, nil
	}
	newMessagingClient = func(*cli.CommonFlags) (platformv1.MessagingServiceClient, func() error, error) {
		return platformv1.NewMessagingServiceClient(conn), noClose, nil
	}
	newObjectStorageClient = func(*cli.CommonFlags) (platformv1.ObjectStorageServiceClient, func() error, error) {
		return platformv1.NewObjectStorageServiceClient(conn), noClose, nil
	}
	var printed any
	output = func(_ *cli.CommonFlags, v any) error {
		printed = v
		return nil
	}
	t.Cleanup(func() {
		newCacheClient, newSchedulerClient, newMessagingClient, newObjectStorageClient, output =
			origCache, origScheduler, origMessaging, origObjects, origOutput
	})
	return &printed
}

// execute runs one platformctl command line against the four groups.
func execute(flags *cli.CommonFlags, args ...string) error {
	root := &cobra.Command{Use: "platformctl", SilenceUsage: true, SilenceErrors: true}
	getFlags := func() *cli.CommonFlags { return flags }
	root.AddCommand(NewCacheCommand(getFlags), NewSchedulerCommand(getFlags), NewMessagingCommand(getFlags),
		NewObjectStorageCommand(getFlags))
	root.SetArgs(args)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	return root.Execute()
}

// commandCase is one command line and the request it must send.
type commandCase struct {
	args    []string
	method  string
	request proto.Message
}

func int64Ptr(v int64) *int64 { return &v }

// commandCases has one command line per RPC of the three services.
func commandCases() []commandCase {
	return []commandCase{
		{[]string{"cache", "stats", "--entity-type", "users"},
			platformv1.CacheService_GetStats_FullMethodName, &platformv1.GetCacheStatsRequest{EntityType: "users"}},
		{[]string{"cache", "config", "get"},
			platformv1.CacheService_GetConfig_FullMethodName, &platformv1.GetCacheConfigRequest{}},
		// Only the settings given are sent.
		{[]string{"cache", "config", "set", "--l1-ttl", "5m"},
			platformv1.CacheService_UpdateConfig_FullMethodName, &platformv1.UpdateCacheConfigRequest{L1TtlMs: int64Ptr(300000)}},
		{[]string{"cache", "clear", "--all"},
			platformv1.CacheService_Clear_FullMethodName, &platformv1.ClearCacheRequest{All: true}},

		{[]string{"scheduler", "create", "nightly", "--type", "recurring", "--handler", "backup",
			"--schedule", "0 2 * * *", "--owner-type", "tenant", "--owner-id", "acme", "--timeout", "90s",
			"--execute-at", "2026-10-13T08:00:00Z", "--tag", "team=storage", "--payload", "full", "--max-retries", "3"},
			platformv1.SchedulerService_CreateJob_FullMethodName, &platformv1.CreateSchedulerJobRequest{
				Name: "nightly", JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_RECURRING, Handler: "backup",
				Schedule: "0 2 * * *", OwnerType: platformv1.SchedulerOwnerType_SCHEDULER_OWNER_TYPE_TENANT, OwnerId: "acme",
				TimeoutMs: 90000, ExecuteAtUnixMs: 1791878400000, Tags: map[string]string{"team": "storage"},
				Payload: []byte("full"), MaxRetries: 3,
			}},
		{[]string{"scheduler", "list", "--status", "paused", "--type", "one-shot", "--tag", "env=prod", "--limit", "10"},
			platformv1.SchedulerService_ListJobs_FullMethodName, &platformv1.ListSchedulerJobsRequest{
				Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED, JobType: platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT,
				Tags: map[string]string{"env": "prod"}, Limit: 10,
			}},
		{[]string{"scheduler", "get", "42"},
			platformv1.SchedulerService_GetJob_FullMethodName, &platformv1.GetSchedulerJobRequest{JobId: "42"}},
		{[]string{"scheduler", "update", "42", "--schedule", "0 3 * * *", "--delay", "2s"},
			platformv1.SchedulerService_UpdateJob_FullMethodName, &platformv1.UpdateSchedulerJobRequest{
				JobId: "42", Schedule: "0 3 * * *", DelayMs: 2000,
			}},
		{[]string{"scheduler", "delete", "42"},
			platformv1.SchedulerService_DeleteJob_FullMethodName, &platformv1.DeleteSchedulerJobRequest{JobId: "42"}},
		{[]string{"scheduler", "trigger", "42"},
			platformv1.SchedulerService_TriggerJob_FullMethodName, &platformv1.TriggerSchedulerJobRequest{JobId: "42"}},
		{[]string{"scheduler", "pause", "42"},
			platformv1.SchedulerService_PauseJob_FullMethodName, &platformv1.PauseSchedulerJobRequest{JobId: "42"}},
		{[]string{"scheduler", "resume", "42"},
			platformv1.SchedulerService_ResumeJob_FullMethodName, &platformv1.ResumeSchedulerJobRequest{JobId: "42"}},
		{[]string{"scheduler", "cancel", "42", "--reason", "replaced"},
			platformv1.SchedulerService_CancelJob_FullMethodName, &platformv1.CancelSchedulerJobRequest{JobId: "42", Reason: "replaced"}},
		{[]string{"scheduler", "history", "42", "--since", "2026-10-13T08:00:00Z", "--status", "failed", "--limit", "5"},
			platformv1.SchedulerService_GetJobHistory_FullMethodName, &platformv1.GetSchedulerJobHistoryRequest{
				JobId: "42", StartTimeUnixMs: 1791878400000, Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED, Limit: 5,
			}},
		{[]string{"scheduler", "status"},
			platformv1.SchedulerService_GetStatus_FullMethodName, &platformv1.GetSchedulerStatusRequest{}},

		{[]string{"messaging", "channel", "create", "events", "--persistent", "--max-history", "100", "--ttl", "1h", "--codec", "json"},
			platformv1.MessagingService_CreateChannel_FullMethodName, &platformv1.CreateMessagingChannelRequest{
				Name: "events", Persistent: true, MaxHistory: 100, TtlMs: 3600000, Codec: "json",
			}},
		{[]string{"messaging", "channel", "list"},
			platformv1.MessagingService_ListChannels_FullMethodName, &platformv1.ListMessagingChannelsRequest{}},
		{[]string{"messaging", "channel", "get", "events"},
			platformv1.MessagingService_GetChannel_FullMethodName, &platformv1.GetMessagingChannelRequest{Name: "events"}},
		{[]string{"messaging", "channel", "delete", "events"},
			platformv1.MessagingService_DeleteChannel_FullMethodName, &platformv1.DeleteMessagingChannelRequest{Name: "events"}},
		{[]string{"messaging", "channel", "stats", "events"},
			platformv1.MessagingService_GetChannelStats_FullMethodName, &platformv1.GetMessagingChannelStatsRequest{Channel: "events"}},
		{[]string{"messaging", "publish", "events", "hello", "--dedup-key", "k1", "--metadata", "a=b"},
			platformv1.MessagingService_Publish_FullMethodName, &platformv1.PublishMessageRequest{
				Channel: "events", Payload: []byte("hello"), DedupKey: "k1", Metadata: map[string]string{"a": "b"},
			}},
		{[]string{"messaging", "stats"},
			platformv1.MessagingService_GetStats_FullMethodName, &platformv1.GetMessagingStatsRequest{}},
		{[]string{"messaging", "dedup-stats"},
			platformv1.MessagingService_GetDedupStats_FullMethodName, &platformv1.GetMessagingDedupStatsRequest{}},

		{[]string{"objectstorage", "put", "docs:a.txt", "hello", "--backend", "default", "--content-type", "text/plain",
			"--tenant", "acme", "--shard", "4", "--tag", "env=prod", "--min-replicas", "3", "--replication-mode", "quorum",
			"--replica-store", "s3", "--archive-after-days", "30", "--archive-store", "glacier",
			"--retention-days", "90", "--max-versions", "5"},
			platformv1.ObjectStorageService_PutObject_FullMethodName, &platformv1.PutObjectRequest{
				Key: "docs:a.txt", Value: []byte("hello"), ContentType: "text/plain", TenantId: "acme", ShardId: 4,
				Tags: map[string]string{"env": "prod"}, TargetBackend: "default",
				ReplicationPolicy: &platformv1.ObjectReplicationPolicy{Enabled: true, MinReplicas: 3, Mode: "quorum", TargetStores: []string{"s3"}},
				ArchivePolicy:     &platformv1.ObjectArchivePolicy{Enabled: true, ArchiveAfterDays: 30, TargetStore: "glacier"},
				RetentionPolicy:   &platformv1.ObjectRetentionPolicy{Enabled: true, RetentionDays: 90, MaxVersions: 5},
			}},
		{[]string{"objectstorage", "get", "docs:a.txt", "--tenant", "acme", "--metadata"},
			platformv1.ObjectStorageService_GetObject_FullMethodName, &platformv1.GetObjectRequest{Key: "docs:a.txt", TenantId: "acme", IncludeMetadata: true}},
		{[]string{"objectstorage", "delete", "docs:a.txt", "--tenant", "acme"},
			platformv1.ObjectStorageService_DeleteObject_FullMethodName, &platformv1.DeleteObjectRequest{Key: "docs:a.txt", TenantId: "acme"}},
		{[]string{"objectstorage", "head", "docs:a.txt"},
			platformv1.ObjectStorageService_HeadObject_FullMethodName, &platformv1.HeadObjectRequest{Key: "docs:a.txt"}},
		{[]string{"objectstorage", "list", "--prefix", "docs:", "--tenant", "acme", "--limit", "20", "--cursor", "c1", "--tags"},
			platformv1.ObjectStorageService_ListObjects_FullMethodName, &platformv1.ListObjectsRequest{
				Prefix: "docs:", TenantId: "acme", Limit: 20, Cursor: "c1", IncludeTags: true,
			}},
		{[]string{"objectstorage", "copy", "docs:a.txt", "docs:b.txt", "--backend", "default", "--overwrite"},
			platformv1.ObjectStorageService_CopyObject_FullMethodName, &platformv1.CopyObjectRequest{
				SourceKey: "docs:a.txt", DestinationKey: "docs:b.txt", OverwriteExisting: true, TargetBackend: "default",
			}},
		{[]string{"objectstorage", "list-by-tag", "env", "prod", "--limit", "5"},
			platformv1.ObjectStorageService_ListObjectsByTag_FullMethodName, &platformv1.ListObjectsByTagRequest{
				TagName: "env", TagValue: "prod", Limit: 5,
			}},
		{[]string{"objectstorage", "list-tenant", "acme", "--tags", "--cursor", "c2"},
			platformv1.ObjectStorageService_ListTenantObjects_FullMethodName, &platformv1.ListTenantObjectsRequest{
				TenantId: "acme", IncludeTags: true, Cursor: "c2",
			}},
	}
}

// Every RPC of the four services has a command, and each command sends the
// request its flags and arguments describe.
func TestCommands_SendTheRequestTheirFlagsDescribe(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range commandCases() {
		conn := &fakeConn{}
		printed := withFakeConn(t, conn)

		require.NoError(t, execute(&cli.CommonFlags{}, tc.args...), "%v", tc.args)
		assert.Equal(t, tc.method, conn.method, "%v", tc.args)
		assert.True(t, proto.Equal(tc.request, conn.request), "%v sent %v, want %v", tc.args, conn.request, tc.request)
		assert.IsType(t, &cli.TableData{}, *printed, "%v", tc.args)
		covered[tc.method] = true
	}

	for _, desc := range []grpc.ServiceDesc{
		platformv1.CacheService_ServiceDesc,
		platformv1.SchedulerService_ServiceDesc,
		platformv1.MessagingService_ServiceDesc,
		platformv1.ObjectStorageService_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			method := "/" + desc.ServiceName + "/" + m.MethodName
			assert.True(t, covered[method], "%s has no platformctl command", method)
		}
	}
}

func TestCommands_WrapRPCFailures(t *testing.T) {
	for _, tc := range commandCases() {
		conn := &fakeConn{err: status.Error(codes.Unavailable, "scheduler service is not configured")}
		printed := withFakeConn(t, conn)

		err := execute(&cli.CommonFlags{}, tc.args...)
		var wrapped *WrappedError
		require.True(t, errors.As(err, &wrapped), "%v: error = %v", tc.args, err)
		assert.True(t, strings.HasPrefix(wrapped.Msg, "failed to "), "%v: %q", tc.args, wrapped.Msg)
		assert.Equal(t, codes.Unavailable, status.Code(err), "%v", tc.args)
		assert.Nil(t, *printed, "%v printed a failed call", tc.args)
	}
}

func TestCommands_SurfaceFactoryFailures(t *testing.T) {
	cause := cli.ErrNoContextSet{}
	origCache, origScheduler, origMessaging, origObjects := newCacheClient, newSchedulerClient, newMessagingClient, newObjectStorageClient
	t.Cleanup(func() {
		newCacheClient, newSchedulerClient, newMessagingClient, newObjectStorageClient = origCache, origScheduler, origMessaging, origObjects
	})
	newObjectStorageClient = func(*cli.CommonFlags) (platformv1.ObjectStorageServiceClient, func() error, error) {
		return nil, nil, cause
	}
	newCacheClient = func(*cli.CommonFlags) (platformv1.CacheServiceClient, func() error, error) { return nil, nil, cause }
	newSchedulerClient = func(*cli.CommonFlags) (platformv1.SchedulerServiceClient, func() error, error) {
		return nil, nil, cause
	}
	newMessagingClient = func(*cli.CommonFlags) (platformv1.MessagingServiceClient, func() error, error) {
		return nil, nil, cause
	}

	for _, tc := range commandCases() {
		assert.ErrorIs(t, execute(&cli.CommonFlags{}, tc.args...), cause, "%v", tc.args)
	}
}

// JSON and YAML print the reply in the proto3 JSON mapping, with enum names
// and every field present.
func TestCommands_PrintTheProtoJSONMappingForStructuredOutput(t *testing.T) {
	conn := &fakeConn{replies: map[string]proto.Message{
		platformv1.SchedulerService_GetJob_FullMethodName: &platformv1.GetSchedulerJobResponse{Job: &platformv1.SchedulerJob{
			JobId: "42", Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED, NextRunAtUnixMs: 1791878400000,
		}},
	}}
	printed := withFakeConn(t, conn)

	for _, format := range []cli.OutputFormat{cli.OutputFormatJSON, cli.OutputFormatYAML} {
		require.NoError(t, execute(&cli.CommonFlags{OutputFormat: format}, "scheduler", "get", "42"))
		view, ok := (*printed).(map[string]any)
		require.True(t, ok, "%s printed %T", format, *printed)
		job, ok := view["job"].(map[string]any)
		require.True(t, ok, "%s: %v", format, view)
		assert.Equal(t, "SCHEDULER_JOB_STATUS_PAUSED", job["status"])
		assert.Equal(t, "1791878400000", job["next_run_at_unix_ms"])
		assert.Contains(t, job, "retry_count", "an unset field is still printed")
	}
}

func TestCommands_RefuseAReplyTheyCannotRender(t *testing.T) {
	conn := &fakeConn{replies: map[string]proto.Message{
		platformv1.SchedulerService_GetJob_FullMethodName: &platformv1.GetSchedulerJobResponse{Job: &platformv1.SchedulerJob{Name: "\xff"}},
	}}
	withFakeConn(t, conn)

	err := execute(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}, "scheduler", "get", "42")
	var wrapped *WrappedError
	require.True(t, errors.As(err, &wrapped), "error = %v", err)
	assert.Equal(t, "failed to render the reply", wrapped.Msg)
}

// A flag the command cannot turn into a request field is refused before any
// call is made.
func TestCommands_RefuseInvalidFlags(t *testing.T) {
	for _, args := range [][]string{
		{"scheduler", "create", "j", "--type", "weekly"},
		{"scheduler", "create", "j", "--type", "one-shot", "--owner-type", "everyone"},
		{"scheduler", "create", "j", "--type", "one-shot", "--execute-at", "tomorrow"},
		{"scheduler", "list", "--status", "sleeping"},
		{"scheduler", "list", "--type", "weekly"},
		{"scheduler", "list", "--owner-type", "everyone"},
		{"scheduler", "history", "42", "--since", "yesterday"},
		{"scheduler", "history", "42", "--until", "today"},
		{"scheduler", "history", "42", "--status", "sleeping"},
	} {
		conn := &fakeConn{}
		withFakeConn(t, conn)

		err := execute(&cli.CommonFlags{}, args...)
		var invalid ErrInvalidFlag
		require.True(t, errors.As(err, &invalid), "%v: error = %v", args, err)
		assert.Contains(t, err.Error(), "--"+invalid.Flag)
		assert.Empty(t, conn.method, "%v made a call", args)
	}

	// cobra refuses these before the command runs.
	for _, args := range [][]string{
		{"scheduler", "create", "j"},
		{"scheduler", "get"},
		{"cache", "config", "set"},
		{"cache", "clear"},
		{"cache", "clear", "--all", "--entity-type", "users"},
		{"messaging", "publish", "events"},
		{"objectstorage", "put"},
		{"objectstorage", "copy", "docs:a.txt"},
		{"objectstorage", "list-by-tag", "env"},
		{"objectstorage", "list", "docs:"},
	} {
		conn := &fakeConn{}
		withFakeConn(t, conn)
		assert.Error(t, execute(&cli.CommonFlags{}, args...), "%v", args)
		assert.Empty(t, conn.method, "%v made a call", args)
	}
}

// fakeCacheServer answers GetStats for the end-to-end test.
type fakeCacheServer struct {
	platformv1.UnimplementedCacheServiceServer
}

func (fakeCacheServer) GetStats(context.Context, *platformv1.GetCacheStatsRequest) (*platformv1.GetCacheStatsResponse, error) {
	return &platformv1.GetCacheStatsResponse{Hits: 7}, nil
}

// The production factory reaches the service through the SDK client over the
// Unix socket.
func TestSDKClient(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "d.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := grpc.NewServer()
	platformv1.RegisterCacheServiceServer(server, fakeCacheServer{})
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		<-served
	})

	flags := &cli.CommonFlags{GetContext: func() (*cli.Context, error) {
		return &cli.Context{Name: "local", Type: cli.ContextTypeLocal, Local: &cli.LocalContext{SocketPath: socket}}, nil
	}}
	client, closeFn, err := newCacheClient(flags)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, closeFn()) })

	reply, err := client.GetStats(context.Background(), &platformv1.GetCacheStatsRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint64(7), reply.GetHits())
}

func TestSDKClient_RefusesFlagsWithoutAContext(t *testing.T) {
	for _, open := range []func(*cli.CommonFlags) error{
		func(flags *cli.CommonFlags) error { _, _, err := newCacheClient(flags); return err },
		func(flags *cli.CommonFlags) error { _, _, err := newSchedulerClient(flags); return err },
		func(flags *cli.CommonFlags) error { _, _, err := newMessagingClient(flags); return err },
		func(flags *cli.CommonFlags) error { _, _, err := newObjectStorageClient(flags); return err },
	} {
		assert.IsType(t, cli.ErrNoContextSet{}, open(&cli.CommonFlags{}))
	}
}

func TestRender(t *testing.T) {
	table := cli.NewTableData("FIELD", "VALUE")
	table.AddRow("hits", "7")
	var buf bytes.Buffer
	require.NoError(t, render(&buf, &cli.CommonFlags{OutputFormat: cli.OutputFormatTable, NoColor: true}, table))
	assert.True(t, strings.HasPrefix(strings.TrimSpace(buf.String()), "FIELD"), buf.String())

	buf.Reset()
	err := render(&buf, &cli.CommonFlags{OutputFormat: "xml"}, table)
	var invalid cli.ErrInvalidOutputFormat
	assert.True(t, errors.As(err, &invalid), "error = %v", err)
	assert.Zero(t, buf.Len())
}

func TestIsStructuredOutput(t *testing.T) {
	assert.True(t, isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatJSON}))
	assert.True(t, isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatYAML}))
	assert.False(t, isStructuredOutput(&cli.CommonFlags{OutputFormat: cli.OutputFormatTable}))
	assert.False(t, isStructuredOutput(nil))
}

func TestWrappedError(t *testing.T) {
	cause := ErrInvalidFlag{Flag: "type", Value: "weekly", Want: "one of one-shot"}
	err := &WrappedError{Msg: "failed to create the job", Err: cause}
	assert.Equal(t, `failed to create the job: invalid --type "weekly": want one of one-shot`, err.Error())
	assert.ErrorIs(t, err, cause)
}
