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
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fieldValues indexes a FIELD/VALUE table by field.
func fieldValues(t *testing.T, table *cli.TableData) map[string]string {
	t.Helper()
	require.Equal(t, []string{"FIELD", "VALUE"}, table.Headers)
	values := map[string]string{}
	for _, row := range table.Rows {
		values[row[0]] = row[1]
	}
	return values
}

// tableOf runs a command and returns the table it printed.
func tableOf(t *testing.T, conn *fakeConn, args ...string) *cli.TableData {
	t.Helper()
	printed := withFakeConn(t, conn)
	require.NoError(t, execute(&cli.CommonFlags{}, args...))
	table, ok := (*printed).(*cli.TableData)
	require.True(t, ok, "printed %T", *printed)
	return table
}

func TestFieldsTable_FormatsEachKindOfField(t *testing.T) {
	job := &platformv1.SchedulerJob{
		JobId:           "42",
		JobType:         platformv1.SchedulerJobType_SCHEDULER_JOB_TYPE_ONE_SHOT,
		Status:          platformv1.SchedulerJobStatus(99),
		DelayMs:         1500,
		Payload:         []byte("hi"),
		NextRunAtUnixMs: 1791878400000,
		Tags:            map[string]string{"team": "storage", "env": "prod"},
	}
	conn := &fakeConn{replies: map[string]proto.Message{
		platformv1.SchedulerService_GetJob_FullMethodName: &platformv1.GetSchedulerJobResponse{Job: job},
	}}

	values := fieldValues(t, tableOf(t, conn, "scheduler", "get", "42"))
	assert.Equal(t, "42", values["job id"])
	assert.Equal(t, "one-shot", values["job type"], "enum without its prefix")
	assert.Equal(t, "99", values["status"], "an enum number the CLI does not know")
	assert.Equal(t, "1.5s", values["delay"], "a _ms field is a duration")
	assert.Equal(t, "aGk=", values["payload"], "bytes are base64")
	assert.Equal(t, "2026-10-13T08:00:00Z", values["next run at"], "a _unix_ms field is a time")
	assert.Equal(t, "never", values["last run at"], "an unset time")
	assert.Equal(t, "env=prod, team=storage", values["tags"], "map entries sorted")
}

func TestFieldsTable_CountsListsAndPrintsNestedMessages(t *testing.T) {
	jobs := fieldValues(t, fieldsTable(&platformv1.ListSchedulerJobsResponse{Jobs: []*platformv1.SchedulerJob{{}, {}}}))
	assert.Equal(t, "2 entries", jobs["jobs"])
	one := fieldValues(t, fieldsTable(&platformv1.ListSchedulerJobsResponse{Jobs: []*platformv1.SchedulerJob{{}}}))
	assert.Equal(t, "1 entry", one["jobs"])

	nested := fieldValues(t, fieldsTable(&platformv1.GetSchedulerJobResponse{Job: &platformv1.SchedulerJob{JobId: "42"}}))
	assert.Contains(t, nested["job"], `"42"`)
}

func TestFieldsTable_IsEmptyForANilMessage(t *testing.T) {
	table := fieldsTable((*platformv1.SchedulerJob)(nil))
	assert.Equal(t, []string{"FIELD", "VALUE"}, table.Headers)
	assert.Empty(t, table.Rows)
}

func TestListTable_HasOneRowPerItem(t *testing.T) {
	conn := &fakeConn{replies: map[string]proto.Message{
		platformv1.SchedulerService_GetJobHistory_FullMethodName: &platformv1.GetSchedulerJobHistoryResponse{
			Executions: []*platformv1.SchedulerJobExecution{
				{ExecutionId: "e1", Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_FAILED, DurationMs: 250, Error: "boom"},
				{ExecutionId: "e2", Status: platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_COMPLETED, StartedAtUnixMs: 1791878400000},
			},
		},
	}}

	table := tableOf(t, conn, "scheduler", "history", "42")
	assert.Equal(t, []string{"EXECUTION ID", "STATUS", "STARTED AT", "DURATION", "RETRY COUNT", "ERROR"}, table.Headers)
	assert.Equal(t, [][]string{
		{"e1", "failed", "never", "250ms", "0", "boom"},
		{"e2", "completed", "2026-10-13T08:00:00Z", "0s", "0", ""},
	}, table.Rows)
}

func TestListTable_LeavesAnUnknownColumnBlank(t *testing.T) {
	table := listTable([]*platformv1.SchedulerJob{{JobId: "42"}}, "job_id", "no_such_field")
	assert.Equal(t, []string{"JOB ID", "NO SUCH FIELD"}, table.Headers)
	assert.Equal(t, [][]string{{"42", ""}}, table.Rows)
}

func TestConfirmation(t *testing.T) {
	table := confirmation[*platformv1.DeleteSchedulerJobResponse]("job id", "42", "deleted")(&platformv1.DeleteSchedulerJobResponse{})
	assert.Equal(t, map[string]string{"job id": "42", "result": "deleted"}, fieldValues(t, table))
}

func TestEnumPrefix(t *testing.T) {
	assert.Equal(t, "SCHEDULER_JOB_STATUS_", enumPrefix(jobStatusEnum))
	assert.Empty(t, enumPrefix(structpb.NullValue_NULL_VALUE.Descriptor()), "zero value is not UNSPECIFIED")
	assert.Empty(t, enumPrefix(descriptorpb.FieldDescriptorProto_TYPE_DOUBLE.Descriptor()), "no zero value")
}

func TestParseEnum(t *testing.T) {
	number, err := parseEnum("status", jobStatusEnum, "paused")
	require.NoError(t, err)
	assert.Equal(t, platformv1.SchedulerJobStatus_SCHEDULER_JOB_STATUS_PAUSED.Number(), number)

	number, err = parseEnum("status", jobStatusEnum, "")
	require.NoError(t, err)
	assert.Zero(t, number, "an empty flag leaves the field unset")

	_, err = parseEnum("status", jobStatusEnum, "unspecified")
	var invalid ErrInvalidFlag
	require.ErrorAs(t, err, &invalid, "the zero value is not a choice")
	assert.Equal(t, "status", invalid.Flag)
	assert.Contains(t, invalid.Want, "paused")
	assert.NotContains(t, invalid.Want, "unspecified")
}

func TestParseTime(t *testing.T) {
	ms, err := parseTime("since", "2026-10-13T08:00:00Z")
	require.NoError(t, err)
	assert.Equal(t, int64(1791878400000), ms)

	ms, err = parseTime("since", "")
	require.NoError(t, err)
	assert.Zero(t, ms)

	_, err = parseTime("since", "2026-10-13")
	var invalid ErrInvalidFlag
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, `invalid --since "2026-10-13": want an RFC 3339 time such as 2026-10-13T08:00:00Z`, err.Error())
}

func TestCacheConfigSet_SendsEverySettingGiven(t *testing.T) {
	conn := &fakeConn{}
	withFakeConn(t, conn)

	require.NoError(t, execute(&cli.CommonFlags{}, "cache", "config", "set",
		"--l1-size", "50000", "--l1-ttl", "5m", "--cleanup-interval", "1m"))
	want := &platformv1.UpdateCacheConfigRequest{L1Size: int64Ptr(50000), L1TtlMs: int64Ptr(300000), CleanupIntervalMs: int64Ptr(60000)}
	assert.True(t, proto.Equal(want, conn.request), "sent %v", conn.request)
}

func TestMarkRequired(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().String("type", "", "")
	markRequired(cmd, "type")
	assert.Error(t, cmd.ValidateRequiredFlags())

	assert.Panics(t, func() { markRequired(cmd, "no-such-flag") }, "a typo in a flag name is a programming error")
}
