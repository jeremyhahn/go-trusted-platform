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

package profile

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
)

// getTestFlags returns a function that provides test CommonFlags
func getTestFlags() func() *cli.CommonFlags {
	return func() *cli.CommonFlags {
		return &cli.CommonFlags{
			OutputFormat: cli.OutputFormatJSON,
		}
	}
}

// TestNewCommand verifies the profile root command is created correctly
func TestNewCommand(t *testing.T) {
	cmd := NewCommand(getTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "profile", cmd.Use)
	assert.Equal(t, "Device profile management", cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify subcommands are registered
	subcommands := cmd.Commands()
	assert.Len(t, subcommands, 4)

	// Verify expected subcommands exist by checking Use field prefix
	expectedCommands := map[string]bool{
		"list":   false,
		"get":    false,
		"delete": false,
		"match":  false,
	}
	for _, sub := range subcommands {
		// Check if Use starts with expected command name
		for cmdName := range expectedCommands {
			if strings.HasPrefix(sub.Use, cmdName) {
				expectedCommands[cmdName] = true
			}
		}
	}
	for cmdName, found := range expectedCommands {
		assert.True(t, found, "%s subcommand should exist", cmdName)
	}
}

// TestNewListCommand verifies the list command is created with correct flags
func TestNewListCommand(t *testing.T) {
	cmd := newListCommand(getTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "list", cmd.Use)
	assert.Equal(t, "List device profiles", cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify flags exist with correct defaults
	pageFlag := cmd.Flag("page")
	require.NotNil(t, pageFlag)
	assert.Equal(t, "1", pageFlag.DefValue)

	pageSizeFlag := cmd.Flag("page-size")
	require.NotNil(t, pageSizeFlag)
	assert.Equal(t, "20", pageSizeFlag.DefValue)
}

// TestNewGetCommand verifies the get command is created correctly
func TestNewGetCommand(t *testing.T) {
	cmd := newGetCommand(getTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "get <id>", cmd.Use)
	assert.Equal(t, "Get device profile by ID", cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify args validation is set
	require.NotNil(t, cmd.Args)
}

// TestNewDeleteCommand verifies the delete command is created correctly
func TestNewDeleteCommand(t *testing.T) {
	cmd := newDeleteCommand(getTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "delete <id>", cmd.Use)
	assert.Equal(t, "Delete device profile by ID", cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify args validation is set
	require.NotNil(t, cmd.Args)
}

// TestNewMatchCommand verifies the match command is created with correct flags
func TestNewMatchCommand(t *testing.T) {
	cmd := newMatchCommand(getTestFlags())

	require.NotNil(t, cmd)
	assert.Equal(t, "match", cmd.Use)
	assert.Equal(t, "Find matching device profile", cmd.Short)
	assert.NotEmpty(t, cmd.Long)

	// Verify flags exist with correct defaults
	macFlag := cmd.Flag("mac")
	require.NotNil(t, macFlag)
	assert.Equal(t, "", macFlag.DefValue)

	serialFlag := cmd.Flag("serial")
	require.NotNil(t, serialFlag)
	assert.Equal(t, "", serialFlag.DefValue)

	modelFlag := cmd.Flag("model")
	require.NotNil(t, modelFlag)
	assert.Equal(t, "", modelFlag.DefValue)
}

// TestListCommandExecution verifies the list command execution returns daemon connection error
func TestListCommandExecution(t *testing.T) {
	cmd := newListCommand(getTestFlags())
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestListCommandWithPagination verifies list command handles pagination flags
func TestListCommandWithPagination(t *testing.T) {
	cmd := newListCommand(getTestFlags())
	cmd.SetArgs([]string{"--page", "5", "--page-size", "100"})

	err := cmd.Execute()
	require.Error(t, err)

	// Should still return daemon connection error since that's the current behavior
	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestGetCommandExecution verifies the get command execution with valid ID
func TestGetCommandExecution(t *testing.T) {
	cmd := newGetCommand(getTestFlags())
	cmd.SetArgs([]string{"123"})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestGetCommandInvalidID verifies get command handles invalid ID
func TestGetCommandInvalidID(t *testing.T) {
	testCases := []struct {
		name string
		id   string
	}{
		{"non-numeric", "abc"},
		{"float", "1.5"},
		{"empty_string_with_spaces", "  "},
		{"mixed", "12abc"},
		{"special_chars", "!@#"},
		{"overflow", "99999999999999999999"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newGetCommand(getTestFlags())
			cmd.SetArgs([]string{tc.id})

			err := cmd.Execute()
			require.Error(t, err)

			var invalidIDErr ErrInvalidID
			assert.ErrorAs(t, err, &invalidIDErr)
			assert.Equal(t, tc.id, invalidIDErr.ID)
		})
	}
}

// TestGetCommandNoArgs verifies get command fails without arguments
func TestGetCommandNoArgs(t *testing.T) {
	cmd := newGetCommand(getTestFlags())
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	// cobra.ExactArgs(1) will return an error
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestGetCommandTooManyArgs verifies get command fails with too many arguments
func TestGetCommandTooManyArgs(t *testing.T) {
	cmd := newGetCommand(getTestFlags())
	cmd.SetArgs([]string{"123", "456"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestDeleteCommandExecution verifies the delete command execution with valid ID
func TestDeleteCommandExecution(t *testing.T) {
	cmd := newDeleteCommand(getTestFlags())
	cmd.SetArgs([]string{"123"})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestDeleteCommandInvalidID verifies delete command handles invalid ID
func TestDeleteCommandInvalidID(t *testing.T) {
	testCases := []struct {
		name string
		id   string
	}{
		{"non-numeric", "xyz"},
		{"float", "3.14"},
		{"overflow", "99999999999999999999"},
		{"mixed_chars", "abc123def"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newDeleteCommand(getTestFlags())
			cmd.SetArgs([]string{tc.id})

			err := cmd.Execute()
			require.Error(t, err)

			var invalidIDErr ErrInvalidID
			assert.ErrorAs(t, err, &invalidIDErr)
			assert.Equal(t, tc.id, invalidIDErr.ID)
		})
	}
}

// TestDeleteCommandNoArgs verifies delete command fails without arguments
func TestDeleteCommandNoArgs(t *testing.T) {
	cmd := newDeleteCommand(getTestFlags())
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestMatchCommandWithMAC verifies match command execution with MAC flag
func TestMatchCommandWithMAC(t *testing.T) {
	cmd := newMatchCommand(getTestFlags())
	cmd.SetArgs([]string{"--mac", "00:11:22:33:44:55"})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestMatchCommandWithSerial verifies match command execution with serial flag
func TestMatchCommandWithSerial(t *testing.T) {
	cmd := newMatchCommand(getTestFlags())
	cmd.SetArgs([]string{"--serial", "ABC123DEF"})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestMatchCommandWithModel verifies match command execution with model flag
func TestMatchCommandWithModel(t *testing.T) {
	cmd := newMatchCommand(getTestFlags())
	cmd.SetArgs([]string{"--model", "Dell PowerEdge R740"})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestMatchCommandWithAllCriteria verifies match command with all flags
func TestMatchCommandWithAllCriteria(t *testing.T) {
	cmd := newMatchCommand(getTestFlags())
	cmd.SetArgs([]string{
		"--mac", "00:11:22",
		"--serial", "ABC",
		"--model", "Dell",
	})

	err := cmd.Execute()
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestMatchCommandNoCriteria verifies match command fails without any criteria
func TestMatchCommandNoCriteria(t *testing.T) {
	cmd := newMatchCommand(getTestFlags())
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err)

	var noMatchErr ErrNoMatchCriteria
	assert.ErrorAs(t, err, &noMatchErr)
	assert.Equal(t, "at least one of --mac, --serial, or --model is required", noMatchErr.Error())
}

// TestRunListFunction verifies the runList function directly
func TestRunListFunction(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatTable,
	}

	err := runList(flags, 1, 20)
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestRunListFunctionVariousPages tests runList with different pagination values
func TestRunListFunctionVariousPages(t *testing.T) {
	testCases := []struct {
		name     string
		page     int
		pageSize int
	}{
		{"first_page", 1, 10},
		{"large_page", 100, 50},
		{"small_page_size", 1, 5},
		{"large_page_size", 1, 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags := &cli.CommonFlags{
				OutputFormat: cli.OutputFormatTable,
			}

			err := runList(flags, tc.page, tc.pageSize)
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestRunGetFunction verifies the runGet function directly
func TestRunGetFunction(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatJSON,
	}

	err := runGet(flags, 42)
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestRunGetFunctionVariousIDs tests runGet with different ID values
func TestRunGetFunctionVariousIDs(t *testing.T) {
	testCases := []struct {
		name string
		id   uint64
	}{
		{"zero", 0},
		{"one", 1},
		{"small", 100},
		{"large", 18446744073709551615}, // max uint64
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags := &cli.CommonFlags{
				OutputFormat: cli.OutputFormatJSON,
			}

			err := runGet(flags, tc.id)
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestRunDeleteFunction verifies the runDelete function directly
func TestRunDeleteFunction(t *testing.T) {
	flags := &cli.CommonFlags{
		OutputFormat: cli.OutputFormatYAML,
	}

	err := runDelete(flags, 999)
	require.Error(t, err)

	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)
}

// TestRunDeleteFunctionVariousIDs tests runDelete with different ID values
func TestRunDeleteFunctionVariousIDs(t *testing.T) {
	testCases := []struct {
		name string
		id   uint64
	}{
		{"zero", 0},
		{"small", 42},
		{"medium", 999999},
		{"large", 9223372036854775807},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags := &cli.CommonFlags{
				OutputFormat: cli.OutputFormatYAML,
			}

			err := runDelete(flags, tc.id)
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestRunMatchFunction verifies the runMatch function directly
func TestRunMatchFunction(t *testing.T) {
	testCases := []struct {
		name   string
		mac    string
		serial string
		model  string
	}{
		{"mac_only", "00:11:22:33:44:55", "", ""},
		{"serial_only", "", "SN12345", ""},
		{"model_only", "", "", "Server Model X"},
		{"mac_and_serial", "AA:BB:CC", "SN999", ""},
		{"all_criteria", "FF:EE:DD", "SN888", "Model Y"},
		{"serial_and_model", "", "SN777", "Model Z"},
		{"mac_and_model", "11:22:33", "", "Model A"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags := &cli.CommonFlags{
				OutputFormat: cli.OutputFormatTable,
			}

			err := runMatch(flags, tc.mac, tc.serial, tc.model)
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestTruncateFunction verifies the truncate helper function
func TestTruncateFunction(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{
			name:     "shorter_than_max",
			input:    "short",
			max:      10,
			expected: "short",
		},
		{
			name:     "equal_to_max",
			input:    "exactten!",
			max:      9,
			expected: "exactten!",
		},
		{
			name:     "longer_than_max",
			input:    "this is a very long string",
			max:      10,
			expected: "this is...",
		},
		{
			name:     "empty_string",
			input:    "",
			max:      10,
			expected: "",
		},
		{
			name:     "one_char_over",
			input:    "abcde",
			max:      4,
			expected: "a...",
		},
		{
			name:     "unicode_string",
			input:    "Hello World",
			max:      8,
			expected: "Hello...",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := truncate(tc.input, tc.max)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// TestErrorTypes verifies all error type implementations
func TestErrorTypes(t *testing.T) {
	t.Run("ErrDaemonConnectionRequired", func(t *testing.T) {
		err := ErrDaemonConnectionRequired{}
		assert.Equal(t, "daemon connection required", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrInvalidID", func(t *testing.T) {
		err := ErrInvalidID{ID: "abc123"}
		assert.Equal(t, "invalid profile ID: abc123", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrInvalidID_empty", func(t *testing.T) {
		err := ErrInvalidID{ID: ""}
		assert.Equal(t, "invalid profile ID: ", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrProfileNotFound", func(t *testing.T) {
		err := ErrProfileNotFound{ID: 456}
		assert.Equal(t, "profile not found: 456", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrProfileNotFound_zero", func(t *testing.T) {
		err := ErrProfileNotFound{ID: 0}
		assert.Equal(t, "profile not found: 0", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrListProfilesFailed", func(t *testing.T) {
		err := ErrListProfilesFailed{Reason: "database unavailable"}
		assert.Equal(t, "failed to list profiles: database unavailable", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrListProfilesFailed_empty", func(t *testing.T) {
		err := ErrListProfilesFailed{Reason: ""}
		assert.Equal(t, "failed to list profiles: ", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrGetProfileFailed", func(t *testing.T) {
		err := ErrGetProfileFailed{ID: 789, Reason: "timeout"}
		assert.Equal(t, "failed to get profile 789: timeout", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrGetProfileFailed_large_id", func(t *testing.T) {
		err := ErrGetProfileFailed{ID: 18446744073709551615, Reason: "not found"}
		assert.Contains(t, err.Error(), "failed to get profile 18446744073709551615")
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrDeleteProfileFailed", func(t *testing.T) {
		err := ErrDeleteProfileFailed{ID: 101, Reason: "permission denied"}
		assert.Equal(t, "failed to delete profile 101: permission denied", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrDeleteProfileFailed_empty_reason", func(t *testing.T) {
		err := ErrDeleteProfileFailed{ID: 202, Reason: ""}
		assert.Equal(t, "failed to delete profile 202: ", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrMatchProfileFailed", func(t *testing.T) {
		err := ErrMatchProfileFailed{Reason: "invalid criteria"}
		assert.Equal(t, "failed to match profile: invalid criteria", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrNoMatchCriteria", func(t *testing.T) {
		err := ErrNoMatchCriteria{}
		assert.Equal(t, "at least one of --mac, --serial, or --model is required", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})

	t.Run("ErrNoMatchingProfile", func(t *testing.T) {
		err := ErrNoMatchingProfile{}
		assert.Equal(t, "no matching profile found", err.Error())
		assert.Implements(t, (*error)(nil), err)
	})
}

// TestCommandLongDescriptions verifies all commands have meaningful descriptions
func TestCommandLongDescriptions(t *testing.T) {
	getFlags := getTestFlags()

	testCases := []struct {
		name     string
		cmd      func() string
		contains []string
	}{
		{
			name: "profile_root",
			cmd:  func() string { return NewCommand(getFlags).Long },
			contains: []string{
				"Manage device profiles",
				"List all device profiles",
				"Get profile details",
				"Delete profiles",
				"Match devices",
			},
		},
		{
			name: "list",
			cmd:  func() string { return newListCommand(getFlags).Long },
			contains: []string{
				"List all device profiles",
				"pagination",
			},
		},
		{
			name: "get",
			cmd:  func() string { return newGetCommand(getFlags).Long },
			contains: []string{
				"Retrieve a device profile",
				"ID",
			},
		},
		{
			name: "delete",
			cmd:  func() string { return newDeleteCommand(getFlags).Long },
			contains: []string{
				"Delete a device profile",
				"permanently remove",
			},
		},
		{
			name: "match",
			cmd:  func() string { return newMatchCommand(getFlags).Long },
			contains: []string{
				"Find a device profile",
				"MAC",
				"serial",
				"model",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			long := tc.cmd()
			assert.NotEmpty(t, long)
			for _, s := range tc.contains {
				assert.Contains(t, long, s)
			}
		})
	}
}

// TestGetCommandValidIDRange verifies get command with various valid ID values
func TestGetCommandValidIDRange(t *testing.T) {
	testCases := []struct {
		name string
		id   string
	}{
		{"zero", "0"},
		{"one", "1"},
		{"small", "100"},
		{"medium", "1000000"},
		{"large", "18446744073709551615"}, // max uint64
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newGetCommand(getTestFlags())
			cmd.SetArgs([]string{tc.id})

			err := cmd.Execute()
			require.Error(t, err)

			// Valid IDs should reach the daemon connection error
			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestDeleteCommandValidIDRange verifies delete command with various valid ID values
func TestDeleteCommandValidIDRange(t *testing.T) {
	testCases := []struct {
		name string
		id   string
	}{
		{"zero", "0"},
		{"one", "1"},
		{"small", "500"},
		{"large", "9999999999"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newDeleteCommand(getTestFlags())
			cmd.SetArgs([]string{tc.id})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestMatchCommandEmptyFlagValues verifies match command treats empty strings correctly
func TestMatchCommandEmptyFlagValues(t *testing.T) {
	// Empty flag values should trigger NoMatchCriteria error
	cmd := newMatchCommand(getTestFlags())
	cmd.SetArgs([]string{"--mac", "", "--serial", "", "--model", ""})

	err := cmd.Execute()
	require.Error(t, err)

	var noMatchErr ErrNoMatchCriteria
	assert.ErrorAs(t, err, &noMatchErr)
}

// TestFlagUsage verifies flag descriptions are set
func TestFlagUsage(t *testing.T) {
	t.Run("list_flags", func(t *testing.T) {
		cmd := newListCommand(getTestFlags())

		pageFlag := cmd.Flag("page")
		require.NotNil(t, pageFlag)
		assert.NotEmpty(t, pageFlag.Usage)

		pageSizeFlag := cmd.Flag("page-size")
		require.NotNil(t, pageSizeFlag)
		assert.NotEmpty(t, pageSizeFlag.Usage)
	})

	t.Run("match_flags", func(t *testing.T) {
		cmd := newMatchCommand(getTestFlags())

		macFlag := cmd.Flag("mac")
		require.NotNil(t, macFlag)
		assert.NotEmpty(t, macFlag.Usage)

		serialFlag := cmd.Flag("serial")
		require.NotNil(t, serialFlag)
		assert.NotEmpty(t, serialFlag.Usage)

		modelFlag := cmd.Flag("model")
		require.NotNil(t, modelFlag)
		assert.NotEmpty(t, modelFlag.Usage)
	})
}

// TestSubcommandRegistration verifies subcommands are properly attached to parent
func TestSubcommandRegistration(t *testing.T) {
	parent := NewCommand(getTestFlags())

	// Verify each subcommand can be found
	listCmd, _, err := parent.Find([]string{"list"})
	require.NoError(t, err)
	assert.Equal(t, "list", listCmd.Use)

	getCmd, _, err := parent.Find([]string{"get"})
	require.NoError(t, err)
	assert.Equal(t, "get <id>", getCmd.Use)

	deleteCmd, _, err := parent.Find([]string{"delete"})
	require.NoError(t, err)
	assert.Equal(t, "delete <id>", deleteCmd.Use)

	matchCmd, _, err := parent.Find([]string{"match"})
	require.NoError(t, err)
	assert.Equal(t, "match", matchCmd.Use)
}

// TestErrorAsInterface verifies errors can be used with errors.As
func TestErrorAsInterface(t *testing.T) {
	var err error

	err = ErrDaemonConnectionRequired{}
	var daemonErr ErrDaemonConnectionRequired
	assert.ErrorAs(t, err, &daemonErr)

	err = ErrInvalidID{ID: "test"}
	var invalidErr ErrInvalidID
	assert.ErrorAs(t, err, &invalidErr)
	assert.Equal(t, "test", invalidErr.ID)

	err = ErrProfileNotFound{ID: 123}
	var notFoundErr ErrProfileNotFound
	assert.ErrorAs(t, err, &notFoundErr)
	assert.Equal(t, uint64(123), notFoundErr.ID)

	err = ErrListProfilesFailed{Reason: "test"}
	var listErr ErrListProfilesFailed
	assert.ErrorAs(t, err, &listErr)
	assert.Equal(t, "test", listErr.Reason)

	err = ErrGetProfileFailed{ID: 456, Reason: "reason"}
	var getErr ErrGetProfileFailed
	assert.ErrorAs(t, err, &getErr)
	assert.Equal(t, uint64(456), getErr.ID)
	assert.Equal(t, "reason", getErr.Reason)

	err = ErrDeleteProfileFailed{ID: 789, Reason: "failed"}
	var delErr ErrDeleteProfileFailed
	assert.ErrorAs(t, err, &delErr)
	assert.Equal(t, uint64(789), delErr.ID)
	assert.Equal(t, "failed", delErr.Reason)

	err = ErrMatchProfileFailed{Reason: "match failed"}
	var matchErr ErrMatchProfileFailed
	assert.ErrorAs(t, err, &matchErr)
	assert.Equal(t, "match failed", matchErr.Reason)

	err = ErrNoMatchCriteria{}
	var noCriteriaErr ErrNoMatchCriteria
	assert.ErrorAs(t, err, &noCriteriaErr)

	err = ErrNoMatchingProfile{}
	var noMatchErr ErrNoMatchingProfile
	assert.ErrorAs(t, err, &noMatchErr)
}

// TestTruncateEdgeCases tests additional edge cases for truncate
func TestTruncateEdgeCases(t *testing.T) {
	// Test with max=3 (minimum for ellipsis)
	result := truncate("abcdefg", 3)
	assert.Equal(t, "...", result)

	// Test with max=4
	result = truncate("abcdefg", 4)
	assert.Equal(t, "a...", result)

	// Test exact boundary
	result = truncate("abc", 3)
	assert.Equal(t, "abc", result)

	// Test with max=5
	result = truncate("abcdefghij", 5)
	assert.Equal(t, "ab...", result)

	// Test string exactly at boundary
	result = truncate("abcd", 4)
	assert.Equal(t, "abcd", result)

	// Test longer string with max=6
	result = truncate("Hello World Test", 6)
	assert.Equal(t, "Hel...", result)
}

// TestMatchCommandMACOnly verifies match command with only MAC address variations
func TestMatchCommandMACOnly(t *testing.T) {
	testCases := []struct {
		name string
		mac  string
	}{
		{"full_mac", "00:11:22:33:44:55"},
		{"partial_mac", "00:11:22"},
		{"short_prefix", "00"},
		{"lowercase", "aa:bb:cc"},
		{"mixed_case", "Aa:Bb:Cc"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newMatchCommand(getTestFlags())
			cmd.SetArgs([]string{"--mac", tc.mac})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestMatchCommandSerialOnly verifies match command with only serial number variations
func TestMatchCommandSerialOnly(t *testing.T) {
	testCases := []struct {
		name   string
		serial string
	}{
		{"alphanumeric", "ABC123DEF456"},
		{"numeric_only", "1234567890"},
		{"alpha_only", "ABCDEFGH"},
		{"with_dash", "ABC-123-DEF"},
		{"short", "A1"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newMatchCommand(getTestFlags())
			cmd.SetArgs([]string{"--serial", tc.serial})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestMatchCommandModelOnly verifies match command with only model variations
func TestMatchCommandModelOnly(t *testing.T) {
	testCases := []struct {
		name  string
		model string
	}{
		{"simple", "ServerX"},
		{"with_spaces", "Dell PowerEdge R740"},
		{"with_numbers", "HP ProLiant DL380 Gen10"},
		{"quoted_internal", "Model \"Pro\""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newMatchCommand(getTestFlags())
			cmd.SetArgs([]string{"--model", tc.model})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestListCommandWithOutputFormats verifies list command with different output formats
func TestListCommandWithOutputFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format cli.OutputFormat
	}{
		{"table", cli.OutputFormatTable},
		{"json", cli.OutputFormatJSON},
		{"yaml", cli.OutputFormatYAML},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: tc.format,
				}
			}

			cmd := newListCommand(getFlags)
			cmd.SetArgs([]string{})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestGetCommandWithOutputFormats verifies get command with different output formats
func TestGetCommandWithOutputFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format cli.OutputFormat
	}{
		{"table", cli.OutputFormatTable},
		{"json", cli.OutputFormatJSON},
		{"yaml", cli.OutputFormatYAML},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: tc.format,
				}
			}

			cmd := newGetCommand(getFlags)
			cmd.SetArgs([]string{"42"})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestDeleteCommandWithOutputFormats verifies delete command with different output formats
func TestDeleteCommandWithOutputFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format cli.OutputFormat
	}{
		{"table", cli.OutputFormatTable},
		{"json", cli.OutputFormatJSON},
		{"yaml", cli.OutputFormatYAML},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: tc.format,
				}
			}

			cmd := newDeleteCommand(getFlags)
			cmd.SetArgs([]string{"99"})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestDeleteCommandDeleteManyArgs verifies delete command fails with multiple args
func TestDeleteCommandDeleteManyArgs(t *testing.T) {
	cmd := newDeleteCommand(getTestFlags())
	cmd.SetArgs([]string{"1", "2", "3"})

	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "accepts 1 arg(s)")
}

// TestCommandShortDescriptions verifies all commands have short descriptions
func TestCommandShortDescriptions(t *testing.T) {
	getFlags := getTestFlags()

	t.Run("root", func(t *testing.T) {
		cmd := NewCommand(getFlags)
		assert.NotEmpty(t, cmd.Short)
		assert.Equal(t, "Device profile management", cmd.Short)
	})

	t.Run("list", func(t *testing.T) {
		cmd := newListCommand(getFlags)
		assert.NotEmpty(t, cmd.Short)
		assert.Equal(t, "List device profiles", cmd.Short)
	})

	t.Run("get", func(t *testing.T) {
		cmd := newGetCommand(getFlags)
		assert.NotEmpty(t, cmd.Short)
		assert.Equal(t, "Get device profile by ID", cmd.Short)
	})

	t.Run("delete", func(t *testing.T) {
		cmd := newDeleteCommand(getFlags)
		assert.NotEmpty(t, cmd.Short)
		assert.Equal(t, "Delete device profile by ID", cmd.Short)
	})

	t.Run("match", func(t *testing.T) {
		cmd := newMatchCommand(getFlags)
		assert.NotEmpty(t, cmd.Short)
		assert.Equal(t, "Find matching device profile", cmd.Short)
	})
}

// TestMatchCommandCombinedCriteria verifies match with various combinations
func TestMatchCommandCombinedCriteria(t *testing.T) {
	testCases := []struct {
		name   string
		args   []string
		expect bool // true if should reach daemon error (valid criteria)
	}{
		{
			name:   "mac_and_serial",
			args:   []string{"--mac", "00:11:22", "--serial", "ABC"},
			expect: true,
		},
		{
			name:   "mac_and_model",
			args:   []string{"--mac", "00:11:22", "--model", "Server"},
			expect: true,
		},
		{
			name:   "serial_and_model",
			args:   []string{"--serial", "ABC", "--model", "Server"},
			expect: true,
		},
		{
			name:   "all_three",
			args:   []string{"--mac", "00:11:22", "--serial", "ABC", "--model", "Server"},
			expect: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := newMatchCommand(getTestFlags())
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			require.Error(t, err)

			if tc.expect {
				var daemonErr ErrDaemonConnectionRequired
				assert.ErrorAs(t, err, &daemonErr)
			}
		})
	}
}

// TestMatchCommandWithOutputFormats verifies match command with different output formats
func TestMatchCommandWithOutputFormats(t *testing.T) {
	testCases := []struct {
		name   string
		format cli.OutputFormat
	}{
		{"table", cli.OutputFormatTable},
		{"json", cli.OutputFormatJSON},
		{"yaml", cli.OutputFormatYAML},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			getFlags := func() *cli.CommonFlags {
				return &cli.CommonFlags{
					OutputFormat: tc.format,
				}
			}

			cmd := newMatchCommand(getFlags)
			cmd.SetArgs([]string{"--mac", "00:11:22"})

			err := cmd.Execute()
			require.Error(t, err)

			var daemonErr ErrDaemonConnectionRequired
			assert.ErrorAs(t, err, &daemonErr)
		})
	}
}

// TestErrorMatchProfileFailed_empty verifies ErrMatchProfileFailed with empty reason
func TestErrorMatchProfileFailed_empty(t *testing.T) {
	err := ErrMatchProfileFailed{Reason: ""}
	assert.Equal(t, "failed to match profile: ", err.Error())
	assert.Implements(t, (*error)(nil), err)
}

// TestTruncateWithLongString verifies truncate with a very long string
func TestTruncateWithLongString(t *testing.T) {
	longStr := strings.Repeat("a", 1000)
	result := truncate(longStr, 20)
	assert.Equal(t, "aaaaaaaaaaaaaaaaa...", result)
	assert.Len(t, result, 20)
}
