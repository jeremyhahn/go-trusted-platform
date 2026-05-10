package commands

import (
	"errors"
	"testing"
)

func TestRootCommandProperties(t *testing.T) {
	if rootCmd.Use != "gatewayd" {
		t.Errorf("expected Use 'gatewayd', got %s", rootCmd.Use)
	}
	if rootCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if rootCmd.Long == "" {
		t.Error("Long description should not be empty")
	}
	if !rootCmd.TraverseChildren {
		t.Error("TraverseChildren should be true")
	}
}

func TestRootCommandSubcommands(t *testing.T) {
	expectedSubs := []string{"serve", "version"}
	commands := rootCmd.Commands()

	for _, expected := range expectedSubs {
		found := false
		for _, subcmd := range commands {
			if subcmd.Name() == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected subcommand %s not found", expected)
		}
	}
}

func TestRootCommandPersistentFlags(t *testing.T) {
	expectedFlags := []string{
		"config", "debug", "log-format",
		"log-level", "data-dir", "config-dir",
	}

	for _, flagName := range expectedFlags {
		flag := rootCmd.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Errorf("persistent flag %s should exist", flagName)
		}
	}
}

func TestVersionCommandProperties(t *testing.T) {
	if versionCmd.Use != "version" {
		t.Errorf("expected Use 'version', got %s", versionCmd.Use)
	}
	if versionCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if versionCmd.Run == nil {
		t.Error("Run should not be nil")
	}
}

func TestVersionCommandExecutes(t *testing.T) {
	versionCmd.Run(versionCmd, []string{})
}

func TestServeCommandProperties(t *testing.T) {
	if serveCmd.Use != "serve" {
		t.Errorf("expected Use 'serve', got %s", serveCmd.Use)
	}
	if serveCmd.Short == "" {
		t.Error("Short description should not be empty")
	}
	if serveCmd.RunE == nil {
		t.Error("RunE should not be nil")
	}
}

func TestServeCommandFlags(t *testing.T) {
	// --modes flag should NOT exist (removed in config-driven refactor)
	modesFlag := serveCmd.Flags().Lookup("modes")
	if modesFlag != nil {
		t.Error("modes flag should not exist (config-driven service loading)")
	}

	// These flags should still exist
	expectedFlags := []string{
		"listen", "bgp-asn",
		"bgp-router-id",
		"api-port", "grpc-port",
	}

	for _, flagName := range expectedFlags {
		flag := serveCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist on serve command", flagName)
		}
	}
}

func TestServeCommandNoModesFlag(t *testing.T) {
	// Explicitly test that --modes is gone
	flag := serveCmd.Flags().Lookup("modes")
	if flag != nil {
		t.Error("--modes flag should have been removed; services are config-driven")
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrMissingBGPConfig", ErrMissingBGPConfig},
		{"ErrGatewayStartFailed", ErrGatewayStartFailed},
		{"ErrGatewayShutdownFailed", ErrGatewayShutdownFailed},
		{"ErrConfigLoadFailed", ErrConfigLoadFailed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}
			if tt.err.Error() == "" {
				t.Error("error message should not be empty")
			}
		})
	}
}

func TestSentinelErrorsAreDistinct(t *testing.T) {
	allErrors := []error{
		ErrMissingBGPConfig,
		ErrGatewayStartFailed,
		ErrGatewayShutdownFailed,
		ErrConfigLoadFailed,
	}

	for i := 0; i < len(allErrors); i++ {
		for j := i + 1; j < len(allErrors); j++ {
			if errors.Is(allErrors[i], allErrors[j]) {
				t.Errorf("expected %v and %v to be distinct", allErrors[i], allErrors[j])
			}
		}
	}
}

func TestInitConfig_NoConfigFile(t *testing.T) {
	origCfgFile := cfgFile
	cfgFile = ""
	defer func() { cfgFile = origCfgFile }()

	// Should not panic
	initConfig()
}

func TestInitConfig_WithConfigFile(t *testing.T) {
	origCfgFile := cfgFile
	cfgFile = "/nonexistent/config.yaml"
	defer func() { cfgFile = origCfgFile }()

	// Should not panic even with nonexistent file
	initConfig()
}

func TestExecuteWithVersion(t *testing.T) {
	rootCmd.SetArgs([]string{"version"})
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("version command should not return error, got: %v", err)
	}
}
