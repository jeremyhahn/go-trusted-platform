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
	expectedFlags := []string{
		"modes", "listen", "bgp-asn",
		"bgp-router-id", "vxlan-vni",
		"api-port", "grpc-port",
	}

	for _, flagName := range expectedFlags {
		flag := serveCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("flag %s should exist on serve command", flagName)
		}
	}
}

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"ErrInvalidGatewayMode", ErrInvalidGatewayMode},
		{"ErrMissingBGPConfig", ErrMissingBGPConfig},
		{"ErrGatewayStartFailed", ErrGatewayStartFailed},
		{"ErrGatewayShutdownFailed", ErrGatewayShutdownFailed},
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
		ErrInvalidGatewayMode,
		ErrMissingBGPConfig,
		ErrGatewayStartFailed,
		ErrGatewayShutdownFailed,
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
	// initConfig should not panic when no config file is found
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
