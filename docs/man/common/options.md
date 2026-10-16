# Common Options

> **Status: REFERENCE** · Last verified: 2026-10-15
> The persistent flags of `platformd` (`pkg/daemon/commands/root.go`).

This is the set of global options supported by every `platformd` command:

  * **-h**, **\--help**:
    Display the commands usage. The help menu is also available for subcommands.

  * **-d**, **\--debug**:
    Enables debug mode with verbose logging

  * **\--debug-secrets**:
    Enables secret debugging. Passwords and other sensitive information is
    printed to the log for debugging.

  * **-e**, **\--env**:
    Runtime environment: `dev`, `staging` or `prod`. Default: `dev`.

  * **-c**, **\--config**:
    Path to a specific config file; overrides **\--config-dir**.

  * **\--init**:
    Initialize and provision the platform.

  * **\--so-pin**:
    Prompt for the Security Officer PIN.

  * **\--pin**:
    Prompt for the administrator or user PIN.

  * **\--raw-so-pin**, **\--raw-pin**:
    The Security Officer PIN / user PIN as plain text, without a prompt. For
    automation, testing and development.

  * **\--platform-dir**:
    The directory where all platform data is stored. Default:
    `<working directory>/trusted-data`.

  * **\--config-dir**:
    The directory where all platform configuration files are stored. Default:
    `/etc/trusted-platform`.

  * **\--log-dir**:
    The directory where all platform log files are stored. Default:
    `trusted-data/log`.

  * **\--ca-dir**:
    The directory where all Certificate Authority files are kept. Default:
    `trusted-data/ca`.

  * **\--intermediate**:
    The target Certificate Authority index. Default: `1`.

  * **\--setuid**:
    The operating system user to run as. Default: `root`.
