This is the set of global options supported by every command in the CLI:

  * **-h**, **\--help**:
    Display the commands usage. The help menu is also available for subcommands.

  * **-d**, **\--debug**:
    Enables debug mode with verbose logging

  * , **\--debug-secrets**:
    Enables secret debugging. Passwords and other sensitive information is
    printed to the log for debugging.

  * **\--init**:
    Perform initialization

  * **\--so-pin**:
    The Security Officer PIN

  * **\--pin**:
    The user PIN

  * , **\--platform-dir**:
    The directory where all platform data is stored.

  * , **\--config-dir**:
    The directory where all platform configuration files are stored.

  * , **\--log-dir**:
    The directory where all platform log files are stored.

  * , **\--ca-dir**:
    The directory where all Certificate Authority files are kept.

  * , **\--setuid**:
    Sets the uid for the platform to run. If the platform is started as root,
    permissions are downgraded to the specified uid.

  * , **\--listen**:
    The socket listen address used for embedded network services
