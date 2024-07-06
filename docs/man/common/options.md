This is the set of global options supported by every command in the CLI:

  * **-h**, **\--help**:
    Display the commands usage. The help menu is also available for subcommands.

  * **-d**, **\--debug**:
    Enables debug mode with verbose logging

  * **-p**, **\--ca-password**:
    The platform Certificate Authority password. This is the password to
    the CA that is currently loaded and in use by the platform.

  * **-r**, **\--root-password**:
    The Root Certificate Authority Password. This options should only be used
    during initialization of the platform. After initialization, the Root
    Certificate Authority should be taken offline, including it's private key,
    for maximum security and align with CA operational best practices.

  * **-i**, **\--intermediate-password**:
    The Intermediate Certificate Authority Password.

  * **-s**, **\--server-password**:
    The web servicer TLS private key password

  * , **\--ek-auth**:
    The Endorsement Key authorization password

  * , **\--srk-auth**:
    The Storage Root Key authorization password

  * , **\--debug-secrets**:
    Enables secret debugging. Passwords and other sensitive information is
    printed to the log for debugging.

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
