package disklessroot

// BootModelShell is the POSIX shell form of BootModelFromCmdline's branch
// decision, for the boot scripts that run before or beside any Go: it answers
// "diskless" only for platform_boot_model=diskless and "disk" for anything
// else — another model, no selector, no command line — so a disk node never
// takes a diskless branch. It only picks the branch; platform-initrd and
// platformd re-read and fully validate the parameters (an unknown model, a
// repeated key).
const BootModelShell = `# Print "diskless" when the command line in the named file selects the
# diskless root, "disk" otherwise.
# Usage: platformd_boot_model <cmdline file>
platformd_boot_model() {
    if [ ! -f "$1" ]; then
        echo disk
        return 0
    fi
    _cmdline=" $(tr '\n\t' '  ' < "$1") "
    case "$_cmdline" in
        *" ` + ParamBootModel + `=` + BootModel + ` "*) echo diskless ;;
        *) echo disk ;;
    esac
}
`
