//go:build libvirt

package hypervisor

import (
	"bytes"
	"text/template"
)

type PreseedConfig struct {
	Locale             string
	KeyboardLayout     string
	NetworkInterface   string
	Hostname           string
	Domain             string
	AptMirrorCountry   string
	AptMirrorHost      string
	AptMirrorDirectory string
	RootPassword       string
	UserFullname       string
	Username           string
	UserPassword       string
	Disk               string
	EnableLUKS         bool
	Packages           []string
	EnableSecureBoot   bool
	EnableEFI          bool
	RootVolumeFS       string // New field for root volume file system type
	RootVolumeSize     string // New field for root volume size
	VarVolumeFS        string // New field for /var volume file system type
	VarVolumeSize      string // New field for /var volume size
}

const preseedTemplate = `
# Localization
d-i debian-installer/locale string {{.Locale}}
d-i keyboard-configuration/xkb-keymap select {{.KeyboardLayout}}

# Network configuration
d-i netcfg/choose_interface select {{.NetworkInterface}}
d-i netcfg/get_hostname string {{.Hostname}}
d-i netcfg/get_domain string {{.Domain}}

# Enable using a mirror
d-i apt-setup/use_mirror boolean true

# Configure the mirror
d-i mirror/country string manual
d-i mirror/http/hostname string {{.AptMirrorHost}}
d-i mirror/http/directory string {{.AptMirrorDirectory}}
d-i mirror/http/proxy string

# Enable contrib/non-free if you need them
d-i apt-setup/contrib boolean true
d-i apt-setup/non-free boolean true
d-i apt-setup/non-free-firmware boolean true

# User setup
d-i passwd/root-password password {{.RootPassword}}
d-i passwd/root-password-again password {{.RootPassword}}
d-i passwd/user-fullname string {{.UserFullname}}
d-i passwd/username string {{.Username}}
d-i passwd/user-password password {{.UserPassword}}
d-i passwd/user-password-again password {{.UserPassword}}

# The disk to partition
d-i partman-auto/disk string {{.Disk}}

{{- if .EnableLUKS}}
# LVM with LUKS
d-i partman-auto/method string crypto
d-i partman-crypto/passphrase string password
d-i partman-crypto/passphrase-again string password
d-i partman-crypto/weak_passphrase boolean true
d-i partman-crypto/confirm boolean true
d-i partman-auto-crypto/erase_disks boolean false
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman-auto-lvm/guided_size string max
d-i partman-auto-lvm/new_vg_name string crypt
d-i partman-auto/choose_recipe select root-crypto
d-i partman-auto/expert_recipe string \
      root-crypto :: \
              538 538 1075 free \
                    $primary{ } \
                    $iflabel{ gpt } \
                    $reusemethod{ } \
                    method{ efi } format{ } \
              . \
              256 512 512 ext2 \
                    $primary{ } \
                    $defaultignore{ } \
                    method{ format } format{ } \
                    use_filesystem{ } filesystem{ ext2 } \
                    mountpoint{ /boot } \
              . \
              8192 16384 16386 linux-swap \
                    $lvmok{ } \
                    in_vg { crypt } \
                    lv_name{ swap } \
                    method{ swap } format{ } \
              . \
              256 512 512 {{.VarVolumeFS}} \
                    $primary{ } \
                    $defaultignore{ } \
                    method{ format } format{ } \
                    use_filesystem{ } filesystem{ {{.VarVolumeFS}} } \
                    mountpoint{ /var } \
              . \
              32768 65536 131072 {{.RootVolumeFS}} \
                    $lvmok{ } lv_name{ root } \
                    in_vg { crypt } \
                    $primary{ } $bootable{ } \
                    method{ format } format{ } \
                    use_filesystem{ } filesystem{ {{.RootVolumeFS}} } \
                    mountpoint{ / } \
              . \

d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true

# Force UEFI booting ('BIOS compatibility' will be lost). Default: false.
d-i partman-efi/non_efi_system boolean false
d-i partman-partitioning/choose_label select gpt
d-i partman-partitioning/default_label string gpt
{{else}}
# Partitioning - Use entire disk (guided partitioning)
d-i partman-partitioning/choose_label string gpt
d-i partman-auto/method string regular
d-i partman-auto/choose_recipe select atomic
d-i partman-auto/confirm boolean true
d-i partman-auto/confirm_nooverwrite boolean true
d-i partman/choose_partition select finish
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
{{end}}

# Package installation
tasksel tasksel/first multiselect standard
d-i pkgsel/include string \
    {{range .Packages}} {{.}} {{end}}
d-i pkgsel/upgrade select safe-upgrade

# Bootloader installation
d-i grub-installer/bootdev string default

# Finish installation and reboot automatically
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true

# Late command to pull and run a Docker image
d-i preseed/late_command string \
    in-target apt-get install -y efitools efivar; \
    in-target which efivar || echo "Failed to install efivar"; \
    in-target mkdir -p /sys/firmware/efi/efivars; \
    in-target mount -t efivarfs efivarfs /sys/firmware/efi/efivars; \
    cp /cdrom/secure-boot-keys/* /target/boot/efi/; \
    in-target for var in $(/bin/efivar --list | grep -E "PK|KEK|db|dbx"); do \
        echo "Removing $var..."; \
        /bin/efivar -d "$var" || echo "Failed to remove $var"; \
    done; \
    in-target efi-updatevar -e -f /cdrom/secure-boot-keys/PK.auth PK || echo "Failed to enroll PK"; \
    in-target efi-updatevar -e -f /cdrom/secure-boot-keys/KEK.auth KEK || echo "Failed to enroll KEK"; \
    in-target efi-updatevar -e -f /cdrom/secure-boot-keys/DB.auth db || echo "Failed to enroll db"; \
    cp /cdrom/playbook.yaml /target/home/tpadm/; \
    mkdir -p /target/home/tpadm/.ansible /target/etc/ansible; \
    echo "[defaults]" > /target/home/tpadm/.ansible/ansible.cfg; \
    echo "inventory=/etc/ansible/hosts" >> /target/home/tpadm/.ansible/ansible.cfg; \
    echo "localhost ansible_connection=local" > /target/etc/ansible/hosts; \
    in-target mount --bind /dev/shm /target/dev/shm; \
    in-target usermod -aG sudo tpadm; \
    in-target chown -R tpadm:tpadm /home/tpadm/.ansible; \
    echo "@reboot   root    ANSIBLE_CONFIG=/home/tpadm/.ansible/ansible.cfg /usr/bin/ansible-playbook /home/tpadm/playbook.yaml -i /etc/ansible/hosts -vvv | tee -a /home/tpadm/install.log; sed -i '/@reboot/d' /etc/crontab" >> /target/etc/crontab; \
    chmod 644 /target/etc/crontab; \
    eject || true; \
    echo "eject" > /dev/virtio-ports/trusted-platform.0 || true
`

func NewPreseedConfig(config PreseedConfig) ([]byte, error) {
	tmpl, err := template.New("preseed").Parse(preseedTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, config)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
