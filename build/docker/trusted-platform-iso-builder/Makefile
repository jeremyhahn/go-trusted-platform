IMAGE_NAME       = trusted-platform-iso-builder
IMAGE_NAME_SWTPM = trusted-platform-iso-builder-swtpm
ISO_NAME         = trusted-platform.iso
ISO_NAME_SWTPM   = trusted-platform-swtpm.iso
ISO_NAME_DEBIAN  ?= debian-12.9.0-amd64-netinst.iso
QEMU_DISK        ?= trusted-platform.qcow2
QEMU_DISK_SWTPM  ?= trusted-platform-swtpm.qcow2
QEMU_DISK_SIZE   ?= 10G
QEMU_BRIDGE      ?= virbr0
LIBVIRT_DOMAIN   ?= trusted-platform
#QEMU_BRIDGE     := $(shell brctl show | awk 'NR > 1 {print $$1}' | head -n 1)
TPM_DEVICE       ?= /dev/tpm0

# UEFI firmware for x86_64, with Secure Boot, required SMM, SB enabled, MS certs enrolled
OVMF_CODE_MS     = /usr/share/OVMF/OVMF_CODE_4M.ms.fd
OVMF_VARS_MS     = /usr/share/OVMF/OVMF_VARS_4M.ms.fd

# UEFI firmware for x86_64, with Secure Boot, required SMM, empty varstore
OVMF_CODE_SECBOOT = /usr/share/OVMF/OVMF_CODE_4M.secboot.fd

# UEFI firmware for x86_64, without Secure Boot, optional SMM, empty varstore
OVMF_CODE        = /usr/share/OVMF/OVMF_CODE_4M.fd
OVMF_VARS        = /usr/share/OVMF/OVMF_VARS_4M.fd

ifeq ($(QEMU_BRIDGE),)
$(error No bridge found. Please configure a bridge manually or set QEMU_BRIDGE explicitly.)
endif

default: clean secure-boot-keys ansible build-all run-all

.PHONY: deps
deps:
	sudo apt-get install -y efitools sbsigntool


# Docker Build
.PHONY: build
build:
	docker buildx build --load \
	--platform linux/amd64 \
	-t $(IMAGE_NAME) .

.PHONY: build-swtpm
build-swtpm:
	docker buildx build --load \
		--platform linux/amd64 \
		--build-arg UEFI_GRUB_DEFAULT=1 \
		--build-arg BIOS_GRUB_DEFAULT=auto-install-swtpm \
		--build-arg ISO_NAME=trusted-platform-swtpm \
		-t $(IMAGE_NAME)-swtpm .

.PHONY: build-all
build-all: 
	make -j$(shell nproc) build build-swtpm

# Docker Run
.PHONY: run
run:
	docker run --rm -v $(PWD):/iso $(IMAGE_NAME)

.PHONY: run-swtpm
run-swtpm:
	docker run --rm -v $(PWD):/iso $(IMAGE_NAME)-swtpm

.PHONY: run-all
run-all: 
	make -j$(shell nproc) run run-swtpm


# Ansible
.PHONY: ansible
ansible:
	cp -R ../../ansible .


# Clean
.PHONY: clean
clean:
	-docker image rm $(IMAGE_NAME) $(IMAGE_NAME_SWTPM)
	-rm -rf *.iso *.efi *.log *.qcow2 nvram/ secure-boot-keys/ ansible/
	@echo "Cleaning up generated GPG keys..."
	@fingerprints=$$(gpg --list-keys --with-colons | awk -F: '/^pub/ {getline fpr; getline uid; if (uid ~ /grub/) print fpr}' | awk -F: '{print $$10}'); \
	for fp in $$fingerprints; do \
		echo "Deleting secret key $$fp..."; \
		gpg --batch --yes --delete-secret-keys $$fp || echo "Secret key $$fp not found or already deleted."; \
		echo "Deleting public key $$fp..."; \
		gpg --batch --yes --delete-keys $$fp || echo "Public key $$fp not found or already deleted."; \
	done
	@echo "Cleanup complete."


# Secure Boot Keys
.PHONY: secure-boot-keys
secure-boot-keys:
	mkdir -p secure-boot-keys
	cd secure-boot-keys && \
	echo "Generating UEFI keys..." && \
	if [ ! -f PK.key ]; then \
		openssl req -new -x509 -newkey rsa:2048 -subj "/CN=Platform Key/" \
			-keyout PK.key -out PK.crt -days 3650 -nodes -sha256 && \
		echo "Platform Key generated."; \
	else \
		echo "Platform Key already exists."; \
	fi && \
	if [ ! -f KEK.key ]; then \
		openssl req -new -x509 -newkey rsa:2048 -subj "/CN=Key Exchange Key/" \
			-keyout KEK.key -out KEK.crt -days 3650 -nodes -sha256 && \
		echo "KEK generated."; \
	else \
		echo "KEK already exists."; \
	fi && \
	if [ ! -f DB.key ]; then \
		openssl req -new -x509 -newkey rsa:2048 -subj "/CN=Database Key/" \
			-keyout DB.key -out DB.crt -days 3650 -nodes -sha256 && \
		echo "Database Key generated."; \
	else \
		echo "Database Key already exists."; \
	fi && \
	echo "Converting certificates to EFI signature list format..." && \
	cert-to-efi-sig-list PK.crt PK.esl && \
	cert-to-efi-sig-list KEK.crt KEK.esl && \
	cert-to-efi-sig-list DB.crt DB.esl && \
	echo "Creating authenticated UEFI variable signature files..." && \
	sign-efi-sig-list -k PK.key -c PK.crt PK PK.esl PK.auth && \
	sign-efi-sig-list -k PK.key -c PK.crt KEK KEK.esl KEK.auth && \
	sign-efi-sig-list -k KEK.key -c KEK.crt db DB.esl DB.auth && \
	echo "Generating GRUB GPG key..." && \
	if ! gpg --list-secret-keys --with-colons | grep -q '^sec:.*grub'; then \
		echo "%no-protection\nKey-Type: RSA\nKey-Length: 4096\nName-Real: grub\nName-Comment: Key for signing GRUB files\nExpire-Date: 0\n%commit" > grub_gpg_params; \
		gpg --batch --full-gen-key grub_gpg_params; \
		rm grub_gpg_params; \
		echo "GRUB GPG key generated."; \
	else \
		echo "GRUB GPG key already exists."; \
	fi && \
	echo "Exporting GRUB GPG public key..." && \
	gpg --armor --export grub > grub_public_key && \
	echo "GRUB GPG public key exported to secure-boot-keys/grub_public_key." && \
	echo "Exporting GRUB GPG secret key..." && \
	gpg --armor --export-secret-keys grub > grub_secret_key.asc && \
	echo "GRUB GPG secret key exported to secure-boot-keys/grub_secret_key.asc." && \
	echo "Secure Boot keys generated successfully."


# QEMU
.PHONY: qemu-bridge
qemu-bridge:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Must be root to run this target" >&2; \
		exit 1; \
	fi
	@echo "allow $(QEMU_BRIDGE)" > /etc/qemu/bridge.conf
	@echo "Using bridge: $(QEMU_BRIDGE)"

.PHONY: qemu-install-all
qemu-install-all: 
	$(MAKE) qemu-install &
	$(MAKE) qemu-install-uefi &
	$(MAKE) qemu-install-uefi-sb &
	$(MAKE) qemu-install-uefi-sb-ms &
	$(MAKE) qemu-install-swtpm &


# Install :: Legacy BIOS
.PHONY: qemu-install
qemu-install:
	qemu-img create -f qcow2 $(QEMU_DISK) $(QEMU_DISK_SIZE)
	sudo chown $(USER):$(USER) $(TPM_DEVICE)
	touch /tmp/cancel
	qemu-system-x86_64 \
		-enable-kvm \
		-m 2048 \
		-cpu host \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-boot order=c \
		-cdrom $(ISO_NAME) \
		-vga virtio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0

# Install :: UEFI w/ TPM w/o secure boot
.PHONY: qemu-install-uefi
qemu-install-uefi:
	@mkdir -p ./nvram
	@touch /tmp/cancel
	@qemu-img create -f qcow2 $(QEMU_DISK) $(QEMU_DISK_SIZE)
	@sudo chown $(USER):$(USER) $(TPM_DEVICE) || echo "Warning: Could not change ownership of TPM devices."
	cp $(OVMF_VARS) ./nvram/OVMF_VARS.fd
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-boot order=d \
		-cdrom $(ISO_NAME) \
		-vga virtio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0

# Install :: UEFI w/ TPM and Secure Boot (custom keys)
.PHONY: qemu-install-uefi-sb
qemu-install-uefi-sb:
	@mkdir -p ./nvram
	@touch /tmp/cancel
	@qemu-img create -f qcow2 $(QEMU_DISK) $(QEMU_DISK_SIZE)
	@sudo chown $(USER):$(USER) $(TPM_DEVICE) || echo "Warning: Could not change ownership of TPM devices."
	cp $(OVMF_VARS) ./nvram/OVMF_VARS.fd
	chmod 666 ./nvram/OVMF_VARS.fd
	virt-fw-vars --inplace ./nvram/OVMF_VARS.fd \
		--set-pk "$(shell uuidgen)" secure-boot-keys/PK.crt \
		--add-kek "$(shell uuidgen)" secure-boot-keys/KEK.crt \
		--add-db "$(shell uuidgen)" secure-boot-keys/DB.crt \
		--append-boot-filepath "\\EFI\\Trusted\\kernel.efi" \
		--secure-boot \
		--microsoft-kek none \
		--no-microsoft
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_SECBOOT) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-boot order=d \
		-cdrom $(ISO_NAME) \
		-vga virtio \
		-serial mon:stdio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
		-device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on

# Install :: UEFI w/ TPM and secure boot (Microsoft signing certs)
.PHONY: qemu-install-uefi-sb-ms
qemu-install-uefi-sb-ms:
	@mkdir -p ./nvram
	@touch /tmp/cancel
	@qemu-img create -f qcow2 $(QEMU_DISK) $(QEMU_DISK_SIZE)
	@sudo chown $(USER):$(USER) $(TPM_DEVICE) || echo "Warning: Could not change ownership of TPM devices."
	cp $(OVMF_VARS_MS) ./nvram/OVMF_VARS.fd
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_MS) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-boot order=d \
		-cdrom $(ISO_NAME) \
		-vga virtio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on

# Install :: Legacy BIOS w/ Software TPM
.PHONY: qemu-install-swtpm
qemu-install-swtpm:
	@mkdir -p ./nvram
	@touch /tmp/cancel
	@qemu-img create -f qcow2 $(QEMU_DISK_SWTPM) $(QEMU_DISK_SIZE)
	@sudo chown $(USER):$(USER) $(TPM_DEVICE) || echo "Warning: Could not change ownership of TPM devices."
	cp $(OVMF_VARS_MS) ./nvram/OVMF_VARS-swtpm.fd
	-killall swtpm
	swtpm socket --tpmstate dir=/tmp --ctrl type=unixio,path=/tmp/swtpm-sock --log level=20 --tpm2 &
	sleep 2
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK_SWTPM),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_SECBOOT) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS-swtpm.fd \
		-boot order=d \
		-cdrom $(ISO_NAME_SWTPM) \
		-vga virtio \
		-chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
	 	-tpmdev emulator,id=tpm0,chardev=chrtpm \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on


# Run :: Legacy BIOS w/ TPM
.PHONY: qemu-run
qemu-run:
	touch /tmp/cancel
	qemu-system-x86_64 \
		-enable-kvm \
		-m 2048 \
		-cpu host \
		-netdev bridge,id=net0,br=$(QEMU_BRIDGE) \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-vga virtio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0

# Run :: UEFI w/o secure boot
.PHONY: qemu-run-uefi
qemu-run-uefi:
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-vga virtio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0

# Run :: UEFI w/ TPM & secure boot
.PHONY: qemu-run-uefi-sb
qemu-run-uefi-sb:
	touch /tmp/cancel
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_SECBOOT) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-vga virtio \
		-serial mon:stdio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on


# Run :: Direct Kernel Boot :: UEFI w/ TPM & secure boot
.PHONY: qemu-run-uefi-sb-direct
qemu-run-uefi-sb-direct:
	sudo mkdir -p /mnt/trusted-platform-os
	sudo chown $(USER) /mnt/trusted-platform-os
#	guestmount -a trusted-platform.qcow2 -i --ro /mnt/trusted-platform-os
	touch /tmp/cancel
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_SECBOOT) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-vga virtio \
		-serial mon:stdio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on \
		-kernel uki.signed.efi

# -kernel /mnt/trusted-platform-os/boot/vmlinuz-6.1.0-31-amd64 \
# -initrd /mnt/trusted-platform-os/boot/initrd.img-6.1.0-31-amd64 \
# -append "root=/dev/vda2"
# -append "root=LABEL=trusted-rootfs"

# Run :: UEFI w/ TPM & secure boot, and Microsoft signing certs
.PHONY: qemu-run-uefi-sb-ms
qemu-run-uefi-sb-ms:
	touch /tmp/cancel
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=$(shell nproc),threads=1 \
		-m 4096 \
		-usb \
		-device usb-tablet \
		-device virtio-vga \
		-netdev bridge,id=net0,br=virbr0 \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_MS) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS.fd \
		-vga virtio \
		-tpmdev passthrough,id=tpm0,path=$(TPM_DEVICE),cancel-path=/tmp/cancel \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on

# Run :: Legacy BIOS w/ Software TPM
.PHONY: qemu-run-swtpm
qemu-run-swtpm:
	swtpm socket --tpmstate dir=/tmp --ctrl type=unixio,path=/tmp/swtpm-sock --log level=20 --tpm2 &
	qemu-system-x86_64 \
		-d guest_errors \
		-D qemu.log \
		-enable-kvm \
		-machine q35,smm=on \
		-cpu host \
		-smp cores=4,threads=1 \
		-m 4096 \
		-netdev bridge,id=net0,br=$(QEMU_BRIDGE) \
		-device virtio-net-pci,netdev=net0 \
		-drive file=$(QEMU_DISK_SWTPM),if=virtio,cache=writeback \
		-drive if=pflash,unit=0,format=raw,readonly=on,file=$(OVMF_CODE_SECBOOT) \
		-drive if=pflash,unit=1,format=raw,file=./nvram/OVMF_VARS-swtpm.fd \
		-vga virtio \
		-chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
		-tpmdev emulator,id=tpm0,chardev=chrtpm \
		-device tpm-tis,tpmdev=tpm0 \
		-object rng-random,filename=/dev/urandom,id=rng0 \
		-device virtio-rng-pci,rng=rng0 \
		-global driver=cfi.pflash01,property=secure,value=on

.PHONY: qemu-run-all
qemu-run-all:
	$(MAKE) qemu-run
	$(MAKE) qemu-run-uefi
	$(MAKE) qemu-run-uefi-sb
	$(MAKE) qemu-run-uefi-sb-ms
	$(MAKE) qemu-run-swtpm


# Libvirt targets
.PHONY: virsh-install
virsh-run:
	touch /tmp/cancel
	virsh define $(LIBVIRT_DOMAIN).xml
	virsh start $(LIBVIRT_DOMAIN)

.PHONY: virsh-install-swtpm
virsh-clean:
	-virsh destroy $(LIBVIRT_DOMAIN)
	-virsh undefine $(LIBVIRT_DOMAIN)

.PHONY: virsh-install-swtpm
virsh-list:
	virsh list --all

.PHONY: virsh-install-swtpm
virt-viewer:
	virt-viewer $(LIBVIRT_DOMAIN)

.PHONY: virsh-install-swtpm
virt-console:
	virsh console $(LIBVIRT_DOMAIN)


# QEMU qcow2 mount / unmount
.PHONY: guestmount
guestmount:
	mkdir -p /mnt/$(QEMU_DISK)
	guestmount -a $(QEMU_DISK) -i --ro /mnt/$(QEMU_DISK)

.PHONY: guestumount
guestumount:
	sudo umount /mnt/$(QEMU_DISK)
	sudo rm -rf /mnt/$(QEMU_DISK)
