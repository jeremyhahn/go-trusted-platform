ISODIR         ?= volume/iso
IMAGE_NAME     ?= pxe-server
CONTAINER_NAME ?= pxe-server
NETWORK_NAME   ?= pxe-net
SUBNET         ?= 192.168.50.0/24
IP_RANGE       ?= 192.168.50.0/25
GATEWAY        ?= 192.168.50.1
STATIC_IP      ?= 192.168.50.100
QEMU_DISK      ?= debian12.qcow2
QEMU_DISK_SIZE ?= 5G
QEMU_BRIDGE    ?= br-3114e390c8a6

DEBIAN_URL     ?= https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-12.8.0-amd64-netinst.iso
VYOS_URL       ?= https://github.com/vyos/vyos-nightly-build/releases/download/1.5-rolling-202412100007/vyos-1.5-rolling-202412100007-generic-amd64.iso

MIRROR         ?= deb.debian.org
ARCH           ?= amd64
DIST           ?= stable

default: load pxe-server

.PHONY: init
init:
	@echo "Initializing directories..."
	mkdir -p $(ISODIR)

	# Download the necessary files
	wget http://$(MIRROR)/debian/dists/$(DIST)/main/installer-"$(ARCH)"/current/images/netboot/netboot.tar.gz -P $(ISODIR)
	wget http://$(MIRROR)/debian/dists/$(DIST)/main/installer-"$(ARCH)"/current/images/SHA256SUMS -P $(ISODIR)
	wget http://$(MIRROR)/debian/dists/$(DIST)/Release -P $(ISODIR)
	wget http://$(MIRROR)/debian/dists/$(DIST)/Release.gpg -P $(ISODIR)

	# Import the Debian 12 archive key (archive-key-12.asc)
	curl -fsSL http://ftp.debian.org/debian-archive/keys/archive-key-12.asc | gpg --dearmor -o /usr/share/keyrings/debian-archive-keyring.gpg

	# Verify the checksum of netboot.tar.gz and the SHA256SUMS file
	@echo "Verifying checksums..."
	cd $(ISODIR) || exit

	# Verify netboot.tar.gz checksum
	grep 'netboot/netboot.tar.gz' SHA256SUMS | sha256sum -c - || { echo "Checksum verification for netboot.tar.gz failed."; exit 1; }

	# Verify SHA256SUMS checksum
	grep "main/installer-$(ARCH)/current/images/SHA256SUMS" Release | sha256sum -c - || { echo "Checksum verification for SHA256SUMS failed."; exit 1; }

	# Verify GPG signature of the Release file
	gpg --keyring /usr/share/keyrings/debian-archive-keyring.gpg --verify Release.gpg Release || { echo "GPG signature verification failed."; exit 1; }

	@echo "Download and verification completed successfully!"


.PHONY: build
build:
	docker build --load \
		--platform=linux/amd64 \
		-t $(IMAGE_NAME) .
	docker build --load \
		--platform=linux/arm64 \
		-t $(IMAGE_NAME) .

.PHONY: push
push: 
	docker build --push \
		--platform=linux/amd64,linux/arm64 \
		-t jeremyhahn/$(IMAGE_NAME) .

.PHONY: pxe-server
pxe-server:
	@docker network inspect $(NETWORK_NAME) >/dev/null 2>&1 || docker network create \
		--driver=bridge \
		--subnet=$(SUBNET) \
		--ip-range=$(IP_RANGE) \
		--gateway=$(GATEWAY) \
		$(NETWORK_NAME)
	docker run -d --name $(CONTAINER_NAME) \
		--network $(NETWORK_NAME) \
		--ip=$(STATIC_IP) \
		-v $(PWD)/$(ISODIR):/var/www/html/isos \
		-p 69:69/udp -p 80:80 -p 2049:2049 \
		$(IMAGE_NAME)

.PHONY: redeploy
redeploy:
	@docker rm $(CONTAINER_NAME) --force
	@$(MAKE) run
	docker logs $(CONTAINER_NAME)

.PHONY: clean
clean:
	@echo "Cleaning up all ISOs and configurations..."
	@sudo rm -rf $(ISODIR)/*
	@docker rm -f $(CONTAINER_NAME) || true
	@docker rmi -f $(IMAGE_NAME) || true
	@echo "Deleting $(NETWORK_NAME)..."
	@docker network rm $(NETWORK_NAME) || true

.PHONY: qemu-bridge
qemu-bridge:
	echo "allow $(QEMU_BRIDGE)" > /etc/qemu/bridge.conf

.PHONY: qemu-install
qemu-install:
	qemu-img create -f qcow2 $(QEMU_DISK) $(QEMU_DISK_SIZE)
	qemu-system-x86_64 \
		-enable-kvm \
		-m 2048 \
		-cpu host \
		-netdev bridge,id=net0,br=$(QEMU_BRIDGE) \
		-device rtl8139,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-boot order=n,menu=on \
		-vga virtio

.PHONY: qemu-run
qemu-run:
	qemu-system-x86_64 \
		-enable-kvm \
		-m 2048 \
		-cpu host \
		-netdev bridge,id=net0,br=$(QEMU_BRIDGE) \
		-device rtl8139,netdev=net0 \
		-drive file=$(QEMU_DISK),if=virtio,cache=writeback \
		-boot order=c \
		-vga virtio

# qemu-img create -f qcow2 rpios64-lite.qcow2 8G
.PHONY: qemu-rpi
qemu-rpi:
	qemu-system-aarch64 \
		-M virt \
		-smp 6 \
		-m 4G \
		-cpu cortex-a72 \
		-kernel ./volume/iso/rpios64-lite/kernel8.img \
		-initrd ./volume/iso/rpios64-lite/initramfs8 \
		-drive file=rpios64-lite.qcow2,format=qcow2 \
		-append "root=/dev/mmcblk0p2 rw ip=dhcp rootwait console=ttyAMA0" \
		-net nic \
		-net user \
		-netdev user,id=mynet,hostfwd=tcp::2222-:22 \
		-serial mon:stdio \
		-device virtio-net-pci \
		-display sdl
# 		-serial telnet:localhost:4321,server,nowait \

# qemu-system-aarch64 \
# 	-M virt,highmem=off \
# 	-smp 8 \
# 	-m 2G \
# 	-cpu cortex-a72 \
# 	-kernel linux-stable/arch/arm64/boot/Image \
# 	-append root=PARTUUID=d97f5830-02 rw console=ttyAMA0 \
# 	-serial telnet:localhost:4321,server,nowait \
# 	-monitor telnet:localhost:4322,server,nowait \
# 	-device VGA,id=vga1 \
# 	-device secondary-vga,id=vga2 \
# 	-object iothread,id=io1 \
# 	-device virtio-blk-pci,drive=disk0,iothread=io1 \
# 	-drive data/images/2022-01-28-raspios-bullseye-arm64.img