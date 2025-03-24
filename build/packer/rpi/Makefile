RPI_OS                      ?= raspbian
RPI_KERNEL                  ?= kernel8.img
RPI_DTB                     ?= bcm2710-rpi-3-b-plus.dtb
RPI_IMAGE_NAME		        ?= trusted-platform
RPI_IMAGE_FILENAME          ?= $(RPI_IMAGE_NAME).img
RPI_SDCARD                  ?= /dev/sda
RPI_USER                    ?= pi
RPI_HOST                    ?= rpi

PACKER_BUILDER_RASPIOS64    ?= raspios-bookworm-arm64
PACKER_BUILDER_UBUNTU64     ?= ubuntu-20.04.01-arm64
PACKER_BUILDER              ?= $(PACKER_BUILDER_RASPIOS64)

PACKER_ENV_SSH_KEY          ?= /ssh-keys/id_rsa.pub
PACKER_ENV_PLATFORM_USER	?= tpadm
PACKER_ENV_PLATFORM_HOME	?= /opt/trusted-platform
PACKER_ENV_PLATFORM_BINARY  ?= platformd-static-musl-aarch64

PACKER_LOG=1


default: build


.PHONY: clean
clean:
	sudo rm -rf .packer_cache \
		packer-builder-arm \
		qemu-rpi-kernel \
		$(RPI_IMAGE_FILENAME) \
		$(RPI_KERNEL) \
		$(RPI_DTB) \
		$(PACKER_ENV_PLATFORM_BINARY)
#		~/.packer.d/plugins/packer-builder-arm

.PHONY: deps
deps:
	# Packer builder
	mkdir -p ~/.packer.d/plugins/
	sudo apt-get install packer
	git clone https://github.com/mkaczanowski/packer-builder-arm
	cd packer-builder-arm && \
		go mod download && \
		go build && \
		mv packer-builder-arm ~/.packer.d/plugins/
	rm -rf packer-builder-arm
	# qemu-rpi-kernel
	git clone https://github.com/dhruvvyas90/qemu-rpi-kernel.git


.PHONY: build
build:
	cp ../../../$(PACKER_ENV_PLATFORM_BINARY) .
	docker run \
		--rm \
		--privileged \
	 	-v ~/.ssh:/ssh-keys \
		-v /dev:/dev \
		-v $(PWD):/build \
		mkaczanowski/packer-builder-arm:latest build \
			-var ssh_key=$(PACKER_ENV_SSH_KEY) \
			-var platform_user=$(PACKER_ENV_PLATFORM_USER) \
			-var platform_home=$(PACKER_ENV_PLATFORM_HOME) \
			-var platform_version=$(PACKER_ENV_PLATFORM_VERSION) \
			-var platform_binary=$(PACKER_ENV_PLATFORM_BINARY) \
			 $(RPI_OS).json

.PHONY: qemu-deps
qemu-deps:
	@echo "Mounting image and copying kernel and DTB..."
	@LOOP_DEVICE=$$(sudo losetup --show -f -P $(RPI_IMAGE_FILENAME)); \
	BOOT_PART=$${LOOP_DEVICE}p1; \
	echo "Using boot partition $$BOOT_PART"; \
	sudo cp $$BOOT_PART/$(RPI_KERNEL) .; \
	sudo cp $$BOOT_PART/$(RPI_DTB) .; \
	sudo losetup -d $$LOOP_DEVICE; \
	echo "Kernel and DTB copied."

.PHONY: qemu
qemu:
	qemu-system-aarch64 \
		-M raspi3b \
		-cpu cortex-a53 \
		-m 1G \
		-kernel $(RPI_KERNEL) \
		-dtb $(RPI_DTB) \
		-drive "file=$(RPI_IMAGE_FILENAME),format=raw,index=0,media=disk" \
		-append cmdline="rw earlyprintk loglevel=8 console=ttyAMA0,115200 dwc_otg.lpm_enable=0 root=/dev/mmcblk0p2 rootdelay=1 systemd.run_success_action=none debug systemd.unit=kernel-command-line.target" \
		-usb \
		-device usb-mouse \
		-device usb-kbd \
		-device usb-net,netdev=net0 \
		-nographic \
		-serial mon:stdio \
		-netdev user,id=net0,hostfwd=tcp::7777-:22

.PHONY: sdcard
sdcard:
	@echo "Writing image to $(RPI_SDCARD)"
	@if [ ! -e "$(RPI_SDCARD)" ]; then \
		echo "Error: Device $(RPI_SDCARD) not found." >&2; \
		exit 1; \
	fi
	@read -p "Are you sure you want to write to $(RPI_SDCARD)? This will erase all data on the device. (y/N): " answer; \
	if [ "$$answer" != "y" ]; then \
		echo "Aborted."; \
		exit 1; \
	fi
	sudo dd if=$(RPI_IMAGE_FILENAME) of=$(RPI_SDCARD) bs=4M status=progress
	# sudo sync
	sudo eject $(RPI_SDCARD)
	@echo "Image successfully written. You may remove the sdcard and boot your device."
