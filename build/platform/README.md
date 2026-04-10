# Hardware Platform Deployment

This directory contains hardware-specific platform deployment configurations for go-trusted-platform.

## Overview

While `build/iso/` contains ISO builders for creating installation media, this directory (`build/platform/`) contains deployment configurations and tooling for specific hardware platforms and deployment scenarios.

## Purpose

Hardware platforms differ from ISO builds in several key ways:

- **ISOs** (`build/iso/`): Generic installation media for any compatible hardware
- **Platforms** (`build/platform/`): Hardware-specific configurations and deployment automation

## Platform Types

### Bare Metal
Deployment configurations for specific server hardware:
- Dell PowerEdge servers
- HP ProLiant servers
- Supermicro servers
- Custom hardware builds

### Edge Devices
Specialized configurations for edge computing:
- Raspberry Pi (ARM)
- Intel NUC
- NVIDIA Jetson
- Industrial PCs

### Cloud Instances
Cloud provider-specific deployments:
- AWS EC2 with vTPM
- Azure with TPM 2.0
- GCP with vTPM
- Private cloud (OpenStack, etc.)

### Virtualization
Hypervisor-specific configurations:
- KVM/QEMU with swtpm
- VMware with vTPM
- Hyper-V with vTPM
- Xen

## Directory Structure

```
build/platform/
├── README.md              # This file
├── baremetal/             # Bare metal servers
│   ├── dell-poweredge/
│   ├── hp-proliant/
│   └── supermicro/
├── edge/                  # Edge devices
│   ├── raspberry-pi/
│   ├── intel-nuc/
│   └── nvidia-jetson/
├── cloud/                 # Cloud instances
│   ├── aws/
│   ├── azure/
│   └── gcp/
└── virtual/               # Virtualization
    ├── kvm/
    ├── vmware/
    └── hyperv/
```

## How It Differs from ISOs

### ISO Builds (`build/iso/`)
- **Purpose**: Create bootable installation media
- **Target**: Any compatible hardware
- **Format**: ISO image
- **Usage**: Boot from USB/CD, run installer
- **Example**: Alpine Linux ISO with platform-initrd

### Platform Deployments (`build/platform/`)
- **Purpose**: Deploy to specific hardware/environment
- **Target**: Known hardware configuration
- **Format**: Ansible playbooks, Terraform configs, scripts
- **Usage**: Automated deployment via network/management tools
- **Example**: PXE boot to specific Dell server model

## Use Cases

### Example: Bare Metal Deployment
```
build/platform/baremetal/dell-poweredge/
├── Makefile
├── ansible/
│   ├── inventory.yml
│   └── deploy.yml
├── configs/
│   └── platform-config.yaml
└── README.md
```

Purpose: Deploy to Dell PowerEdge R740 servers with:
- BIOS-specific TPM settings
- RAID controller configuration
- iDRAC management integration
- Hardware-specific kernel parameters

### Example: Raspberry Pi Edge
```
build/platform/edge/raspberry-pi/
├── Makefile
├── boot-config.txt
├── kernel-cmdline.txt
└── README.md
```

Purpose: Deploy to Raspberry Pi 4 with:
- ARM64-specific kernel
- GPIO TPM module support
- Boot partition configuration
- Performance tuning for ARM

## Relationship to Ansible Playbooks

The existing Ansible playbooks in `build/ansible/` can be used as a foundation:
- `build/ansible/playbooks/baremetal.yml` → Platform-specific variants
- `build/ansible/playbooks/docker.yml` → Container orchestration
- `build/ansible/playbooks/k8s.yaml` → Kubernetes deployment

Platform-specific deployments extend these with:
- Hardware-specific variables
- Vendor management tools
- Performance tuning
- Monitoring/alerting

## Getting Started

### Creating a New Platform

1. Choose the platform category (baremetal/edge/cloud/virtual)
2. Create a directory for your specific hardware
3. Include:
   - `README.md` - Hardware requirements and setup
   - `Makefile` - Build and deployment targets
   - Configuration files specific to the hardware
   - Deployment automation (Ansible/Terraform/scripts)

### Example Platform Structure
```bash
mkdir -p build/platform/baremetal/dell-poweredge
cd build/platform/baremetal/dell-poweredge

# Create README with hardware specs
cat > README.md << 'EOF'
# Dell PowerEdge R740 Deployment

## Hardware Requirements
- Dell PowerEdge R740
- TPM 2.0 module installed
- UEFI firmware with Secure Boot
- Network PXE boot capability
EOF

# Create Makefile with deployment targets
cat > Makefile << 'EOF'
.PHONY: deploy
deploy:
	ansible-playbook -i inventory.yml deploy.yml
EOF
```

## Common Platform Operations

### PXE Network Boot
Many platforms use PXE boot for deployment:
1. DHCP/TFTP server configuration
2. iPXE or GRUB network boot loader
3. Automated installation via Kickstart/Preseed
4. Post-install configuration management

### Configuration Management
Most platforms include:
- Hardware discovery and inventory
- Automated OS installation
- TPM provisioning and key sealing
- Security hardening
- Monitoring agent deployment

### Testing
Platform deployments should include:
- Hardware compatibility verification
- TPM functionality tests
- Performance benchmarks
- Security validation

## Integration with ISO Builds

Platform deployments often use ISO builds as a starting point:

1. Build Alpine ISO with platform-initrd:
   ```bash
   cd build/iso/alpine
   make iso-amd64
   ```

2. Deploy to platform using automation:
   ```bash
   cd build/platform/baremetal/dell-poweredge
   make deploy ISO=/path/to/alpine.iso
   ```

## Future Platforms

Planned platform support:
- [ ] Dell PowerEdge servers
- [ ] HP ProLiant servers
- [ ] Raspberry Pi (various models)
- [ ] AWS EC2 with Nitro TPM
- [ ] Azure VMs with vTPM
- [ ] Google Cloud with vTPM
- [ ] NVIDIA Jetson edge devices

## Contributing

To add a new platform:
1. Create the directory structure
2. Document hardware requirements
3. Provide deployment automation
4. Include testing instructions
5. Update this README

## Related Documentation

- **ISO Builds**: `build/iso/alpine/README.md`
- **Ansible Playbooks**: `build/ansible/README.md`
- **Platform-Initrd**: `docs/PLATFORM-INITRD.md`
- **Architecture**: `docs/ARCHITECTURE-REF.md`

## License

Part of the go-trusted-platform project.
See the main project LICENSE file for details.
