# Running DNS on Port 53 Without Root

## Option 1: CAP_NET_BIND_SERVICE (Recommended)

Give the binary capability to bind to privileged ports:

```bash
# Set capability on the binary
sudo setcap 'cap_net_bind_service=+ep' /path/to/platformd

# Verify capability is set
getcap /path/to/platformd

# Run as normal user
./platformd serve
```

**Pros**: Clean, specific permission, follows principle of least privilege
**Cons**: Capability is lost if binary is replaced/rebuilt

## Option 2: Systemd Socket Activation

Create systemd socket unit that binds to port 53:

```ini
# /etc/systemd/system/platformd-dns.socket
[Unit]
Description=Trusted Platform DNS Socket

[Socket]
ListenDatagram=53
ListenStream=53

[Install]
WantedBy=sockets.target
```

```ini
# /etc/systemd/system/platformd.service
[Unit]
Description=Trusted Platform
Requires=platformd-dns.socket

[Service]
Type=simple
User=platformd
Group=platformd
ExecStart=/usr/local/bin/platformd serve
StandardInput=socket

[Install]
WantedBy=multi-user.target
```

**Pros**: Most secure, systemd manages the socket
**Cons**: Requires systemd, more complex setup

## Option 3: authbind

```bash
# Install authbind
sudo apt-get install authbind

# Configure port 53
sudo touch /etc/authbind/byport/53
sudo chown platformd:platformd /etc/authbind/byport/53
sudo chmod 755 /etc/authbind/byport/53

# Run with authbind
authbind --deep ./platformd serve
```

**Pros**: Simple, per-port control
**Cons**: External dependency, slight overhead

## Option 4: sysctl for non-root bind

```bash
# Allow binding to privileged ports from 1-1024
sudo sysctl net.ipv4.ip_unprivileged_port_start=53

# Make permanent
echo 'net.ipv4.ip_unprivileged_port_start=53' | sudo tee /etc/sysctl.d/50-unprivileged-ports.conf

# Run as normal user
./platformd serve
```

**Pros**: Simple, no external tools
**Cons**: Allows ANY process to bind to ports ≥53

## Option 5: iptables REDIRECT

```bash
# Run DNS on 8053, redirect 53 to 8053
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 8053
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 8053
```

**Pros**: No changes to app, works with existing setup
**Cons**: Additional complexity, requires iptables

## Recommended Implementation

For go-trusted-platform, I recommend:

1. **Development**: Use CAP_NET_BIND_SERVICE for simplicity
2. **Production**: Use systemd socket activation for security
3. **Containers**: Use CAP_NET_BIND_SERVICE or run as root (container isolated)

### Configuration

The go-trusted-platform DNS ports are fully configurable. You can set custom DNS ports either during config generation or by editing the YAML config file.

#### Option 1: Using config gen (Recommended)

```bash
platformd config gen \
  --dns-public-port 53 \
  --dns-internal-port 53 \
  # ... other flags
```

#### Option 2: Manual Configuration

Edit the generated config.yaml to change from the default ports (8053/8054) to port 53:

```yaml
dns:
  public:
    port: 53  # Changed from default 8053
    zone:
      name: example.com.
  internal:  
    port: 53  # Changed from default 8054
    zone:
      name: internal.
```

### Makefile Helper

```makefile
.PHONY: setcap
setcap:
	@echo "Setting capability to bind port 53..."
	@sudo setcap 'cap_net_bind_service=+ep' $(APPBIN)
	@echo "✓ Done. platformd can now bind to port 53 as normal user"
```

This would make the internal DNS example much cleaner - no forwarding needed!