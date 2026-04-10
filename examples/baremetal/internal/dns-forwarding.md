# DNS Forwarding Setup

This guide shows how to forward DNS queries from standard port 53 to go-trusted-platform DNS on port 8053.

## Option 1: systemd-resolved (Recommended for modern Linux)

```bash
# Configure split DNS for .internal domain
sudo resolvectl dns <interface> 182.168.xxx.xxx
sudo resolvectl domain <interface> "~internal"
sudo resolvectl default-route <interface> no

# Or use a drop-in config file
sudo mkdir -p /etc/systemd/resolved.conf.d/
sudo tee /etc/systemd/resolved.conf.d/internal.conf << EOF
[Resolve]
DNS=182.168.xxx.xxx:8053
Domains=~internal
EOF

sudo systemctl restart systemd-resolved
```

## Option 2: dnsmasq (Lightweight forwarder)

```bash
# Install dnsmasq
sudo apt-get install dnsmasq

# Configure forwarding for .internal
sudo tee /etc/dnsmasq.d/internal.conf << EOF
# Forward .internal queries to go-trusted-platform
server=/internal/182.168.xxx.xxx#8053

# Optionally, disable DHCP
no-dhcp-interface=

# Listen on standard DNS port
port=53
EOF

sudo systemctl restart dnsmasq
```

## Option 3: BIND9 (Full DNS server)

```bash
# Install BIND9
sudo apt-get install bind9

# Configure forwarding zone
sudo tee /etc/bind/named.conf.local << EOF
zone "internal" {
    type forward;
    forward only;
    forwarders { 182.168.xxx.xxx port 8053; };
};
EOF

sudo systemctl restart bind9
```

## Option 4: iptables NAT (Port redirect)

```bash
# Redirect local DNS queries to port 8053
sudo iptables -t nat -A OUTPUT -p udp --dport 53 -d 182.168.xxx.xxx \
    -j REDIRECT --to-port 8053
sudo iptables -t nat -A OUTPUT -p tcp --dport 53 -d 182.168.xxx.xxx \
    -j REDIRECT --to-port 8053

# For external clients
sudo iptables -t nat -A PREROUTING -p udp --dport 53 \
    -j REDIRECT --to-port 8053
sudo iptables -t nat -A PREROUTING -p tcp --dport 53 \
    -j REDIRECT --to-port 8053

# Make persistent
sudo apt-get install iptables-persistent
sudo netfilter-persistent save
```

## Option 5: socat (Simple forwarder)

```bash
# Install socat
sudo apt-get install socat

# Create systemd service
sudo tee /etc/systemd/system/dns-forwarder.service << EOF
[Unit]
Description=DNS Forwarder to go-trusted-platform
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/socat UDP4-LISTEN:53,fork,reuseaddr UDP4:182.168.xxx.xxx:8053
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now dns-forwarder
```

## Testing

```bash
# Test resolution
dig @localhost server.internal
dig @localhost client-001.internal

# Check which resolver is being used
resolvectl status
```

## Recommendations

1. **For development**: Use systemd-resolved with split DNS
2. **For production**: Use dnsmasq or BIND9 for more control
3. **For containers**: Use iptables NAT rules
4. **For quick testing**: Use socat

Choose based on your environment and requirements.