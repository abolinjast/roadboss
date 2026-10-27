#!/bin/bash

set -euo pipefail

cfg=/etc/roadboss/config.yaml

if [ "$1" == "create" ]; then

    sudo rm -f "$cfg"
    sudo ip netns add roadbosstest
    sudo ip link add veth0 type veth peer name veth1
    sudo ip link set veth1 netns roadbosstest
    sudo ip link set veth0 up
    sudo ip addr add 10.198.0.1/24 dev veth0
    sudo ip netns exec roadbosstest ip link set veth1 up
    sudo ip netns exec roadbosstest ip addr add 10.198.0.2/24 dev veth1

    sudo ./roadboss attach -iface veth0 -mode native
    sudo ip netns exec roadbosstest ping -c 3 10.198.0.1
    sudo ./roadboss stats -iface veth0

elif [ "$1" = "block" ]; then
    sudo mkdir -p /etc/roadboss
    sudo tee "$cfg" >/dev/null <<'EOF'
iface: veth0
syn_pps: 0
udp_pps: 0
blocklist:
  - 10.198.0.2
EOF

    sudo ./roadboss detach -iface veth0
    sudo ./roadboss attach -iface veth0 -mode native
    if sudo ip netns exec roadbosstest ping -c 3 -W 1 10.198.0.1; then
        echo "ping succeeded, blocklist was not applied" >&2
        exit 1
    fi
    sudo ./roadboss stats -iface veth0

elif [ "$1" == "destroy" ]; then
    sudo ./roadboss detach -iface veth0
    sudo ip netns delete roadbosstest
    sudo rm -f "$cfg"

fi