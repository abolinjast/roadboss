This is what i created in order to learn eBPF/XDP and see what differences does it make than using nftables and Netfilter

Requirements
go
ubuntu/debian

run
```bash
sudo apt install clang llvm libbpf-dev
```

and then
```bash
go generate ./cmd/roadboss
go build -o roadboss ./cmd/roadboss
```

# Modes
Native mode is the one that sees the frame before an sk_buff exists. Generic mode runs later, after that buffer has already been allocated.

Native (-mode native, XDPDriverMode) is a hook inside the NIC driver. The driver has the frame in an xdp_buff and calls your program before build_skb. XDP_DROP frees the frame there. The allocation never happens. The driver has to implement this. veth on a current Ubuntu kernel does.

Generic (-mode generic, XDPGenericMode) is the kernel's compatibility path, also called SKB mode. The receive path allocates the sk_buff first, then wraps that buffer in an xdp_buff and runs the same program. XDP_DROP still throws the packet away, but the cost of building the sk_buff has already been paid. That is the mode used when the driver has no native XDP support.

In our go code in the attachXDP function, native tries the driver hook and, if that attach fails, tries generic. generic does not try the driver hook. The program and the maps are the same either way. Only the place in the receive path changes.

# Test
you can test roadboss via these commands with the script in the test folder
```bash
sudo bash test/test_roadboss.sh create
sudo bash test/test_roadboss.sh block
sudo bash test/test_roadboss.sh destroy
```
