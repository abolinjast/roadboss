package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -Wall -I/usr/include/x86_64-linux-gnu" -type limits_cfg -type source_rate filter ../../bpf/xdp_filter.c

func main() {}
