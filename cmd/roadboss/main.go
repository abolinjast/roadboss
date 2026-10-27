package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"encoding/binary"

	"gopkg.in/yaml.v3"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-O2 -Wall -I/usr/include/x86_64-linux-gnu" -type limits_cfg -type source_rate filter ../../bpf/xdp_filter.c

const (
	statPass = iota
	statDropBlocklist
	statDropSyn
	statDropUdp
	statDropFull
	statMax
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "spec":
		err = showSpec()
	case "attach":
		err = attach(os.Args[2:])
	case "detach":
		err = detach(os.Args[2:])
	case "stats":
		err = stats(os.Args[2:])
	case "block":
		err = block(os.Args[2:])
	case "unblock":
		err = unblock(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
	case "limits":
		err = limits(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: roadboss spec\n")
	fmt.Fprintf(os.Stderr, "       roadboss attach -iface NAME [-mode native|generic]\n")
	fmt.Fprintf(os.Stderr, "       roadboss detach -iface NAME\n")
	fmt.Fprintf(os.Stderr, "       roadboss stats -iface NAME\n")
	fmt.Fprintf(os.Stderr, "       roadboss block -iface NAME ADDRESS\n")
	fmt.Fprintf(os.Stderr, "       roadboss unblock -iface NAME ADDRESS\n")
	fmt.Fprintf(os.Stderr, "       roadboss list -iface NAME\n")
	fmt.Fprintf(os.Stderr, "       roadboss limits -iface NAME [-syn N] [-udp N]\n")

}

func showSpec() error {
	spec, err := loadFilter()
	if err != nil {
		return err
	}
	fmt.Println("program:", filterProgXdpFilter)
	for name := range spec.Maps {
		fmt.Println("map:", name)
	}
	return nil
}

func pinDir(iface string) string {
	return filepath.Join("/sys/fs/bpf/roadboss", iface)
}

const configPath = "/etc/roadboss/config.yaml"

type savedConfig struct {
	Iface     string   `yaml:"iface"`
	SynPPS    uint32   `yaml:"syn_pps"`
	UDPPPS    uint32   `yaml:"udp_pps"`
	Blocklist []string `yaml:"blocklist"`
}

func ipKey(s string) (uint32, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return 0, fmt.Errorf("%s is not an IPv4 address", s)
	}
	return binary.LittleEndian.Uint32(ip), nil
}

func ipFromKey(k uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], k)
	return net.IP(b[:]).String()
}

func perCPU(global uint32) (uint32, error) {
	if global == 0 {
		return 0, nil
	}
	n, err := ebpf.PossibleCPU()
	if err != nil {
		return 0, err
	}
	if n < 1 {
		n = 1
	}
	v := global / uint32(n)
	if v == 0 {
		v = 1
	}
	return v, nil
}

func loadSaved() (savedConfig, error) {
	data, err := os.ReadFile(configPath)
	if errors.Is(err, os.ErrNotExist) {
		return savedConfig{}, nil
	}
	if err != nil {
		return savedConfig{}, err
	}
	var cfg savedConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return savedConfig{}, err
	}
	return cfg, nil
}

func storeSaved(cfg savedConfig) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return err
	}
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0o644)
}

func block(args []string) error {
	fs := flag.NewFlagSet("block", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("block requires -iface")

	}
	if fs.NArg() != 1 {
		return errors.New("block requires an IPv4 address")
	}
	addr := fs.Arg(0)
	key, err := ipKey(addr)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir(*iface), "blocklist"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	if err := m.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
		return err
	}
	cfg, err := loadSaved()
	if err != nil {
		return err
	}
	cfg.Iface = *iface
	for _, existing := range cfg.Blocklist {
		if existing == addr {
			return storeSaved(cfg)
		}
	}
	cfg.Blocklist = append(cfg.Blocklist, addr)
	return storeSaved(cfg)
}

func unblock(args []string) error {
	fs := flag.NewFlagSet("unblock", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("unblock requires -iface")
	}
	if fs.NArg() != 1 {
		return errors.New("unblock requires an IPv4 address")
	}
	addr := fs.Arg(0)
	key, err := ipKey(addr)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir(*iface), "blocklist"), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return err
	}

	cfg, err := loadSaved()
	if err != nil {
		return err
	}

	kept := cfg.Blocklist[:0]
	for _, existing := range cfg.Blocklist {
		if existing != addr {
			kept = append(kept, existing)
		}
	}
	cfg.Blocklist = kept
	cfg.Iface = *iface
	return storeSaved(cfg)
}

func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("list requires -iface")
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir(*iface), "blocklist"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	var key uint32
	var value uint8
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		fmt.Println(ipFromKey(key))
	}
	return iter.Err()
}

func limits(args []string) error {
	fs := flag.NewFlagSet("limits", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	syn := fs.Int("syn", -1, "SYN packets per second, 0 disables")
	udp := fs.Int("udp", -1, "UDP packets per second, 0 disables")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("limits requires -iface")
	}
	cfg, err := loadSaved()
	if err != nil {
		return err
	}
	if *syn >= 0 {
		cfg.SynPPS = uint32(*syn)
	}
	if *udp >= 0 {
		cfg.UDPPPS = uint32(*udp)
	}
	cfg.Iface = *iface
	synPerCPU, err := perCPU(cfg.SynPPS)
	if err != nil {
		return err
	}
	udpPerCPU, err := perCPU(cfg.UDPPPS)
	if err != nil {
		return err
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir(*iface), "limits"), nil)
	if err != nil {
		return err
	}
	defer m.Close()
	err = m.Update(uint32(0), filterLimitsCfg{SynPps: synPerCPU, UdpPps: udpPerCPU}, ebpf.UpdateAny)
	if err != nil {
		return err
	}
	return storeSaved(cfg)
}

func attach(args []string) error {
	fs := flag.NewFlagSet("attach", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	mode := fs.String("mode", "native", "native or generic")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("attach requires -iface")
	}
	if *mode != "native" && *mode != "generic" {
		return errors.New("mode must be native or generic")
	}

	ifi, err := net.InterfaceByName(*iface)
	if err != nil {
		return err
	}

	dir := pinDir(*iface)
	linkPath := filepath.Join(dir, "link")
	if _, err := os.Stat(linkPath); err == nil {
		return fmt.Errorf("%s already has a pinned link, detach first", *iface)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	var objs filterObjects
	if err := loadFilterObjects(&objs, nil); err != nil {
		os.RemoveAll(dir)
		return err
	}
	lnk, err := attachXDP(objs.XdpFilter, ifi.Index, *mode)
	if err != nil {
		objs.Close()
		os.RemoveAll(dir)
		return err
	}
	if err := pinAll(dir, &objs, lnk); err != nil {
		os.RemoveAll(dir)
		lnk.Close()
		objs.Close()
		return err
	}
	if err := applySaved(&objs); err != nil {
		lnk.Close()
		objs.Close()
		return err
	}
	lnk.Close()
	objs.Close()
	return nil
}

func applySaved(objs *filterObjects) error {
	cfg, err := loadSaved()
	if err != nil {
		return err
	}
	for _, addr := range cfg.Blocklist {
		key, err := ipKey(addr)
		if err != nil {
			return fmt.Errorf("config address %s: %w", addr, err)
		}
		if err := objs.Blocklist.Update(key, uint8(1), ebpf.UpdateAny); err != nil {
			return err
		}
	}
	syn, err := perCPU(cfg.SynPPS)
	if err != nil {
		return err
	}
	udp, err := perCPU(cfg.UDPPPS)
	if err != nil {
		return err
	}
	return objs.Limits.Update(uint32(0), filterLimitsCfg{
		SynPps: syn,
		UdpPps: udp,
	}, ebpf.UpdateAny)
}

func attachXDP(prog *ebpf.Program, index int, mode string) (link.Link, error) {
	flags := link.XDPDriverMode
	if mode == "generic" {
		flags = link.XDPGenericMode
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: index,
		Flags:     flags,
	})
	if err == nil || mode == "generic" {
		return lnk, err
	}
	return link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: index,
		Flags:     link.XDPGenericMode,
	})
}

func pinAll(dir string, objs *filterObjects, lnk link.Link) error {
	maps := []struct {
		name string
		m    *ebpf.Map
	}{
		{"blocklist", objs.Blocklist},
		{"limits", objs.Limits},
		{"sources", objs.Sources},
		{"stats", objs.Stats},
	}
	for _, item := range maps {
		if err := item.m.Pin(filepath.Join(dir, item.name)); err != nil {
			return err
		}
	}
	return lnk.Pin(filepath.Join(dir, "link"))
}

func detach(args []string) error {
	fs := flag.NewFlagSet("detach", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("detach requires -iface")
	}

	dir := pinDir(*iface)
	lnk, err := link.LoadPinnedLink(filepath.Join(dir, "link"), nil)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		lnk.Close()
		return err
	}
	return lnk.Close()
}

func stats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	iface := fs.String("iface", "", "network interface")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *iface == "" {
		return errors.New("stats requires -iface")
	}

	m, err := ebpf.LoadPinnedMap(filepath.Join(pinDir(*iface), "stats"), nil)
	if err != nil {
		return err
	}
	defer m.Close()

	names := []string{"pass", "drop_blocklist", "drop_syn", "drop_udp", "drop_full"}
	// values := make([]uint64, ebpf.PossibleCPU())
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	values := make([]uint64, ncpu)
	for slot := 0; slot < statMax; slot++ {
		if err := m.Lookup(uint32(slot), &values); err != nil {
			return err
		}
		var total uint64
		for _, n := range values {
			total += n
		}
		fmt.Printf("%s %d\n", names[slot], total)
	}
	return nil
}
