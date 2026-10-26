package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"

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
	lnk.Close()
	objs.Close()
	return nil
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
