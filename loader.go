package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const targetSymbol = "_CmdVersion"

var flagAsset = flag.String("asset", "findsym.elf", "name of the bundled asset")
var flagLoadAddr = flag.Uint("load_addr", 0, "load address (i.e. "+targetSymbol+"). 0 determines it automatically.")
var flagDump = flag.String("dump", "", "dump final relocated binary to given filename")
var flagWrite = flag.Bool("write", true, "write relocated binary to determined load address")
var flagTriggerCmd = flag.String("trigger_cmd", "b.ver", "trigger command that executes "+targetSymbol)
var flagTriggerExec = flag.String("trigger_exec", "/system/bin/sh", "execve() given binary with args after triggering")
var flagTrigger = flag.Bool("trigger", true, "trigger loaded binary with --trigger_cmd and execve --trigger_exec")

var warning = log.New(os.Stderr, "WARNING: ", log.LstdFlags)

// from debug/elf/file.go.
func applyRelocationsARM(f *elf.File, symbols []elf.Symbol, dst []byte, rels []byte, daddr addr) error {
	// 8 is the size of elf.Rel32.
	if len(rels)%8 != 0 {
		return errors.New("length of relocation section is not a multiple of 8")
	}

	b := bytes.NewReader(rels)
	var rel elf.Rel32

	for b.Len() > 0 {
		binary.Read(b, f.ByteOrder, &rel)
		symNo := rel.Info >> 8
		t := elf.R_ARM(rel.Info & 0xff)

		if symNo == 0 || symNo > uint32(len(symbols)) {
			return fmt.Errorf("Unknown symbol 0x%x", symNo)
		}
		sym := &symbols[symNo-1]
		if rel.Off+4 >= uint32(len(dst)) {
			return fmt.Errorf("offset 0x%x for symbol %#v out of range", rel.Off, sym)
		}
		if sym.Value == 0 {
			return fmt.Errorf("undefined symbol %#v", sym)
		}

		switch t {
		case elf.R_ARM_ABS32:
			val := f.ByteOrder.Uint32(dst[rel.Off : rel.Off+4])
			val += uint32(sym.Value)
			f.ByteOrder.PutUint32(dst[rel.Off:rel.Off+4], val)

		case elf.R_ARM_CALL:
			// From linux/arch/arm/kernel/module.c
			offset := int32((f.ByteOrder.Uint32(dst[rel.Off:rel.Off+4]) & 0x00ffffff) << 2)
			if offset&0x02000000 != 0 {
				offset -= 0x04000000
			}

			pos := uint64(daddr) + uint64(rel.Off)
			delta := int64(sym.Value) - int64(pos)
			offset += int32(delta)

			if offset&3 != 0 || offset <= -0x02000000 || offset >= 0x02000000 {
				return fmt.Errorf("target offset %08x for symbol %#v out of range", offset, sym)
			}

			offset >>= 2

			val := f.ByteOrder.Uint32(dst[rel.Off : rel.Off+4])
			val &= 0xff000000
			val |= uint32(offset)
			f.ByteOrder.PutUint32(dst[rel.Off:rel.Off+4], val)

		default:
			return fmt.Errorf("Unsupported relocation type %v", t)
		}
	}

	return nil
}

type addr uint32

func loadELF(data []byte, loadaddr addr) ([]byte, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("can't open elf: %v", err)
	}

	sections := make(map[string][]byte, 3)
	for _, name := range []string{".text", ".rel.text", ".data"} {
		sec := f.Section(name)
		if sec == nil {
			return nil, fmt.Errorf("section %s not found", name)
		}
		var err error
		sections[name], err = sec.Data()
		if err != nil {
			return nil, fmt.Errorf("can't get section %s's data: %v", name, err)
		}
	}

	ret := sections[".text"]
	for len(ret)%4 != 0 {
		ret = append(ret, byte(0))
	}

	dataaddr := loadaddr + addr(len(ret))
	ret = append(ret, sections[".data"]...)

	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("can't get list of symbols: %v", err)
	}

	for i, sym := range syms {
		if sym.Name == "" && elf.SymType(sym.Info&0xf) == elf.STT_SECTION {
			if int(sym.Section) >= len(f.Sections) {
				return nil, fmt.Errorf("section %v for symbol %#v out of range", sym.Section, sym)
			}
			switch f.Sections[sym.Section].Name {
			case ".text":
				syms[i].Value = uint64(loadaddr)
			case ".data":
				syms[i].Value = uint64(dataaddr)
			}
		}
	}

	if err := applyRelocationsARM(f, syms, ret, sections[".rel.text"], loadaddr); err != nil {
		return nil, fmt.Errorf("can't relocate: %v", err)
	}

	for len(ret)%4 != 0 {
		ret = append(ret, byte(0))
	}
	return ret, nil
}

func sendString(f *os.File, cmd string) error {
	bp, err := syscall.BytePtrFromString(cmd)
	if err != nil {
		return fmt.Errorf("can't get a byte buffer: %v", err)
	}

	start := time.Now()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), 1, uintptr(unsafe.Pointer(bp)))
	if errno != 0 {
		return fmt.Errorf("ioctl(%v, INPUT_STRING, %q) failed: %v", f, cmd, errno)
	}
	log.Printf("Sent %q to CLI (took %v).", cmd, time.Now().Sub(start))

	return nil
}

func ignoreSIGKILL(err error) error {
	if err == nil {
		return nil
	}

	if ee, ok := err.(*exec.ExitError); ok {
		if ws, ok := ee.ProcessState.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() && ws.Signal() == os.Kill {
				return nil
			}
		}
	}
	return err
}

func cliCommand(f *os.File, cmdstr string, recv chan<- string) error {
	cmd := exec.Command("logcat", "-T0", "-s", "MTK_KL")
	cmd.Stdin = nil
	cmd.Stderr = nil
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("can't get a pipe to logcat's stdout: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't start logcat: %v", err)
	}

	defer func() {
		cmd.Process.Kill()
		if err := ignoreSIGKILL(cmd.Wait()); err != nil {
			warning.Printf("When waiting for logcat: %v", err)
		}
	}()

	s := bufio.NewScanner(stdout)
	if !s.Scan() {
		ret := s.Err()
		if ret == nil {
			ret = errors.New("unexpected EOF while waiting for first line")
		}
		return ret
	}

	go func() {
		for s.Scan() {
			line := s.Text()
			if len(line) > 0 && line[0] == '-' {
				continue
			}
			recv <- line
		}
		close(recv)
		if err := s.Err(); err != nil {
			warning.Printf("While reading from logcat: %v", err)
		}
	}()

	// Will block until the command has been processed. The log does lag a bit, but
	// it doesn’t matter if we lose a couple of lines at the end of a thread dump.
	return sendString(f, cmdstr)

	// defer kills logcat, goroutine closes recv on EOF.
}

func mustAtoi(s string) uint32 {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		log.Panicf("ParseUint(%q, 16, 32) unexpectedly failed: %v", s, err)
	}
	return uint32(v)
}

var symRE = regexp.MustCompile(`\[<([[:xdigit:]]{8})>\] \((.*?)\+0x([[:xdigit:]]+)/`)
var taskRE = regexp.MustCompile(`\] Task\s+\d+\s`)

func getThreadDump() (map[string]addr, error) {
	f, err := os.Open("/dev/cli")
	if err != nil {
		return nil, fmt.Errorf("can't open CLI: %v", err)
	}
	defer f.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	recv := make(chan string)
	go func() {
		err = cliCommand(f, "b.da", recv)
		wg.Done()
	}()

	const markTimeout = 15 * time.Second
	mark := time.NewTimer(markTimeout)
	tasks := 0

	inconclusive := map[string]struct{}{
		"MonitorProcess": struct{}{},
		"cb_ioctl":       struct{}{},
	}

	ret := make(map[string]addr)
F:
	for {
		select {
		case <-mark.C:
			log.Printf("Still here (got %d tasks so far).", tasks)
			mark.Reset(markTimeout)

		case line, ok := <-recv:
			if !ok {
				break F
			}

			if taskRE.MatchString(line) {
				tasks++
				continue F
			}

			for _, m := range symRE.FindAllStringSubmatch(line, -1) {
				abs, sym, off := mustAtoi(m[1]), m[2], mustAtoi(m[3])
				symaddr := addr(abs - off)
				if old, ok := ret[sym]; ok && old != symaddr {
					if _, iok := inconclusive[sym]; !iok {
						warning.Printf("Inconclusive address for %q: %08x (previous) vs. %08x (current). Ignoring symbol.", sym, old, symaddr)
						inconclusive[sym] = struct{}{}
					}
				} else if !ok {
					log.Printf("Discovered %q at 0x%08x.", sym, symaddr)
					ret[sym] = symaddr
					mark.Reset(markTimeout)
				}
			}
		}
	}
	wg.Wait()

	if err != nil {
		return nil, fmt.Errorf("can't send CLI command: %v", err)
	}

	for sym, _ := range inconclusive {
		delete(ret, sym)
	}

	return ret, nil
}

type addrWithLen struct {
	Addr addr
	Len  uint32
}

func (a addrWithLen) String() string {
	return fmt.Sprintf("0x%08x (%d bytes)", a.Addr, a.Len)
}

func getDriverSymbols() (map[string]addrWithLen, error) {
	f, err := elf.Open("/basic/dtv_driver.ko") // Not all copies are readable.
	if err != nil {
		return nil, fmt.Errorf("can't open dtv_driver: %v", err)
	}

	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("can't determine dtv_driver's symbols: %v", err)
	}

	ret := make(map[string]addrWithLen)
	for _, sym := range syms {
		if int(sym.Section) >= len(f.Sections) {
			continue
		}
		section := f.Sections[sym.Section]
		if sym.Name == "" || section.Name != ".text" || sym.Value == 0 || sym.Size == 0 {
			continue
		}
		ret[sym.Name] = addrWithLen{addr(sym.Value), uint32(sym.Size)}
	}

	return ret, nil
}

type cache struct {
	KernelVersion string
	TargetSymbol  string
	TargetAddr    addrWithLen
}

const cacheFile = "/data/local/tmp/targetcache"

func getCache() *cache {
	f, err := os.Open(cacheFile)
	if err != nil {
		warning.Printf("Can't open cache file, ignoring: %v", err)
		return nil
	}
	defer f.Close()

	var ret cache
	if err := gob.NewDecoder(f).Decode(&ret); err != nil {
		warning.Printf("Can't decode %v as %T, ignoring: %v", cacheFile, &ret, err)
		return nil
	}

	return &ret
}

func putCache(c *cache) error {
	f, err := os.Create(cacheFile)
	if err != nil {
		return fmt.Errorf("can't create cache file: %v", err)
	}

	if err := gob.NewEncoder(f).Encode(c); err != nil {
		os.Remove(cacheFile)
		return fmt.Errorf("can't encode %T%#v to %v: %v", c, c, f, err)
	}

	if err := f.Close(); err != nil {
		os.Remove(cacheFile)
		return fmt.Errorf("can't close cache file: %v", err)
	}

	return nil
}

func getKernelVersion() (string, error) {
	v, err := ioutil.ReadFile("/proc/version")
	return string(v), err
}

func getTargetAddr() (addrWithLen, error) {
	var zero addrWithLen

	kver, err := getKernelVersion()
	if err != nil {
		return zero, fmt.Errorf("can't determine running kernel: %v", err)
	}

	if c := getCache(); c != nil {
		if c.KernelVersion != kver {
			warning.Printf("Cached kernel version (%q) doesn't match running kernel (%q), ignoring.", c.KernelVersion, kver)
		} else if c.TargetSymbol != targetSymbol {
			warning.Printf("Cache symbol name (%q) doesn't match expected (%q), ignoring.", c.TargetSymbol, targetSymbol)
		} else {
			log.Printf("Loaded target symbol %q = %v from cache, delete %q if this is incorrect.", targetSymbol, c.TargetAddr, cacheFile)
			return c.TargetAddr, nil
		}
	}

	warning.Printf("Need to acquire a thread dump, this might take a minute or two.")
	runsyms, err := getThreadDump()
	if err != nil {
		return zero, fmt.Errorf("can't acquire thread dump: %v", err)
	}

	drvsyms, err := getDriverSymbols()
	if err != nil {
		return zero, fmt.Errorf("can't get symbols from dtv driver: %v", err)
	}

	var offset addr
	offsym := ""
	for sym, dval := range drvsyms {
		rval, ok := runsyms[sym]
		if !ok {
			continue
		}
		soff := rval - dval.Addr
		if offset != addr(0) && offset != soff {
			return zero, fmt.Errorf("inconclusive symbol offset: 0x%08x (previous, for %q) vs. 0x%08x (now, for %q)", offset, offsym, soff, sym)
		}
		offset = soff
		offsym = sym
	}

	dval, ok := drvsyms[targetSymbol]
	if !ok {
		return zero, fmt.Errorf("symbol %q not found in driver", targetSymbol)
	}
	ret := addrWithLen{dval.Addr + offset, dval.Len}

	if err := putCache(&cache{KernelVersion: kver, TargetSymbol: targetSymbol, TargetAddr: ret}); err != nil {
		warning.Printf("Can't store cache: %v", err)
	}

	return ret, nil
}

func main() {
	flag.Parse()

	a, err := Asset(*flagAsset)
	if err != nil {
		log.Fatalf("Can't load asset %q: %v", *flagAsset, err)
	}

	loadAddr := addr(*flagLoadAddr)
	loadLen := uint32(0)
	if loadAddr == addr(0) {
		tgt, err := getTargetAddr()
		if err != nil {
			log.Fatalf("Can't determine load address: %v.", err)
		}
		loadAddr, loadLen = tgt.Addr, tgt.Len
	}

	data, err := loadELF(a, loadAddr)
	if err != nil {
		log.Fatalf("Can't load ELF: %v", err)
	}

	if loadLen > 0 {
		l := uint32(len(data))
		if l > loadLen {
			log.Fatalf("Binary size (%d bytes) exceeds target length (%d). Run with -dump and investigate what to strip.", l, loadLen)
		}

		log.Printf("Linked ELF: %d bytes, available at target: %d (room for %d more bytes)", l, loadLen, loadLen-l)
	}

	if *flagDump != "" {
		if err := ioutil.WriteFile(*flagDump, data, 0666); err != nil {
			log.Fatalf("Can't dump data: %v", err)
		}
		log.Printf("Output written to %q", *flagDump)
		log.Printf("arm-none-eabi-objdump -marm -bbinary -EL -D --adjust-vma=0x%08x %s", loadAddr, *flagDump)
		os.Exit(0)
	}

	f, err := os.Open("/dev/cli")
	if err != nil {
		log.Fatalf("Can't open CLI: %v.", err)
	}
	defer f.Close()

	if *flagWrite {
		for i := 0; i < len(data); i += 4 {
			cmd := fmt.Sprintf("w 0x%08x 0x%02x%02x%02x%02x", uint(loadAddr)+uint(i), data[i+3], data[i+2], data[i+1], data[i])
			if err := sendString(f, cmd); err != nil {
				log.Fatalf("Can't send write command %q to CLI: %v.", cmd, err)
			}
		}
	}

	if *flagTrigger {
		if err := sendString(f, *flagTriggerCmd); err != nil {
			log.Fatalf("Can't send trigger command %q to CLI: %v", *flagTriggerCmd, err)
		}
		log.Printf("Executed %s.", *flagAsset)

		if ex := *flagTriggerExec; ex != "" {
			args := strings.Fields(ex)
			argv0 := args[0]
			env := os.Environ()
			log.Printf("Calling execve(argv0=%q, args=%q, env=%q). Goodbye!", argv0, args, env)
			if err := syscall.Exec(argv0, args, env); err != nil {
				log.Fatalf("Exec failed: %v", err)
			}
			log.Panic("Should not be here")
		}
	}
}
