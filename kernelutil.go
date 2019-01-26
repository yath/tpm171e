package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sort"
)

var dumpKernel = flag.String("dump_kernel", "", "dump uncompressed kernel to the filename given")
var dumpSymtab = flag.String("dump_symtab", "", "dump symbol table to the filename given")

// lzop tries decompressing in with lzop, ignoring warnings (i.e. trailing garbage).
func lzop(in []byte) ([]byte, error) {
	cmd := exec.Command("lzop", "-c", "-d", "--ignore-warn")
	cmd.Stdin = bytes.NewReader(in)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// findKernel extracts the first valid LZO archive of data, assuming it’s the uncompressed
// image.
func findKernel(data []byte) ([]byte, error) {
	abs := 0
	for {
		i := bytes.Index(data, []byte{0x89, 'L', 'Z', 'O', 0x00})
		if i < 0 {
			return nil, errors.New("no valid LZO archives found")
		}

		log.Printf("Trying to uncompress LZO archive at 0x%x", abs+i)
		if unpacked, err := lzop(data[i:]); err == nil {
			return unpacked, nil
		}

		abs += i + 1
		data = data[i+1:]
	}
}

// nextIndex returns the next index of sep in s strictly after the specified offset.
func nextIndex(s, sep []byte, after int) int {
	if len(s) <= after+1 {
		return -1
	}
	i := bytes.Index(s[after+1:], sep)
	if i < 0 {
		return i
	}
	return i + after + 1
}

// getaddr returns the first four bytes of data interpreted as a little-endian address
// or an error if it’s outside of 0xc0000000-0xc0ffffff.
func getaddr(data []byte) (uint32, error) {
	if data[3] != 0xc0 {
		return 0, errors.New("does not look like an address")
	}
	return uint32(data[3])<<24 | uint32(data[2])<<16 | uint32(data[1])<<8 | uint32(data[0]), nil
}

// symbol is a kernel symbol with an address and a name.
type symbol struct {
	name   string
	addr   uint32
	offset int
}

// String formats s nicely.
func (s *symbol) String() string {
	return fmt.Sprintf("[%08x] %s (Image+0x%x", s.addr, s.name, s.offset)
}

// lds returns a symbol as a linker script statement.
func (s *symbol) lds() string {
	return fmt.Sprintf("%s = 0x%08x; /* = 0x%08x + 0x%x */", s.name, s.addr, s.addr-uint32(s.offset), s.offset)
}

// getSymtab tried to find the symbol table in kernel.
//
// The expected format is:
//
// [4 byte char *name_sym1]
// [4 byte void *addr_sym1]
// [4 byte char *name_sym2]
// [4 byte void *addr_sym2]
// […]
// [char name_symN[]]
// [char name_symM[]]
// […]
// 0x00
//
// The code relies on being able to spot an entry in the list of names by a
// well-known and expected name (currently: kallsyms_lookup_name).
func getSymtab(kernel []byte) ([]*symbol, error) {
	const sym = "\x00kallsyms_lookup_name\x00"

	// Find the symbol in the string table.
	i := bytes.Index(kernel, []byte(sym))
	if nextIndex(kernel, []byte(sym), i) >= 0 {
		return nil, fmt.Errorf("symbol %q not uniquely found", sym)
	}

	// Align and walk back until we find something that looks like an address.
	i &= ^3
	log.Printf("looking for start of string table prior to 0x%x", i)
	strStart := -1
	for i > 0 {
		if _, err := getaddr(kernel[i : i+4]); err == nil {
			strStart = i + 4
			break
		}
		i -= 4
	}

	if strStart < 0 {
		return nil, errors.New("start of string table not found")
	}
	log.Printf("start of string table in kernel: 0x%x", strStart)

	// Find end of string table.
	strEnd := nextIndex(kernel, []byte{0, 0}, strStart)
	if strEnd < 0 {
		return nil, errors.New("end of string table not found")
	}

	// Gather all strings and their offsets in kernel.
	type strAndOff struct {
		val string
		off int
	}
	strs := []strAndOff{}

	off := strStart
	for _, sym := range bytes.Split(kernel[strStart:strEnd], []byte{0}) {
		strs = append(strs, strAndOff{string(sym), off})
		off += len(sym) + 1
	}
	log.Printf("found %d strings", len(strs))

	// Walk back from start of string table and find all addresses.
	addrEnd := strStart - 4
	i = addrEnd
	addrs := []uint32{}
	for i > 0 {
		if addr, err := getaddr(kernel[i:]); err == nil {
			addrs = append([]uint32{addr}, addrs...) // Prepend; we’re walking backwards.
			i -= 4
		} else {
			break
		}
	}
	log.Printf("found %d addresses", len(addrs))

	// Group addresses into [void *sym, char *name] pairs, sort by name.
	if len(addrs)%2 != 0 {
		return nil, fmt.Errorf("odd number of addresses (%d)", len(addrs))
	}

	type addrpair struct {
		symp, strp uint32
	}
	pairs := make([]addrpair, len(addrs)/2)
	for i = 0; i < len(pairs); i++ {
		pairs[i] = addrpair{addrs[i*2], addrs[i*2+1]}
	}
	sort.Slice(pairs, func(x, y int) bool { return pairs[x].strp < pairs[y].strp })

	if len(pairs) != len(strs) {
		return nil, fmt.Errorf("not exactly as many addrpairs (%d) as strings (%d)", len(pairs), len(strs))
	}

	// Build return value.
	ret := make([]*symbol, len(pairs))
	for i, str := range strs {
		stroff := pairs[i].strp - uint32(str.off)
		ret[i] = &symbol{addr: pairs[i].symp, name: str.val, offset: int(pairs[i].symp - stroff)}
	}

	return ret, nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-flags] zImage\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Flags are:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
	}

	zImage, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		log.Fatalf("Can't read zImage: %v", err)
	}

	kernel, err := findKernel(zImage)
	if err != nil {
		log.Fatalf("Kernel not found in zImage: %v", err)
	}
	zImage = nil

	log.Printf("Found kernel: %d bytes", len(kernel))

	veri := bytes.Index(kernel, []byte("Linux version "))
	if veri < 0 {
		log.Fatalf("Does not look like a Linux kernel image, though :(")
	}
	verend := nextIndex(kernel, []byte{0}, veri)
	if verend < 0 {
		log.Fatalf("Linux version string terminator not found")
	}
	for kernel[verend-1] == '\n' || kernel[verend-1] == '\r' {
		verend--
	}

	log.Printf("Found version: %q", string(kernel[veri:verend]))

	didSomething := false

	if *dumpKernel != "" {
		if err := ioutil.WriteFile(*dumpKernel, kernel, 0644); err != nil {
			log.Fatalf("Can't write kernel to %q: %v", *dumpKernel, err)
		}
		log.Printf("Wrote uncompressed kernel image to %q", *dumpKernel)
		didSomething = true
	}

	if *dumpSymtab != "" {
		syms, err := getSymtab(kernel)
		if err != nil {
			log.Fatalf("Can't generate list of symbols: %v", err)
		}
		log.Printf("Found %d symbols, dumping to %q", len(syms), *dumpSymtab)
		f := os.Stdout
		if *dumpSymtab != "-" {
			f, err = os.Create(*dumpSymtab)
			defer func(f *os.File) {
				if err := f.Close(); err != nil {
					log.Fatalf("Can't close %q: %v", *dumpSymtab, err)
				}
			}(f)

			if err != nil {
				log.Fatalf("Can't open %q for dumping symbol table: %v", *dumpSymtab, err)
			}
		}

		for _, sym := range syms {
			if _, err := fmt.Fprintln(f, sym.lds()); err != nil {
				log.Fatalf("Can't write to %q: %v", *dumpSymtab, err)
			}
		}
		didSomething = true
	} // *dumpSymtab != ""

	if !didSomething {
		log.Print("No action specified")
	}
}
