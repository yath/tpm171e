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
	return uint32(data[3])<<24 | uint32(data[2])<<12 | uint32(data[1])<<8 | uint32(data[0]), nil
}

// symbol is a kernel symbol with a start and an end address.
type symbol struct {
	start, end uint32
	name       string
}

// String formats s nicely.
func (s *symbol) String() string {
	return fmt.Sprintf("[%08x-%08x] %s", s.start, s.end, s.name)
}

// getSymtab tried to find the symbol table in kernel.
//
// The expected format is:
//
// [4 byte start address of symbol 1]
// [4 byte end address of symbol 1]
// [4 byte start address of symbol 2]
// [4 byte end address of symbol 2]
// […]
// [zero-terminated name of symbol 1]
// [zero-terminated name of symbol 2]
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

	strEnd := nextIndex(kernel, []byte{0, 0}, strStart)
	if strEnd < 0 {
		return nil, errors.New("end of string table not found")
	}

	strs := []string{}
	for _, sym := range bytes.Split(kernel[strStart:strEnd], []byte{0}) {
		strs = append(strs, string(sym))
	}
	log.Printf("found %d strings", len(strs))

	addrEnd := strStart - 4
	i = addrEnd
	addrs := []uint32{}
	for i > 0 {
		if addr, err := getaddr(kernel[i:]); err == nil {
			addrs = append(addrs, addr)
			i -= 4
		} else {
			break
		}
	}
	log.Printf("found %d addresses", len(addrs))

	if len(strs)*2 != len(addrs) {
		return nil, fmt.Errorf("not twice as many addresses (%d) as strings (%d)", len(addrs), len(strs))
	}

	ret := make([]*symbol, len(strs))
	for i, str := range strs {
		ret[i] = &symbol{start: addrs[i*2], end: addrs[i*2+1], name: str}
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

	if bytes.Index(kernel, []byte("Linux version ")) < 0 {
		log.Fatalf("Does not look like a Linux kernel image, though :(")
	}

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
			for _, s := range []string{
				fmt.Sprintf("%s = 0x%08x;", sym.name, sym.start),
				fmt.Sprintf("%s_end = 0x%08x;", sym.name, sym.end),
			} {
				if _, err := fmt.Fprintln(f, s); err != nil {
					log.Fatalf("Can't write to %q: %v", *dumpSymtab, err)
				}
			}
		}
		didSomething = true
	} // *dumpSymtab != ""

	if !didSomething {
		log.Print("No action specified")
	}
}
