// Patch a running 'dtv_svc' process; run with --help for flag help.
//
// To build and push:
//  make patcher && adb push patcher /data/local/tmp/patcher
//
// To run as root:
//  /data/local/tmp/patcher -pid="$(pidof dtv_svc|tr ' ' '\n'|sort -n|tail -n 1)"

package main

import (
	"bytes"
	"debug/elf"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"syscall"
)

var warning = log.New(os.Stderr, "WARNING: ", log.Ltime)

var (
	flagLLGetterELF    = flag.String("log_level_getter_elf", "/linux_rootfs/basic/libmtkapp.so", "ELF file the --log_level_getter_symbol is defined in.")
	flagLLGetterSymbol = flag.String("log_level_getter_symbol", "a_cfg_custom_get_log_print_flag", "Symbol that returns the customer log level.")
	flagPID            = flag.Int("pid", 0, "PID of dtv_svc.")
	flagAction         = flag.String("action", "patch-ll-value", "Action to perform. 'patch-ll-value' to override the log level with 0xff, 'patch-ll-getter' to override the --log_level_getter_symbol entirely.")
)

// retFF is the native encoding of a subroutine that returns 0xff.
var retFF = []byte{
	0xff, 0x00, 0xa0, 0xe3, // mov r0, #255
	0x1e, 0xff, 0x2f, 0xe1, // bx lr
}

// getELFSymAddr returns the *elf.Symbol of a symbol in an ELF file.
func getELFSymAddr(filename, symbol string) (*elf.Symbol, error) {
	f, err := elf.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("can't open %q as ELF: %v", filename, err)
	}

	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("can't get symbols from %q: %v", filename, err)
	}

	var ret *elf.Symbol
	for _, sym := range syms {
		if sym.Name == symbol {
			if ret != nil {
				return nil, fmt.Errorf("duplicate symbol %q: previous: %#v, current: %#v", symbol, ret, sym)
			}
			sym := sym // copy
			ret = &sym
		}
	}

	return ret, nil
}

// addr is a 32-bit address.
type addr uint32

// String implements fmt.Stringer.
func (a addr) String() string {
	return fmt.Sprintf("0x%08x", uint32(a))
}

// parseAddr parses an addr from a hexadecimal string.
func parseAddr(s string) (addr, error) {
	ret, err := strconv.ParseUint(s, 16, 32)
	return addr(ret), err
}

// addrWithLen is an address with a length.
type addrWithLen struct {
	a addr
	l uint
}

// String implements fmt.Stringer.
func (al *addrWithLen) String() string {
	return fmt.Sprintf("&addrWithLen{addr: %v, len: %d}", al.a, al.l)
}

// getExecutableMapping returns the load address and length of the executable with the name
// “libname” mapped into pid’s address space at offset 0.
func getExecutableMapping(pid int, libname string) (*addrWithLen, error) {
	var err error

	b, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, fmt.Errorf("can't read %d's page mappings: %v", err)
	}

	bb := bytes.NewBuffer(b)
	for err == nil {
		var line string
		line, err = bb.ReadString('\n')
		if line == "" {
			continue
		}

		f := strings.Fields(line)
		if l := len(f); l != 6 {
			continue
		}

		//         0          1       2      3    4         5
		// abe15000-ac7a0000 r-xp 00000000 fd:01 115 /linux_rootfs/basic/libmtkapp.so

		if f[5] != libname {
			continue
		}

		if !strings.Contains(f[1], "x") {
			continue
		}

		if off, cerr := strconv.ParseUint(f[2], 16, 64); cerr != nil || off != 0 {
			continue
		}

		f = strings.SplitN(f[0], "-", 2)
		if len(f) != 2 {
			continue
		}

		var start, end addr
		start, err = parseAddr(f[0])
		if err != nil {
			err = fmt.Errorf("can't parse start address of line %q: %v", line, err)
			break
		}

		end, err = parseAddr(f[1])
		if err != nil {
			err = fmt.Errorf("can't parse end address of line %q: %v", line, err)
			break
		}

		return &addrWithLen{a: start, l: uint(end - start)}, nil
	}

	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("error reading %d's mappings: %v", err)
	}

	return nil, fmt.Errorf("no executable mapping of %q in %d", libname, pid)
}

// patchLLhandler patches the log level getter with the contents of retFF.
func patchLLGetter(pid int, dst *addrWithLen) error {
	data := make([]byte, dst.l)
	n, err := syscall.PtracePeekData(pid, uintptr(dst.a), data)
	if err != nil {
		return fmt.Errorf("can't read %d bytes from tracee PID %d: %v", dst.l, pid, err)
	}

	data = data[0:n]
	log.Printf("Read getter: %#v, overwriting with retFF = %d bytes", data, len(retFF))

	if len(data) < len(retFF) {
		return fmt.Errorf("len(data) = %d < len(retFF) = %d, would overwrite too much", len(data), len(retFF))
	}

	n, err = syscall.PtracePokeData(pid, uintptr(dst.a), retFF)
	if err != nil {
		return fmt.Errorf("can't poke %#v to tracee PID %d at %v: %v", retFF, pid, dst, err)
	}

	log.Printf("Wrote %d bytes (%#v), want %d", n, retFF, len(retFF))
	return nil
}

// patchLLvalue patches the log level value, pointed to in the last word of the getter.
func patchLLvalue(pid int, getter *addrWithLen) error {
	data := make([]byte, getter.l)
	n, err := syscall.PtracePeekData(pid, uintptr(getter.a), data)
	if err != nil {
		return fmt.Errorf("can't read %d bytes from tracee PID %d: %v", getter.l, pid, err)
	}

	data = data[0:n]
	log.Printf("Read getter: %#v", data)

	s := data[len(data)-4:]
	ptr := addr(s[3])<<24 | addr(s[2])<<16 | addr(s[1])<<8 | addr(s[0])
	log.Printf("Pointer to log level: %v", ptr)

	data = make([]byte, 1)
	n, err = syscall.PtracePeekData(pid, uintptr(ptr), data)
	if err != nil {
		return fmt.Errorf("Can't read %d bytes from tracee PID %d: %v", len(data), pid, err)
	}

	log.Printf("Log level now: 0x%02x; setting to 0xff.", data[0])

	data[0] = 0xff
	n, err = syscall.PtracePokeData(pid, uintptr(ptr), data)
	if err != nil {
		return fmt.Errorf("can't poke %#v to tracee PID %d at %v: %v", data, pid, ptr, err)
	}

	log.Printf("Wrote %d bytes (%#v), want %d", n, data, len(data))
	return nil
}

// getPIDSymAddr returns the offset and length of a file-mapped symbol in a running process.
func getPIDSymAddr(pid int, elff, symbol string) (*addrWithLen, error) {
	sym, err := getELFSymAddr(elff, symbol)
	if err != nil {
		return nil, fmt.Errorf("can't determine address of %q in ELF %q: %v", symbol, elff, err)
	}

	log.Printf("Found symbol in ELF: %#v", sym)

	m, err := getExecutableMapping(pid, elff)
	if err != nil {
		return nil, fmt.Errorf("can't determine executable mapping of %q for PID %d: %v. Exiting.", elff, pid, err)
	}
	log.Printf("Found mapping in process: %v", m)

	if sym.Value+sym.Size > uint64(m.l) {
		return nil, fmt.Errorf("symbol %v's address (%v) + length (%d) = %d exceeds mapping size %d. Exiting.", sym.Value, sym.Size, sym.Value+sym.Size, m.l)
	}

	off := m.a + addr(sym.Value)

	ret := &addrWithLen{a: off, l: uint(sym.Size)}
	log.Printf("Offset: %v", ret)

	return ret, nil
}

// ptrace attaches to a tracee and returns a function that must be called before the program exits.
func ptrace(pid int) (func(), error) {
	if err := syscall.PtraceAttach(pid); err != nil {
		return nil, fmt.Errorf("can't ptrace(PTRACE_ATTACH, %d): %v", pid, err)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return nil, fmt.Errorf("can't wait for tracee with PID %d: %v.", pid, err)
	}
	log.Printf("waitpid(%d) = %#v", pid, ws)

	return func() {
		log.Printf("Note: If the UI gets stuck, run pkill -CONT dtv_svc")
		if err := syscall.PtraceDetach(pid); err != nil {
			warning.Printf("Can't detach from tracee PID %d: %v", pid, err)
		}
	}, nil
}

// main attaches to the tracee and performs the action specified by --action.
func main() {
	flag.Parse()

	detach, err := ptrace(*flagPID)
	if err != nil {
		log.Fatalf("Can't ptrace --pid=%d: %v.", *flagPID, err)
	}
	defer detach()

	llGetter, err := getPIDSymAddr(*flagPID, *flagLLGetterELF, *flagLLGetterSymbol)
	if err != nil {
		log.Fatalf("Can't determine load address of %q in %q of PID %d: %v.", *flagLLGetterSymbol, *flagLLGetterELF, *flagPID, err)
	}

	err = nil
	switch *flagAction {
	case "patch-ll-value":
		err = patchLLvalue(*flagPID, llGetter)
	case "patch-ll-getter":
		err = patchLLGetter(*flagPID, llGetter)
	default:
		err = fmt.Errorf("Unknown action %q", *flagAction)
	}

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Everything is fine.")
}
