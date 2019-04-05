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
	"errors"
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
	flagAction         = flag.String("action", "patch-ll-value", "Action to perform. 'patch-ll-value' to override the log level with 0xff, 'patch-ll-getter' to override the --log_level_getter_symbol entirely, 'getpid' to inject a getpid() system call.")
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

// word is a 32-bit word.
type word uint32

// String implements fmt.Stringer.
func (w word) String() string {
	return fmt.Sprintf("0x%08x", uint32(w))
}

// addr is a word used as an address.
type addr word

// String implements fmt.Stringer.
func (a addr) String() string {
	return fmt.Sprintf("0x%08x", uint32(a))
}

// wordsAt is the *addrWithLen of a with length of n words.
func (a addr) wordsAt(n uint) *addrWithLen {
	return &addrWithLen{a: a, l: n * 4}
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

// patchLLGetter patches the log level getter with the contents of retFF.
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

// patchLLValue patches the log level value, pointed to in the last word of the getter.
func patchLLValue(pid int, getter *addrWithLen) error {
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

// ptraceAttach attaches to a tracee and returns a function that must be called before the program exits.
func ptraceAttach(pid int) (func(), error) {
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

// armRegs is the ARM EABI register set.
type armRegs struct {
	r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 word
	fp, ip, sp, lr, pc, cpsr, r0orig            word
}

// ptraceRegs returns a syscall.PtraceRegs from a.
func (a *armRegs) ptraceRegs() syscall.PtraceRegs {
	return syscall.PtraceRegs{
		Uregs: [18]uint32{
			uint32(a.r0), uint32(a.r1), uint32(a.r2), uint32(a.r3), uint32(a.r4), uint32(a.r5), uint32(a.r6),
			uint32(a.r7), uint32(a.r8), uint32(a.r9), uint32(a.r10), uint32(a.fp), uint32(a.ip), uint32(a.sp),
			uint32(a.lr), uint32(a.pc), uint32(a.cpsr), uint32(a.r0orig),
		}}
}

// setSyscall sets a up for calling trap with args.
func (a *armRegs) setSyscall(trap word, args ...word) error {
	switch len(args) {
	case 7:
		a.r6 = args[6]
		fallthrough
	case 6:
		a.r5 = args[5]
		fallthrough
	case 5:
		a.r4 = args[4]
		fallthrough
	case 4:
		a.r3 = args[3]
		fallthrough
	case 3:
		a.r2 = args[2]
		fallthrough
	case 2:
		a.r1 = args[1]
		fallthrough
	case 1:
		a.r0 = args[0]
		fallthrough
	case 0:
		a.r7 = trap
		return nil
	}
	return errors.New("can't have more than 7 syscall args")
}

// fromPtraceRegs returns armRegs from syscall.PtraceRegs’ Uregs.
func fromPtraceRegs(pr syscall.PtraceRegs) armRegs {
	r := pr.Uregs
	return armRegs{
		word(r[0]), word(r[1]), word(r[2]), word(r[3]), word(r[4]), word(r[5]), word(r[6]),
		word(r[7]), word(r[8]), word(r[9]), word(r[10]), word(r[11]), word(r[12]), word(r[13]),
		word(r[14]), word(r[15]), word(r[16]), word(r[17])}
}

// peek reads src.l bytes from the tracee’s memory at offset src.a.
func peek(pid int, src *addrWithLen) ([]byte, error) {
	ret := make([]byte, src.l)

	n, err := syscall.PtracePeekData(pid, uintptr(src.a), ret)
	if err != nil {
		return nil, fmt.Errorf("can't peek %v from tracee %d: %v", src, pid, err)
	}

	if n < 0 || uint(n) != src.l {
		return nil, fmt.Errorf("only peeked %d bytes from tracee %d at %v, want %d", n, pid, src, src.l)
	}

	ret = ret[0:n]
	return ret, nil
}

// poke writes data to the tracee’s memory at offset dst.
func poke(pid int, dst addr, data []byte) error {
	wantN := len(data)
	n, err := syscall.PtracePokeData(pid, uintptr(dst), data)
	if err != nil {
		return fmt.Errorf("can't poke %#v to tracee %d at offset %v: %v", data, pid, dst, err)
	}

	if n != wantN {
		return fmt.Errorf("only poked %d bytes to tracee %d at offset %v, want %v (%v)", n, pid, dst, wantN, data)
	}

	return nil
}

// injectSyscall injects a syscall into the tracee.
func injectSyscall(pid int, trapno word, args ...word) (word, error) {
	// Get registers, save 3 words at PC.
	var pr syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &pr); err != nil {
		return 0, fmt.Errorf("can't get tracee %d's registers: %v", pid, err)
	}

	regs := fromPtraceRegs(pr)
	pc := addr(regs.pc)
	ins, err := peek(pid, pc.wordsAt(3))
	if err != nil {
		return 0, fmt.Errorf("can't get current instruction: %v", err)
	}

	origRegs := regs
	origIns := ins

	// Set up registers for syscall args and our instructions at pc+4.
	if err := regs.setSyscall(trapno, args...); err != nil {
		return 0, err
	}
	regs.pc += 4
	ins = []byte{
		0x00, 0x00, 0x00, 0xef, // svc 0
		0xe7, 0xf0, 0x01, 0xf0, // debugger trap
	}

	// Restore original memory/register contents before returning.
	pokeInsn := func(insn []byte, regs armRegs) error {
		r := regs.ptraceRegs()
		if err := syscall.PtraceSetRegs(pid, &r); err != nil {
			return fmt.Errorf("can't set registers for tracee %d to %#v (%#v): %v", pid, r, regs, err)
		}

		if err := poke(pid, addr(regs.pc), insn); err != nil {
			return fmt.Errorf("can't poke instruction %#v to tracee %d at %v: %v", insn, pid, regs.pc, err)
		}

		return nil
	}

	defer func() {
		if err := pokeInsn(origIns, origRegs); err != nil {
			log.Printf("Warning: Unable to restore original instruction and/or registers: %v.")
			log.Printf("Tracee may become unstable. reboot soon.")
			return
		}
		log.Printf("Restored original program state.")
	}()

	// Actually patch memory, set register, continue execution (until the breakpoint after svc 0).
	log.Printf("Patching current instruction %#v, registers %#v", origIns, origRegs)
	if err := pokeInsn(ins, regs); err != nil {
		return 0, fmt.Errorf("can't patch syscall instruction: %v", err)
	}

	log.Printf("Set insn %#v, regs %#v", ins, regs)

	if err := syscall.PtraceCont(pid, 0); err != nil {
		return 0, fmt.Errorf("can't single-step tracee %d: %v", pid, err)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("can't wait for tracee %d: %v.", pid, err)
	}
	log.Printf("waitpid(%d) = %#v", pid, ws)

	// Back from syscall, get return value.
	var newRegs syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(pid, &newRegs); err != nil {
		return 0, fmt.Errorf("can't get registers after single-stepping tracee %d: %v", pid, err)
	}

	log.Printf("regs after syscall: %#v (%#v)", newRegs, fromPtraceRegs(newRegs))

	return fromPtraceRegs(newRegs).r0, nil

	// Deferred function restores original memory/registers.
}

// main attaches to the tracee and performs the action specified by --action.
func main() {
	flag.Parse()

	detach, err := ptraceAttach(*flagPID)
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
		err = patchLLValue(*flagPID, llGetter)
	case "patch-ll-getter":
		err = patchLLGetter(*flagPID, llGetter)
	case "getpid":
		var pidw word
		pidw, err = injectSyscall(*flagPID, syscall.SYS_GETPID)
		if err == nil {
			log.Printf("getpid() = %d", pidw)
		}
	default:
		err = fmt.Errorf("Unknown action %q", *flagAction)
	}

	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Everything is fine.")
}
