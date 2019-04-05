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
func patchLLGetter(t *tracee, dst *addrWithLen) error {
	old, err := t.peek(dst)
	if err != nil {
		return fmt.Errorf("can't read %d bytes from %v: %v", dst.l, t, err)
	}

	log.Printf("Read getter: %#v, overwriting with retFF = %d bytes", old, len(retFF))

	if len(old) < len(retFF) {
		return fmt.Errorf("len(old) = %d < len(retFF) = %d, would overwrite too much", len(old), len(retFF))
	}

	return t.poke(dst.a, retFF)
}

// patchLLValue patches the log level value, pointed to in the last word of the getter.
func patchLLValue(t *tracee, getter *addrWithLen) error {
	data, err := t.peek(getter)
	if err != nil {
		return fmt.Errorf("can't read %d bytes from %v: %v", getter.l, t, err)
	}
	log.Printf("Read getter: %#v", data)

	s := data[len(data)-4:]
	ptr := addr(s[3])<<24 | addr(s[2])<<16 | addr(s[1])<<8 | addr(s[0])
	log.Printf("Pointer to log level: %v", ptr)

	data, err = t.peek(&addrWithLen{ptr, 1})
	if err != nil {
		return fmt.Errorf("can't read 1 byte from %v: %v", t, err)
	}

	log.Printf("Log level now: 0x%02x; setting to 0xff.", data[0])

	data[0] = 0xff
	return t.poke(ptr, data)
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
		return nil, fmt.Errorf("can't determine executable mapping of %q for PID %d: %v", elff, pid, err)
	}
	log.Printf("Found mapping in process: %v", m)

	if sym.Value+sym.Size > uint64(m.l) {
		return nil, fmt.Errorf("symbol %v's address (%v) + length (%d) = %d exceeds mapping size %d", sym.Value, sym.Size, sym.Value+sym.Size, m.l)
	}

	off := m.a + addr(sym.Value)

	ret := &addrWithLen{a: off, l: uint(sym.Size)}
	log.Printf("Offset: %v", ret)

	return ret, nil
}

type tracee struct {
	pid int
}

func (t *tracee) String() {
	fmt.Sprintf("%T{pid=%d}", t, t.pid)
}

// ptraceAttach attaches to a tracee and returns a function that must be called before the program exits.
func (t *tracee) attach() (func(), error) {
	if err := syscall.PtraceAttach(t.pid); err != nil {
		return nil, fmt.Errorf("can't ptrace(PTRACE_ATTACH, %v): %v", t, err)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(t.pid, &ws, 0, nil); err != nil {
		return nil, fmt.Errorf("can't wait for tracee with PID %d: %v", t.pid, err)
	}
	log.Printf("waitpid(%d) = %#v", t.pid, ws)

	return func() {
		log.Printf("Note: If the UI gets stuck, run pkill -CONT dtv_svc")
		if err := syscall.PtraceDetach(t.pid); err != nil {
			warning.Printf("Can't detach from %v: %v", t, err)
		}
	}, nil
}

// armRegs is the ARM EABI register set.
type armRegs struct {
	r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 word
	fp, ip, sp, lr, pc, cpsr, r0orig            word
}

// ptraceRegs returns syscall.PtraceRegs from a.
func (a *armRegs) ptraceRegs() *syscall.PtraceRegs {
	return &syscall.PtraceRegs{
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

// getRegs returns the tracee’s current register set.
func (t *tracee) getRegs() (*armRegs, error) {
	var pr syscall.PtraceRegs
	if err := syscall.PtraceGetRegs(t.pid, &pr); err != nil {
		return nil, fmt.Errorf("can't get %v's registers: %v", t, err)
	}

	regs := fromPtraceRegs(pr)
	return &regs, nil
}

// setRegs sets the tracee’s register set.
func (t *tracee) setRegs(regs *armRegs) error {
	r := regs.ptraceRegs()
	if err := syscall.PtraceSetRegs(t.pid, r); err != nil {
		return fmt.Errorf("can't set registers for %v to %#v (%#v): %v", t, r, regs, err)
	}
	return nil
}

// peek reads src.l bytes from the tracee’s memory at offset src.a.
func (t *tracee) peek(src *addrWithLen) ([]byte, error) {
	ret := make([]byte, src.l)

	n, err := syscall.PtracePeekData(t.pid, uintptr(src.a), ret)
	if err != nil {
		return nil, fmt.Errorf("can't peek %v from %v: %v", src, t, err)
	}

	if n < 0 || uint(n) != src.l {
		return nil, fmt.Errorf("only peeked %d bytes from %v at %v, want %d", n, t, src, src.l)
	}

	ret = ret[0:n]
	return ret, nil
}

// poke writes data to the tracee’s memory at offset dst.
func (t *tracee) poke(dst addr, data []byte) error {
	wantN := len(data)
	n, err := syscall.PtracePokeData(t.pid, uintptr(dst), data)
	if err != nil {
		return fmt.Errorf("can't poke %#v to %v at offset %v: %v", data, t, dst, err)
	}

	if n != wantN {
		return fmt.Errorf("only poked %d bytes to %v at offset %v, want %v (%v)", n, t, dst, wantN, data)
	}

	return nil
}

// injectCode writes the code into the tracee at the current program counter + 4 (next word),
// followed by a debugger trap (0xe7f001f0), executes it, restores the previous state and
// returns the value of r0. If pc is nonzero, it will be executed instead and the injected code
// will be pointed to by lr. rs, if non-nil, can make further adjustments to the register set.
func (t *tracee) injectCode(code []byte, pc word, rs func(*armRegs)) (word, error) {
	// Get tracee’s registers, code before overwriting.
	origRegs, err := t.getRegs()
	if err != nil {
		return 0, fmt.Errorf("can't get tracee's registers before injecting code: %v", err)
	}
	newCode := append(code, []byte{0xe7, 0xf0, 0x01, 0xf0}...) // trap
	loc := &addrWithLen{a: addr(origRegs.pc) + 4, l: uint(len(newCode))}

	origCode, err := t.peek(loc)
	if err != nil {
		return 0, fmt.Errorf("can't get tracee's code at %v before injecting ours: %v", loc, err)
	}

	// Build new register set.
	newRegs := *origRegs
	newRegs.pc += 4
	if pc != 0 {
		newRegs.lr = newRegs.pc
		newRegs.pc = pc
	}
	if rs != nil {
		rs(&newRegs)
	}

	// Set registers and code at “loc”.
	setCodeAndRegs := func(code []byte, regs *armRegs) error {
		if err := t.setRegs(regs); err != nil {
			return fmt.Errorf("can't set registers for %v to %v:", t, regs, err)
		}

		if err := t.poke(loc.a, code); err != nil {
			return fmt.Errorf("can't poke code %#v to %v at %v: %v", code, t, loc.a, err)
		}

		return nil
	}

	defer func() {
		if err := setCodeAndRegs(origCode, origRegs); err != nil {
			log.Printf("Warning: Unable to restore original instruction and/or registers: %v.")
			log.Printf("Tracee may become unstable. reboot soon.")
			return
		}
		log.Printf("Restored original program state.")
	}()

	log.Printf("Patching current code %#v, registers %#v", origCode, origRegs)

	// Actually patch memory, set register, continue execution until breakpoint.
	if err := setCodeAndRegs(newCode, &newRegs); err != nil {
		return 0, fmt.Errorf("can't patch code %#v and registers %#v: %v", newCode, newRegs, err)
	}

	log.Printf("Set code %#v, regs %#v", newCode, newRegs)

	if err := syscall.PtraceCont(t.pid, 0); err != nil {
		return 0, fmt.Errorf("can't single-step %v: %v", t, err)
	}

	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(t.pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("can't wait for %v: %v", t, err)
	}
	log.Printf("waitpid(%d) = %#v", t.pid, ws)

	currRegs, err := t.getRegs()
	if err != nil {
		return 0, fmt.Errorf("can't get registers after stepping %v: %v", t, err)
	}

	return currRegs.r0, nil
}

// injectSyscall injects a syscall into the tracee.
func (t *tracee) injectSyscall(trapno word, args ...word) (word, error) {
	code := []byte{
		0x00, 0x00, 0x00, 0xef, // svc 0
	}
	regSetter := func(r *armRegs) {
		r.setSyscall(trapno, args...)
	}
	return t.injectCode(code, 0, regSetter)
}

// main attaches to the tracee and performs the action specified by --action.
func main() {
	flag.Parse()

	t := &tracee{pid: *flagPID}

	detach, err := t.attach()
	if err != nil {
		log.Fatalf("Can't ptrace %v: %v.", t, err)
	}
	defer detach()

	llGetter, err := getPIDSymAddr(*flagPID, *flagLLGetterELF, *flagLLGetterSymbol)
	if err != nil {
		log.Fatalf("Can't determine load address of %q in %q of PID %d: %v.", *flagLLGetterSymbol, *flagLLGetterELF, *flagPID, err)
	}

	err = nil
	switch *flagAction {
	case "patch-ll-value":
		err = patchLLValue(t, llGetter)
	case "patch-ll-getter":
		err = patchLLGetter(t, llGetter)
	case "getpid":
		var pidw word
		pidw, err = t.injectSyscall(syscall.SYS_GETPID)
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
