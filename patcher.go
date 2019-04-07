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
	"encoding/binary"
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
	flagDLLib          = flag.String("dl_lib", "/linux_rootfs/lib/libdl-2.18.so", "Path to libdl.so (as mapped by dtv_svc).")
	flagSOFile         = flag.String("so_file", "/data/local/tmp/patcher-payload.so", "Path to the .so file to load for --action=inject-so.")
	flagPID            = flag.Int("pid", 0, "PID of dtv_svc.")
	flagAction         = flag.String("action", "patch-ll-value", "Action to perform. 'patch-ll-value' to override the log level with 0xff, 'getpid' to inject a getpid() system call, 'load-so' to load --so_file into the process, 'unload-so' to unload it.")
)

// unloadSOMaxTries specifies how often to try dlclose() on a previously-loaded library.
const unloadSOMaxTries = 10

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

	if ret == nil {
		return nil, fmt.Errorf("symbol %q not found in library %q", symbol, filename)
	}

	return ret, nil
}

// word is a 32-bit word.
type word uint32

// nullOrHex returns “NULL” if n equals 0, a hexadecimal string otherwise.
func nullOrHex(n uint32) string {
	if n == 0 {
		return "NULL"
	}
	return fmt.Sprintf("0x%08x", n)
}

// String implements fmt.Stringer.
func (w word) String() string {
	return nullOrHex(uint32(w))
}

// addr is a word used as an address.
type addr word

// String implements fmt.Stringer.
func (a addr) String() string {
	return nullOrHex(uint32(a))
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

// findMapping returns the load address and length of the mapping containing offset within libname
// in the tracee.
func (t *tracee) findMapping(offset addr, filename string) (*addrWithLen, error) {
	b, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/maps", t.pid))
	if err != nil {
		return nil, fmt.Errorf("can't read %v's page mappings: %v", t, err)
	}

	bb := bytes.NewBuffer(b)
	var readerr error
	for readerr == nil {
		var line string
		line, readerr = bb.ReadString('\n')
		if line == "" {
			continue
		}

		f := strings.Fields(line)
		if l := len(f); l < 6 {
			continue
		}

		//         0          1       2      3    4         5						     6
		// abe15000-ac7a0000 r-xp 00000000 fd:01 115 /linux_rootfs/basic/libmtkapp.so [(deleted)]

		if f[5] != filename {
			continue
		}

		off, err := parseAddr(f[2])
		if err != nil {
			continue
		}

		f = strings.SplitN(f[0], "-", 2)
		if len(f) != 2 {
			continue
		}

		start, err := parseAddr(f[0])
		if err != nil {
			return nil, fmt.Errorf("can't parse start address of line %q: %v", line, err)
		}

		end, err := parseAddr(f[1])
		if err != nil {
			return nil, fmt.Errorf("can't parse end address of line %q: %v", line, err)
		}

		l := uint(end - start)
		offstart, offend := off, off+addr(l)
		if offset < offstart || offset > offend {
			continue
		}

		// XXX: Return the page from start-offset onwards, so the symbol offset can be
		// added.
		return &addrWithLen{a: start - off, l: l + uint(off)}, nil
	}

	if readerr != nil && readerr != io.EOF {
		return nil, fmt.Errorf("error reading %v's mappings: %v", t, err)
	}

	return nil, fmt.Errorf("no mapping of %v+%v in %v (is it in .bss?)", filename, offset, t)
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
	t := &tracee{pid}
	return t.getSymAddr(elff, symbol)
}

// getSymAddr returns the offset and length of a file-mapped symbol (i.e. *not* .bss) in the
// tracee.
func (t *tracee) getSymAddr(elff, symbol string) (*addrWithLen, error) {
	sym, err := getELFSymAddr(elff, symbol)
	if err != nil {
		return nil, fmt.Errorf("can't determine address of %q in ELF %q: %v", symbol, elff, err)
	}

	m, err := t.findMapping(addr(sym.Value), elff)
	if err != nil {
		return nil, fmt.Errorf("can't determine mapping of %q for %v: %v", elff, t, err)
	}

	if sym.Value+sym.Size > uint64(m.l) {
		return nil, fmt.Errorf("symbol %v's address (%v) + length (%d) = %d exceeds mapping size %d", symbol, sym.Value, sym.Size, sym.Value+sym.Size, m.l)
	}

	off := m.a + addr(sym.Value)
	ret := &addrWithLen{a: off, l: uint(sym.Size)}

	return ret, nil
}

// tracee is a process that can be traced.
type tracee struct {
	pid int
}

// String implements fmt.Stringer.
func (t *tracee) String() string {
	return fmt.Sprintf("%T{pid=%d}", t, t.pid)
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

	return func() {
		if err := syscall.PtraceDetach(t.pid); err != nil {
			warning.Printf("Can't detach from %v: %v", t, err)
		}
	}, nil
}

// armRegs is the ARM EABI register set. Must be in ptrace uregs order.
type armRegs struct {
	r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 word
	fp, ip, sp, lr, pc, cpsr, r0orig            word
}

// ptraceRegs returns syscall.PtraceRegs from a.
func (a *armRegs) ptraceRegs() *syscall.PtraceRegs {
	return &syscall.PtraceRegs{
		Uregs: [18]uint32{
			uint32(a.r0), uint32(a.r1), uint32(a.r2), uint32(a.r3), uint32(a.r4), uint32(a.r5),
			uint32(a.r6), uint32(a.r7), uint32(a.r8), uint32(a.r9), uint32(a.r10), uint32(a.fp),
			uint32(a.ip), uint32(a.sp), uint32(a.lr), uint32(a.pc), uint32(a.cpsr), uint32(a.r0orig),
		}}
}

// setCallRegs set a up for calling a subroutine with arguments.
func (a *armRegs) setCallRegs(args ...word) error {
	switch len(args) {
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
		return nil
	}

	return errors.New("can't have more than 4 call args") // would need a stack.
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
func (t *tracee) injectCode(code []byte, pc addr, rs func(*armRegs)) (word, error) {
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
		newRegs.pc = word(pc)
	}
	if rs != nil {
		rs(&newRegs)
	}

	// Set registers and code at “loc”.
	setCodeAndRegs := func(code []byte, regs *armRegs) error {
		if err := t.setRegs(regs); err != nil {
			return fmt.Errorf("can't set registers for %v to %v: %v", t, regs, err)
		}

		if err := t.poke(loc.a, code); err != nil {
			return fmt.Errorf("can't poke code %#v to %v at %v: %v", code, t, loc.a, err)
		}

		return nil
	}

	defer func() {
		if err := setCodeAndRegs(origCode, origRegs); err != nil {
			log.Printf("Warning: Unable to restore original instruction and/or registers: %v.", err)
			log.Printf("Tracee may become unstable. reboot soon.")
			return
		}
	}()

	// Actually patch memory, set register, continue execution until breakpoint.
	if err := setCodeAndRegs(newCode, &newRegs); err != nil {
		return 0, fmt.Errorf("can't patch code %#v and registers %#v: %v", newCode, newRegs, err)
	}

	if err := syscall.PtraceCont(t.pid, 0); err != nil {
		return 0, fmt.Errorf("can't single-step %v: %v", t, err)
	}

	// Wait for debugger trap, return r0.
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(t.pid, &ws, 0, nil); err != nil {
		return 0, fmt.Errorf("can't wait for %v: %v", t, err)
	}

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
		if err := r.setSyscall(trapno, args...); err != nil {
			log.Fatalf("Can't set syscall registers: %v", err) // unlikely
		}
	}
	ret, err := t.injectCode(code, 0, regSetter)
	if err != nil {
		return 0, fmt.Errorf("can't inject syscall %v with args=%v: %v", trapno, args, err)
	}
	if ret > 0xfffff000 {
		e := syscall.Errno(int32(ret) * -1)
		log.Printf("injectSyscall(%v, %#v) failed with errno %d=%v", trapno, args, e, e)
		return 0, e
	}
	return ret, nil
}

// injectCall injects a procedure call into the tracee.
func (t *tracee) injectCall(proc addr, args ...word) (word, error) {
	regSetter := func(r *armRegs) {
		if err := r.setCallRegs(args...); err != nil {
			log.Fatalf("Can't set registers for calling proc %v: %v", proc, err) // unlikely
		}
	}
	ret, err := t.injectCode(nil, proc, regSetter)
	if err != nil {
		return 0, fmt.Errorf("can't inject call to %v with args=%v: %v", proc, args, err)
	}

	return ret, nil
}

// readString reads a NUL-terminated string from the tracee’s address space.
func (t *tracee) readString(a addr) (string, error) {
	ret := []byte{}
	pos := a
	for {
		cs, err := t.peek(&addrWithLen{pos, 1})
		if err != nil {
			return "", fmt.Errorf("can't read string at %v+%d: %v", a, pos-a, err)
		}
		c := cs[0]
		if c == 0 {
			break
		}
		ret = append(ret, c)
		pos++
	}
	return string(ret), nil
}

// allocString allocates a NUL-terminated string in the tracee’s address space.
func (t *tracee) allocString(s string) (*addrWithLen, error) {
	cstr, err := syscall.ByteSliceFromString(s)
	if err != nil {
		return nil, fmt.Errorf("can't make a byte slice from string %q: %v", s, err)
	}

	prot := word(syscall.PROT_READ | syscall.PROT_WRITE | syscall.PROT_EXEC)
	flags := word(syscall.MAP_PRIVATE | syscall.MAP_ANONYMOUS)
	m, err := t.injectSyscall(syscall.SYS_MMAP2, 0, word(len(cstr)), prot, flags, ^word(0), 0)
	if err != nil {
		return nil, fmt.Errorf("mmap()ing %d anonymous bytes failed: %v", len(cstr), err)
	}

	a := addr(m)
	if err := t.poke(a, cstr); err != nil {
		return nil, fmt.Errorf("can't copy C string %#v to tracee memory %v: %v", cstr, a, err)
	}

	return &addrWithLen{a, uint(len(cstr))}, nil
}

// free frees (munmap) a memory block in the tracee.
func (t *tracee) free(a *addrWithLen) error {
	ret, err := t.injectSyscall(syscall.SYS_MUNMAP, word(a.a), word(a.l))
	if ret != 0 || err != nil {
		return fmt.Errorf("can't munmap(%v): %v (ret=%v)", a, err, ret)
	}
	return nil
}

// warnOnError prints a warning if f returns a non-nil error.
func warnOnError(f func() error, ft string, args ...interface{}) {
	if err := f(); err != nil {
		log.Printf("WARNING: %s: %v", fmt.Sprintf(ft, args...), err)
	}
}

const (
	// dlopen flags
	RTLD_LAZY     = 0x00001
	RTLD_NOW      = 0x00002
	RTLD_NOLOAD   = 0x00004
	RTLD_DEEPBIND = 0x00008
	RTLD_GLOBAL   = 0x00100
	RTLD_LOCAL    = 0
	RTLD_NODELETE = 0x01000

	// special handles
	RTLD_NEXT    = ^word(0)
	RTLD_DEFAULT = 0
)

// dlerror returns an error from dlerror() in the tracee, if any.
func (t *tracee) dlerror() error {
	dlerror, err := getPIDSymAddr(t.pid, *flagDLLib, "dlerror")
	if err != nil {
		return fmt.Errorf("can't find dlerror in %v: %v", t, err)
	}

	msgp, err := t.injectCall(dlerror.a)
	if err != nil {
		return fmt.Errorf("can't call dlerror(): %v", err)
	}

	if msgp == 0 {
		return nil
	}

	msg, err := t.readString(addr(msgp))
	if err != nil {
		return fmt.Errorf("can't read string returned from dlerror(): %v", err)
	}

	return errors.New(msg)
}

// dlopen calls dlopen (defined in *flagDLLib) with the given filename in the tracee.
func (t *tracee) dlopen(filename string, flags word) (word, error) {
	dlopen, err := getPIDSymAddr(t.pid, *flagDLLib, "dlopen")
	if err != nil {
		return 0, fmt.Errorf("can't find dlopen in %v: %v", t, err)
	}

	cfilename, err := t.allocString(filename)
	if err != nil {
		return 0, fmt.Errorf("can't allocate string for dlopen(%q) in %v: %v", filename, t, err)
	}
	defer warnOnError(func() error { return t.free(cfilename) }, "can't free string from dlopen(%q) in %v", filename, t)

	hdl, err := t.injectCall(dlopen.a, word(cfilename.a), flags)
	if err == nil && hdl == 0 {
		err = t.dlerror()
	}
	return hdl, err
}

// dlsym calls dlsym (defined in *flagDLLib) with the given handle and symbol name in the tracee.
func (t *tracee) dlsym(handle word, symbol string) (word, error) {
	dlsym, err := getPIDSymAddr(t.pid, *flagDLLib, "dlsym")
	if err != nil {
		return 0, fmt.Errorf("can't find dlsym in %v: %v", t, err)
	}

	csymbol, err := t.allocString(symbol)
	if err != nil {
		return 0, fmt.Errorf("can't allocate string for dlsym(%v, %q) in %v: %v", handle, symbol, t, err)
	}
	defer warnOnError(func() error { return t.free(csymbol) }, "can't free string from dlsym(%v, %q) in %v", handle, symbol, t)

	_ = t.dlerror() // clear
	ret, err := t.injectCall(dlsym.a, handle, word(csymbol.a))

	if err == nil {
		if derr := t.dlerror(); derr != nil {
			err = derr
		}
	}

	return ret, err
}

// dlclose calls dlclose (defined in *flagDLLib) for the given handle in the tracee.
func (t *tracee) dlclose(handle word) error {
	dlclose, err := getPIDSymAddr(t.pid, *flagDLLib, "dlclose")
	if err != nil {
		return fmt.Errorf("can't find dlclose in %v: %v", t, err)
	}

	ret, err := t.injectCall(dlclose.a, handle)
	if err != nil {
		return fmt.Errorf("can't inject call to dlclose: %v", err)
	}
	if ret != 0 {
		return t.dlerror()
	}

	return nil
}

// word2bytes converts a word to a byte slice with the word in little-endian encoding.
func word2bytes(w word) []byte {
	ret := make([]byte, 4)
	binary.LittleEndian.PutUint32(ret, uint32(w))
	return ret
}

// bytes2word returns a word from a little-endian encoded byte slice.
func bytes2word(bs []byte) word {
	if len(bs) != 4 {
		log.Panicf("len(bs) = %d (%#v), want 4", len(bs), bs)
	}
	return word(binary.LittleEndian.Uint32(bs))
}

// loadSO dlopen()s the given library into the tracee. If a library with the same filename is
// already opened, it is closed beforehand.
func (t *tracee) loadSO(filename string) error {
	if err := t.unloadSO(filename); err == nil {
		log.Printf("Unloaded previously loaded %q.", filename)
	} else if err != errNotLoaded {
		return fmt.Errorf("can't unload previous instance of %q: %v", filename, err)
	}

	hdl, err := t.dlopen(filename, RTLD_NOW)
	if err != nil {
		return fmt.Errorf("can't dlopen(%q): %v", filename, err)
	}
	log.Printf("dlopen(%q, RTLD_NOW) = %v", filename, hdl)
	return nil
}

var errNotLoaded = errors.New("library not loaded")

// unloadSO dlclose()s filename and verifies whether it was successfully unloaded.
func (t *tracee) unloadSO(filename string) error {
	hdl, err := t.dlopen(filename, RTLD_NOW|RTLD_NOLOAD)
	if err != nil {
		return fmt.Errorf("can't dlopen(%q, RTLD_NOW|RTLD_NOLOAD) for closing: %v", filename, err)
	}
	if hdl == 0 {
		return errNotLoaded
	}

	// The previous dlopen() holds a new reference to hdl, so we need to dlclose at least
	// twice. But, try a couple of times, in case loadSO has been called more than once or
	// dlsym was used to look up a symbol in the library.
	for i := 0; i < unloadSOMaxTries; i++ {
		if err := t.dlclose(hdl); err != nil {
			if strings.Contains(err.Error(), "not open") { // meh.
				break
			}
			return fmt.Errorf("can't dlclose(%q=%v) (attempt #%d): %v", filename, hdl, i, err)
		}
	}

	newhdl, err := t.dlopen(filename, RTLD_NOW|RTLD_NOLOAD)
	if err != nil {
		return fmt.Errorf("can't dlopen(%q, RTLD_NOW|RTLD_NOLOAD) for verification: %v", filename, err)
	}

	if newhdl != 0 {
		return fmt.Errorf("library %q still loaded after %d times dlclose(%v); current handle %v", filename, unloadSOMaxTries, hdl, newhdl)
	}

	log.Printf("Library %q with handle %v unloaded.", filename, hdl)
	return nil
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

	switch *flagAction {
	case "patch-ll-value":
		getter, err := getPIDSymAddr(*flagPID, *flagLLGetterELF, *flagLLGetterSymbol)
		if err != nil {
			log.Fatalf("Can't determine load address of %q in %q of PID %d: %v.", *flagLLGetterSymbol, *flagLLGetterELF, *flagPID, err)
		}
		if err := patchLLValue(t, getter); err != nil {
			log.Fatalf("Can't patch log level value at %v: %v", getter, err)
		}

	case "getpid":
		pidw, err := t.injectSyscall(syscall.SYS_GETPID)
		if err != nil {
			log.Fatalf("Can't inject getpid(): %v", err)
		}

		log.Printf("getpid() = %d", pidw)

	case "load-so":
		if err := t.loadSO(*flagSOFile); err != nil {
			log.Fatalf("Can't load %q into process: %v", *flagSOFile, err)
		}

	case "unload-so":
		if err := t.unloadSO(*flagSOFile); err != nil {
			log.Fatalf("Can't unload %q from process: %v", *flagSOFile, err)
		}

	default:
		log.Fatalf("Unknown action %q.", *flagAction)
	}

	log.Printf("Everything is fine.")
}
