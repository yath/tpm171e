package main

import (
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <cmd>", os.Args[0])
	}

	cmd := strings.Join(os.Args[1:], " ")

	f, err := os.Open("/dev/cli")
	if err != nil {
		log.Fatalf("can't open /dev/cli: %v", err)
	}

	bp, err := syscall.BytePtrFromString(cmd)
	if err != nil {
		log.Fatalf("can't get a byte buffer: %v", err)
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), 1, uintptr(unsafe.Pointer(bp)))
	if errno != 0 {
		log.Fatalf("ioctl(%d, 1, %q) failed: %v", f.Fd(), cmd, errno)
	}
}
