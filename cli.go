package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const devCli = "/dev/cli"

type lineCallback func(line string, cmd *exec.Cmd) error

func streamLog(cb lineCallback) error {
	cmd := exec.Command("logcat", "-bmain", "-s", "-T1", "MTK_KL")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("can't get a pipe for logcat child: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("can't start logcat: %v", err)
	}

	var ret error

	s := bufio.NewScanner(pipe)
	for s.Scan() {
		line := s.Text()
		if err := cb(line, cmd); err != nil {
			ret = fmt.Errorf("while running streamLog callback: %v", err)
			cmd.Process.Kill()
			break
		}
	}

	if err := s.Err(); err != nil {
		if ret != nil {
			ret = fmt.Errorf("%v (additionally, while splitting logcat input: %v)", ret, err)
		} else {
			ret = fmt.Errorf("can't split logcat output: %v", err)
		}
	}

	if err := cmd.Wait(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if ws, ok := ee.ProcessState.Sys().(syscall.WaitStatus); ok {
				if ws.Signaled() && ws.Signal() == os.Kill {
					// We sent SIGKILL, don’t report is an error.
					err = nil
				}
			}
		}

		if err != nil {
			if ret != nil {
				ret = fmt.Errorf("%v (additionally, while executing logcat: %v)", ret, err)
			} else {
				ret = fmt.Errorf("execution of logcat failed: %v", err)
			}
		}
	}
	return ret
}

func sendString(f *os.File, cmd string) error {
	bp, err := syscall.BytePtrFromString(cmd)
	if err != nil {
		return fmt.Errorf("can't get a byte buffer: %v", err)
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), 1, uintptr(unsafe.Pointer(bp)))
	if errno != 0 {
		return fmt.Errorf("ioctl(%d=%q, INPUT_STRING, %q) failed: %v", f.Fd(), devCli, cmd, errno)
	}

	return nil
}

func sendChar(f *os.File, char byte) error {
	bp, err := syscall.BytePtrFromString(string(char))
	if err != nil {
		return fmt.Errorf("can't get a byte buffer: %v", err)
	}

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(f.Fd()), 0, uintptr(unsafe.Pointer(bp)))
	if errno != 0 {
		return fmt.Errorf("ioctl(%d=%q, INPUT_CHAR, %#v) failed: %v", f.Fd(), devCli, char, errno)
	}

	return nil
}

func sendStringAsChars(f *os.File, cmd string) error {
	for _, c := range cmd {
		if err := sendChar(f, byte(c)); err != nil {
			return err
		}
	}
	return nil
}

func streamCommand(f *os.File, command string) error {
	const sentinelKey = "cl1w4sh3re"
	const sentinelValStart = "sTaRT"
	const sentinelValEnd = "TheenD"
	putSentinel := func(value string) error {
		for _, c := range []string{fmt.Sprintf("alias %s %s", sentinelKey, value), "alias"} {
			if err := sendString(f, c); err != nil {
				return err
			}
		}
		return nil
	}
	hasSentinel := func(line, value string) bool {
		return strings.Index(line, sentinelKey) > 0 && strings.Index(line, value) > 0
	}

	type stateKind int
	const (
		_ stateKind = iota
		stateWaitStart
		stateWaitEnd
		stateDone
	)

	state := stateWaitStart
	callback := func(line string, cmd *exec.Cmd) error {
		if state == stateWaitStart {
			if hasSentinel(line, sentinelValStart) {
				state = stateWaitEnd
				for _, err := range []error{sendString(f, command), putSentinel(sentinelValEnd)} {
					if err != nil {
						return fmt.Errorf("Error while sending: %v", err)
					}
				}
			}
		} else if state == stateWaitEnd {
			if hasSentinel(line, sentinelValEnd) {
				cmd.Process.Kill()
				state = stateDone
			} else {
				log.Print(line)
			}
		}

		return nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var ret error
	go func() {
		ret = streamLog(callback)
		wg.Done()
	}()

	if err := putSentinel(sentinelValStart); err != nil {
		return err
	}

	wg.Wait()
	return ret
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <cmd>", os.Args[0])
	}

	cmd := strings.Join(os.Args[1:], " ")

	f, err := os.Open(devCli)
	if err != nil {
		log.Fatalf("can't open %v: %v", devCli, err)
	}

	if err := streamCommand(f, cmd); err != nil {
		log.Fatalf("Error when streaming command: %v", err)
	}
}
