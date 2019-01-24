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

func findKernel(data []byte) ([]byte, error) {
	for {
		i := bytes.Index(data, []byte{0x89, 'L', 'Z', 'O', 0x00})
		if i < 0 {
			return nil, errors.New("no valid LZO archives found")
		}

		if unpacked, err := lzop(data[i:]); err == nil {
			return unpacked, nil
		}

		data = data[i+1:]
	}
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
	if *dumpKernel != "" {
		if err := ioutil.WriteFile(*dumpKernel, kernel, 0644); err != nil {
			log.Fatalf("Can't write kernel to %q: %v", *dumpKernel, err)
		}
		log.Printf("Wrote uncompressed kernel image to %q", *dumpKernel)
	}
}
