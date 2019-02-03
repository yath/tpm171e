package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

var flagAsset = flag.String("asset", "findsym.elf", "name of the bundled asset")
var flagLoadAddr = flag.Uint("load_addr", 0xbf0cde8c, "load address (i.e. _CmdVersion)")
var flagDump = flag.String("dump", "", "dump final relocated binary to given filename")

// from debug/elf/file.go.
func applyRelocationsARM(f *elf.File, symbols []elf.Symbol, dst []byte, rels []byte, daddr addr) error {
	// 8 is the size of Rel32.
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

func main() {
	flag.Parse()

	a, err := Asset(*flagAsset)
	if err != nil {
		log.Fatalf("Can't load asset %q: %v", *flagAsset, err)
	}

	data, err := loadELF(a, addr(*flagLoadAddr))
	if err != nil {
		log.Fatalf("Can't load ELF: %v", err)
	}

	if *flagDump != "" {
		if err := ioutil.WriteFile(*flagDump, data, 0666); err != nil {
			log.Fatalf("Can't dump data: %v", err)
		}
		log.Printf("Output written to %q", *flagDump)
		log.Printf("arm-none-eabi-objdump -marm -bbinary -EL -D --adjust-vma=0x%08x %s", *flagLoadAddr, *flagDump)
		os.Exit(0)
	}

	for i := 0; i < len(data); i += 4 {
		cmd := fmt.Sprintf("w 0x%08x 0x%02x%02x%02x%02x", int(*flagLoadAddr)+i, data[i+3], data[i+2], data[i+1], data[i])
		fmt.Printf("adb shell cli_shell %s < /dev/null\n", cmd)
	}
}
