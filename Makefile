ALL_BINARY_TARGETS := decrypt cli kernelutil loader

.PHONY: all
all: $(ALL_BINARY_TARGETS)

ADB := adb
AWK := awk
CC := gcc
GO := go
OBJCOPY := objcopy
PERL := perl
READELF := readelf
XXD := xxd

CFLAGS += -W -Wall -Wextra
TARGET_CFLAGS = $(CFLAGS) -mcpu=cortex-a17 -mfpu=neon

CROSS := arm-none-eabi-

RUN_CLI_DIR := /data/local/tmp

## root shell

getroot.elf: getroot.c getroot.lds
	$(CROSS)$(CC) $(TARGET_CFLAGS) -Os -ffreestanding -nostdlib -o $@ -Wl,-r -T getroot.lds $<

assets.go: getroot.elf
	go-bindata -nocompress -pkg main -o $@ $^

loader: loader.go assets.go
	GOARCH=arm $(GO) build -o $@ $^

## utils

cli: cli.go
	GOARCH=arm $(GO) build -o $@ $<

kernelutil: kernelutil.go
	$(GO) build -o $@ $<

## firmware unpacking

decrypt: decrypt.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

## debugging stuff

# _Cust_dump_all_thread (b.da)
threaddump.txt:
	$(MAKE) run-cli CLICOMMAND=b.da | tee $@

MEMDUMP_BASE_ADDR ?= 0xc0008000
MEMDUMP_LEN ?= 9264960 # ls -l Image

.PRECIOUS: memdump.txt
memdump.txt:
	$(MAKE) run-cli CLICOMMAND="b.scm 0"
	$(MAKE) run-cli CLICOMMAND="b.mdmp $(MEMDUMP_BASE_ADDR) $(MEMDUMP_LEN)" | tee $@

memdump.bin: memdump.txt
	$(PERL) -ne 'if (($$_) = /^0x.*? \| ([^|]+)/) { print chr hex for /[0-9a-f]{2}/g }' < $< > $@

threaddump.lds: threaddump.txt
	$(PERL) -nE 'say sprintf("%s = 0x%08x;", $$2, hex($$1)-hex($$3)) for /\[<(.*?)>\] \((.*?)\+0x(.*?)\//' < $< | sort -u | sort -k3 > $@

zImage:
dtv_driver.ko:
	echo "Grab $@ from firmware dump (all copies are the same)"; exit 1

kernel.lds: zImage kernelutil
	./kernelutil -dump_symtab=$@ $<

MATCH_SYM=_Cust_dump_all_thread
dtv_driver.lds: dtv_driver.ko threaddump.lds
	set -x; \
	vma=$$(	 $(CROSS)objdump -t dtv_driver.ko | \
		actual=$$($(PERL) -nE 'say $$1 if /^$(MATCH_SYM) = (.*);/' < threaddump.lds) \
		$(PERL) -nE 'say sprintf("0x%08x", hex($$ENV{actual})-hex($$1)) if /(.*?) .*$(MATCH_SYM)/' \
	); 	echo VMA: $$vma; if [ x"$$vma" = x ]; then echo $(MATCH_SYM) not found, check $^; exit 1; fi; \
	$(CROSS)objdump --adjust-vma=$$vma -t dtv_driver.ko | \
	$(PERL) -nE 'say "$$2 = 0x$$1;" if /^([0-9a-f]+)\s+.\s.*\s(\S+)$$/ && hex($$1) > 0' | \
	sort -k3 > $@

.PHONY: run-cli
run-cli: cli
	$(ADB) push cli $(RUN_CLI_DIR)/cli && $(ADB) shell $(RUN_CLI_DIR)/cli $(CLICOMMAND)

.PHONY: clean
clean:
	rm -f getroot.elf dtv_driver.lds threaddump.lds kernel.lds assets.go $(ALL_BINARY_TARGETS)
