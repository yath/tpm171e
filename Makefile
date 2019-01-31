ALL_BINARY_TARGETS := exploit decrypt cli kernelutil

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
CROSS := arm-none-eabi-

RUN_CLI_DIR := /data/local/tmp

decrypt: decrypt.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

kernelutil: kernelutil.go
	$(GO) build -o $@ $<

cli: cli.go
	GOARCH=arm $(GO) build -o $@ $<

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

LOAD_SYM=_CmdVersion
shellcode.lds: shellcode.lds.in dtv_driver.lds
	loadaddr=$$($(PERL) -nE 'say $$1 if /^$(LOAD_SYM) = (.*);/' < dtv_driver.lds) \
	$(PERL) -pe 's/#LOADADDR#/$$ENV{loadaddr}/g' < $< > $@

shellcode.o: shellcode.lds dtv_driver.lds kernel.lds shellcode.S
	echo '.ascii "Built at $(shell date)"' > buildts.S
	$(CROSS)$(CC) $(CFLAGS) -nostdlib -o $@ $^

shellcode.bin: shellcode.o
	$(CROSS)$(OBJCOPY) -O binary -j .text --reverse-bytes=4 $< $@

shellcode.bin.h: shellcode.bin
	$(XXD) -i $^ > $@

shellcode.addr.h: shellcode.o
	$(READELF) -e $< | $(AWK) '/Entry point/ { print "tgt_addr_t shellcode_addr = "$$NF";" }' > $@

exploit: main.c shellcode.bin.h shellcode.addr.h
	$(CC) $(CFLAGS) -I$(CURDIR) -o $@ $<

.PHONY: run-cli
run-cli: cli
	$(ADB) push cli $(RUN_CLI_DIR)/cli && $(ADB) shell $(RUN_CLI_DIR)/cli $(CLICOMMAND)

.PHONY: clean
clean:
	rm -f *.o *.bin *.bin.h *.addr.h buildts.S *.lds $(ALL_BINARY_TARGETS)
