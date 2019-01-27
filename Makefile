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

shellcode.o: shellcode.lds shellcode.S
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

decrypt: decrypt.c
	$(CC) $(CFLAGS) -o $@ $< -lcrypto

kernelutil: kernelutil.go
	$(GO) build -o $@ $<

cli: cli.go
	GOARCH=arm $(GO) build -o $@ $<

# Cust_dump_all_thread (b.da)
threaddump.txt:
	$(MAKE) run-cli CLICOMMAND=b.da | tee $@

threaddump.lds: threaddump.txt
	$(PERL) -nE 'say sprintf("%s = 0x%08x;", $$2, hex($$1)-hex($$3)) for /\[<(.*?)>\] \((.*?)\+0x(.*?)\//' < $< | sort -u | sort -k3 > $@

.PHONY: run-cli
run-cli: cli
	$(ADB) push cli $(RUN_CLI_DIR)/cli && $(ADB) shell $(RUN_CLI_DIR)/cli $(CLICOMMAND)

.PHONY: clean
clean:
	rm -f *.o *.bin *.bin.h *.addr.h buildts.S $(ALL_BINARY_TARGETS)
