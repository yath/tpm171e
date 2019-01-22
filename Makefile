.PHONY: all
all: exploit

CFLAGS += -W -Wall -Wextra
CROSS := arm-none-eabi-
CC := gcc
OBJCOPY := objcopy
XXD := xxd
READELF := readelf
AWK := awk

shellcode.o: shellcode.lds shellcode.S
	$(CROSS)$(CC) $(CFLAGS) -nostdlib -o $@ $^

shellcode.bin: shellcode.o
	$(CROSS)$(OBJCOPY) -O binary $< $@

shellcode.bin.h: shellcode.bin
	$(XXD) -i $^ > $@

shellcode.addr.h: shellcode.o
	$(READELF) -l $< | $(AWK) '$$1 == "LOAD" { print "tgt_addr_t shellcode_addr = "$$3";" }' > $@

exploit: main.c shellcode.bin.h shellcode.addr.h
	$(CC) $(CFLAGS) -I$(CURDIR) -o $@ $<

.PHONY: clean
clean:
	rm -f *.o *.bin *.bin.h *.addr.h exploit
