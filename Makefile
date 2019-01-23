.PHONY: all
all: exploit decrypt

CFLAGS += -W -Wall -Wextra
CROSS := arm-none-eabi-
CC := gcc
OBJCOPY := objcopy
XXD := xxd
READELF := readelf
AWK := awk

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

.PHONY: clean
clean:
	rm -f *.o *.bin *.bin.h *.addr.h buildts.S exploit decrypt
