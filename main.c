#include <stdio.h>
#include <stdint.h>

typedef uint64_t tgt_addr_t;
#include "shellcode.bin.h"
#include "shellcode.addr.h"

static void print_commands(FILE *f) {
    for (int i = 0; i < (int)sizeof(shellcode_bin); i++) {
        if (i%4 == 0) {
            if (i)
                fprintf(f, "\n");
            fprintf(f, "cli_shell w 0x%08lx 0x", shellcode_addr+i);
        }
        fprintf(f, "%02x", shellcode_bin[i]);
    }
    printf("\ncli_shell b.ver\n");
}

int main(void) {
    print_commands(stdout);
    return 0;
}
