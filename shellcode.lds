/* XXX: these are no longer valid */

printk = 0xc05ad84c;
kallsyms_lookup_name = 0xc0085818;
dump_stack = 0xc05b1a4c;
kmsg_dump = 0xc002e3a4;
panic = 0xc05ad62c;
warn_slowpath_null = 0xc002b308;
StrToInt = 0xbf0d0770;
memset = 0xc0269a60;

SECTIONS {
    .text (0xbf019000+0x000b4e78) : ALIGN(0) { *(.text) }
}
