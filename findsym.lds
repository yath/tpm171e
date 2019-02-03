printk = 0xc05ad98c;

SECTIONS {
    /DISCARD/ : { *(.comment) *(.ARM.attributes) }
    .text : { *(.text) }
    .data : { *(.rodata*) *(.data*) }
}
