SECTIONS {
    /DISCARD/ : { *(.comment) *(.ARM.attributes) }
    .text : { *(.text) }
    .data : { *(.rodata*) *(.data*) }
}
