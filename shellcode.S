.text
.global _start
_start:
  // prologue
  mov     ip, sp
  push    {r3, r4, fp, ip, lr, pc}
  sub     fp, ip, #12

  // printk timestamp
  ldr r0, helloAddr
  bl printk

  // epilogue
  mov r0, #0
  ldm     sp, {r3, r4, fp, sp, pc}

helloAddr: .word hello
hello:
 .asciz "<1>Ohai\n"
