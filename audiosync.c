#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>

#define SPDIF // control SPDIF output

/* Channel map:
   0071d1a4 [0]              1,   2,   3,   4,
   0071d1a8 [4]              5,   6,   7,  10,
   0071d1ac [8]             11,   8,   9,  12,
   0071d1b0 [12]            13,  14,  15,  16,
   0071d1b4 [16]            17,   0,   0,  20,
   0071d1b8 [20]            21,   1
*/

#ifdef SPDIF
#define LEFT_CHANNEL 6
#define RIGHT_CHANNEL 7
#else
#define LEFT_CHANNEL 10
#define RIGHT_CHANNEL 11
#endif

#define DEBUG(fmt, args...) printk(KERN_INFO KBUILD_MODNAME ": "fmt"\n", ##args)

#define ASSERT(condition) do { \
    if (!(condition)) { \
        WARN(true, "Assertion \""#condition"\" failed"); \
        return -EINVAL; \
    } \
} while(0)

typedef unsigned long word;

#define FAR_JMP 0xe51ff004 // ldr pc, [pc, #-4]

enum {
    TI_BRANCH_HOOK_1 = 0, // FAR_JMP
    TI_BRANCH_HOOK_2,     // addr of hook
    TI_ORIG_INSN_1,       // overwritten first word of f
    TI_ORIG_INSN_2,       // overwritten second word of f
    TI_CALL_ORIG_1,       // FAR_JMP
    TI_CALL_ORIG_2,       // addr of f+8
    TI_CALL_MAX,
} trampoline_instruction_t;

static void hook_fun(word *f, void *hook, word **orig_fun) {
    word *trampoline = kcalloc(TI_CALL_MAX, sizeof(word), GFP_KERNEL);

    trampoline[TI_BRANCH_HOOK_1] = FAR_JMP;
    trampoline[TI_BRANCH_HOOK_2] = (word)hook;
    trampoline[TI_ORIG_INSN_1] = f[0];
    trampoline[TI_ORIG_INSN_2] = f[1];
    trampoline[TI_CALL_ORIG_1] = FAR_JMP;
    trampoline[TI_CALL_ORIG_2] = (word)&f[2];

    *orig_fun = &trampoline[TI_ORIG_INSN_1];

    f[0] = FAR_JMP;
    f[1] = (word)trampoline;

    DEBUG("hook_fun(f=%pS (%px), hook=%pS (%px)), trampoline is at %px", f, f, hook, hook, trampoline);

    for (int i = 0; i < TI_CALL_MAX; i++)
        DEBUG("  trampoline[%d] = %lx", i, trampoline[i]);
    for (int i = 0; i < 2; i++)
        DEBUG("  set f[%d]: %lx", i, f[i]);
}

static int restore_fun(word **orig_fun) {
    word *trampoline = *orig_fun - TI_ORIG_INSN_1;
    ASSERT(trampoline[TI_BRANCH_HOOK_1] == FAR_JMP);
    ASSERT(trampoline[TI_CALL_ORIG_1] == FAR_JMP);

    word *f = ((word **)trampoline)[TI_CALL_ORIG_2] - 2;
    DEBUG("restore_fun(orig_fun=%pS (%px)), trampoline is at %px, f=%pS (%px)", orig_fun, orig_fun, trampoline, f, f);

    ASSERT(f[0] == FAR_JMP);
    ASSERT(f[1] == (word)trampoline);

    f[0] = trampoline[TI_ORIG_INSN_1];
    f[1] = trampoline[TI_ORIG_INSN_2];

    for (int i = 0; i < 2; i++)
        DEBUG("  reset f[%d]: %lx", i, f[i]);

    kfree(trampoline);
    *orig_fun = NULL;

    return 0;
}

int (*orig_MTAUD_SetChannelVolume)(int, int, int) = NULL;

int my_MTAUD_SetChannelVolume(int decoder, int channel, int value) {
    DEBUG("my_MTAUD_SetChannelVolume(%d, %d, %d)", decoder, channel, value);

    if (channel == 5) {
      DEBUG("Also setting channels %d and %d to volume %d", LEFT_CHANNEL,
            RIGHT_CHANNEL, value);
      orig_MTAUD_SetChannelVolume(0, LEFT_CHANNEL, value);
      orig_MTAUD_SetChannelVolume(0, RIGHT_CHANNEL, value);
    }

    return orig_MTAUD_SetChannelVolume(decoder, channel, value);
}

int init_module(void) {
    word *p = (word *)kallsyms_lookup_name("_MTAUD_SetChannelVolume");
    if (!p) {
        printk(KERN_ERR "can't find symbol\n");
        return -ENOENT;
    }

    hook_fun((word *)p, my_MTAUD_SetChannelVolume, (word **)&orig_MTAUD_SetChannelVolume);
    DEBUG("loaded.");
	return 0;
}

void cleanup_module(void) {
    restore_fun((word **)&orig_MTAUD_SetChannelVolume);
    DEBUG("unloaded.");
}

MODULE_LICENSE("GPL");
