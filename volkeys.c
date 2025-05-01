#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>

#define DEBUG(fmt, args...)                                                    \
  printk(KERN_INFO KBUILD_MODNAME ": " fmt "\n", ##args)

static void (**ext_ir_rpc_init)(int, int, int, int) = NULL;
static void (*orig_callback)(int, int, int, int) = NULL;

static void callback(int type, int sys, int key, int val) {
  // DEBUG("callback(%d, %d, %d, %d)", type, sys, key, val);
  if (type == 2 && sys == 0 && (key == 114 || key == 115)) {
    char *key_name = key == 114 ? "VOLUME_DOWN" : "VOLUME_UP";
    char *direction = val ? "KEY_DOWN" : "KEY_UP";
    DEBUG("Ignoring %s %s", key_name, direction);
    return;
  }
  orig_callback(type, sys, key, val);
}

#define LOAD_SYMBOL(var, name)                                                 \
  do {                                                                         \
    var = (void *)kallsyms_lookup_name(name);                                  \
    if (!var) {                                                                \
      printk(KERN_ERR "can't find symbol \"" name "\"\n");                     \
      return -ENOENT;                                                          \
    }                                                                          \
    DEBUG(#var " = %p", var);                                                  \
  } while (0)

int init_module(void) {
  LOAD_SYMBOL(ext_ir_rpc_init, "ir_rpc_init");

  orig_callback = *ext_ir_rpc_init;
  DEBUG("orig_callback = %p", orig_callback);

  *ext_ir_rpc_init = callback;
  DEBUG("loaded.");

  return 0;
}

void cleanup_module(void) {
  *ext_ir_rpc_init = orig_callback;
  DEBUG("unloaded.");
}

MODULE_LICENSE("GPL");
