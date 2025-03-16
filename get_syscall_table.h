#ifndef H_GET_SYSCALL_TABLE
#define H_GET_SYSCALL_TABLE

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/version.h>

// global ptr to syscall table
static void **syscall_table;

static uint64_t get_syscall_table_fallback(void) {
  uint64_t addr;
  struct kprobe kp = {.symbol_name = "do_syscall_64"};

  if (register_kprobe(&kp) < 0)
    return 0;

  // x86-64: sys_call_table находится по смещению 0x24
  addr = *(uint64_t *)((char *)kp.addr + 0x24);

  pr_err("Addr is %llu\n", addr);

  unregister_kprobe(&kp);
  return addr;
}

static __attribute__((unused)) uint64_t alternative_get_syscall_table_fallback(void) {
    struct file *filp;
    char buf[256], symname[128];
    loff_t pos = 0;
    ssize_t ret;
    uint64_t addr = 0;
    int found = 0;

    filp = filp_open("/proc/kallsyms", O_RDONLY, 0);
    if (IS_ERR(filp)) {
        pr_err("Failed to open /proc/kallsyms\n");
        return 0;
    }

    while ((ret = kernel_read(filp, buf, sizeof(buf)-1, &pos)) > 0) {
        char *ptr = buf;
        char *line;

        buf[ret] = '\0';

        // Обрабатываем каждую строку в буфере
        while ((line = strsep(&ptr, "\n")) != NULL) {
            if (sscanf(line, "%llx %*c %*s %127s", &addr, symname) == 2) {
                if (strcmp(symname, "sys_call_table") == 0) {
                    found = 1;
                    break;
                }
            }
        }

        if (found) break;
    }

    filp_close(filp, NULL);
    return found ? addr : 0;
}

#endif /* H_GET_SYSCALL_TABLE */