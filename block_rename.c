#include "get_syscall_table.h"
#include "config_params.h"

static char config_data[16];
static asmlinkage int64_t (*orig_renemeat2)(int32_t, const char __user *,
                                            int32_t, const char __user *,
                                            uint32_t);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
#define HAVE_RENEMEAT2
#endif

static int is_necessary_extension(const char *filename) {
  const char *dot = strrchr(filename, '.');

  return !strncmp(dot + 1, file_extension, strlen(file_extension));
}

static int read_first_bytes(const char *path, char *buffer) {
  struct file *file;
  loff_t pos = 0;

  int ret = 0;

  file = filp_open(path, O_RDONLY, 0);
  if (IS_ERR(file))
    return PTR_ERR(file);

  ret = kernel_read(file, buffer, NUMBER_OF_BYTES_TO_READ, &pos);
  filp_close(file, NULL);

  return ret < 0 ? ret : 0;
}

static int load_config(void) {
  return read_first_bytes(CONFIG_FILE, config_data);
}

static asmlinkage int64_t hooked_renameat2(int old_dif_fd,
                                           const char __user *old_path,
                                           int32_t new_dir_fd,
                                           const char __user *new_path,
                                           uint32_t flags) {
  int64_t ret;
  char buffer[PATH_MAX];

  ret = strncpy_from_user(buffer, old_path, PATH_MAX - 1);
  if (unlikely(ret < 0)) {
    pr_err("Failed to copy ptr from user space to kernel space\n");
    return -EFAULT;
  }
  buffer[PATH_MAX] = '\0';

  if (is_necessary_extension(buffer)) {
    char file_data[NUMBER_OF_BYTES_TO_READ] = {0};

    if (!read_first_bytes(old_path, file_data)) {
      if (!memcmp(file_data, config_data, NUMBER_OF_BYTES_TO_READ)) {
        return -EACCES;
      }
    }
  }

#ifdef HAVE_RENEMEAT2
  ret = orig_renemeat2(old_dif_fd, old_path, new_dir_fd, new_path, flags);
#else
  ret = orig_renemeat2(old_dif_fd, old_path, new_dir_fd, new_path);
#endif /* HAVE_RENEMEAT2 */

  return ret;
}

static void disable_write_protection(void) { write_cr0(read_cr0() & ~0x10000); }

static void enable_write_protection(void) { write_cr0(read_cr0() | 0x10000); }

static int __init mod_init(void) {
  int ret;

  syscall_table = (void **)get_syscall_table_fallback();
  if (unlikely(!syscall_table)) {
    pr_err("Failed to get syscall table\n");
    return -EINVAL;
  }

  if (unlikely((ret = load_config()) < 0)) {
    pr_err("Failed to read configuration file");
    return ret;
  }

  disable_write_protection();

#ifdef HAVE_RENEMEAT2
  orig_renemeat2 = syscall_table[__NR_renameat2];
  syscall_table[__NR_renameat2] = hooked_renameat2;
#else
  orig_renameat2 = syscall_table[__NR_rename];
  syscall_table[__NR_rename] = hooked_renameat2;
#endif
  enable_write_protection();

  pr_info("Module block rename succesfuel loaded!\n");

  return 0;
}

static void __exit mod_exit(void) {
  if (likely(syscall_table)) {
    disable_write_protection();
#ifdef HAVE_RENEMEAT2
    orig_renemeat2 = syscall_table[__NR_renameat2];
    syscall_table[__NR_renameat2] = hooked_renameat2;
#else
    orig_renameat2 = syscall_table[__NR_rename];
    syscall_table[__NR_rename] = hooked_renameat2;
#endif
    enable_write_protection();
  }

  pr_info("Module block rename succesfuel unloaded!\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Made by Ghosttty");
MODULE_DESCRIPTION("Prevent renaming of protected .txt files");