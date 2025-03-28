/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <syscall.h>
#include <asm/current.h>

KPM_NAME("anti_debug_kpm");
KPM_VERSION("2.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Bypass advanced debugger detection techniques");

static enum hook_type hook_type = INLINE_CHAIN;

// === Manual strstr replacement ===
static char *local_strstr(const char *haystack, const char *needle)
{
    if (!*needle) return (char *)haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n && *h == *n) {
            ++h;
            ++n;
        }
        if (!*n) return (char *)haystack;
    }
    return NULL;
}

// === Safe copy from user without using copy_from_user symbol ===
static int safe_copy_user_string(char *dst, const char __user *src, int maxlen) {
    int i;
    long result;
    char ch;
    for (i = 0; i < maxlen - 1; i++) {
        asm volatile (
            "mov x0, %2\n"
            "mov x1, %3\n"
            "mov x2, #1\n"
            "mov x8, #217\n"   // sys_read (compatible syscall)
            "svc #0\n"
            "mov %0, x0\n"
            : "=r" (result)
            : "0"(result), "r"(dst + i), "r"(src + i)
            : "x0", "x1", "x2", "x8"
        );
        if (result != 0)
            return -1;
        ch = *(dst + i);
        if (ch == '\0') break;
    }
    dst[i] = '\0';
    return i;
}

// === ptrace hook ===
void before_ptrace(hook_fargs4_t *args, void *udata)
{
    pr_info("[anti-debug] ptrace called, spoofing return\n");
    args->ret = 0;
}

// === getppid hook ===
asmlinkage long fake_getppid(unsigned long a1, unsigned long a2, unsigned long a3,
                             unsigned long a4, unsigned long a5, unsigned long a6)
{
    pr_info("[anti-debug] getppid spoofed\n");
    return 1; // Fake PID
}

// === openat hook ===
void before_openat(hook_fargs4_t *args, void *udata)
{
    const char __user *filename = (typeof(filename))syscall_argn(args, 1);
    char buf[256];
    for (int i = 0; i < 256; i++) buf[i] = 0;

    if (safe_copy_user_string(buf, filename, sizeof(buf)) <= 0) return;

    if (buf[0] &&
        (local_strstr(buf, "/proc/self/status") ||
         local_strstr(buf, "/proc/self/pagemap") ||
         local_strstr(buf, "/proc/self/mem") ||
         local_strstr(buf, "/proc/self/maps") ||
         (local_strstr(buf, "/proc/self/task/") &&
          (local_strstr(buf, "/status") ||
           local_strstr(buf, "/comm") ||
           local_strstr(buf, "/mem") ||
           local_strstr(buf, "/pagemap"))))) {

        pr_info("[anti-debug] blocked openat: %s\n", buf);
        args->ret = -ENOENT;
    }
}

// === readlink hook ===
void before_readlink(hook_fargs3_t *args, void *udata)
{
    const char __user *path = (typeof(path))syscall_argn(args, 0);
    char buf[256];
    for (int i = 0; i < 256; i++) buf[i] = 0;

    if (safe_copy_user_string(buf, path, sizeof(buf)) <= 0) return;

    if (local_strstr(buf, "/proc/self/exe") || local_strstr(buf, "maps")) {
        pr_info("[anti-debug] blocked readlink: %s\n", buf);
        args->ret = -ENOENT;
    }
}

// === INIT ===
static long anti_debug_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("[anti-debug] init\n");

    hook_err_t err = 0;

    err |= inline_hook_syscalln(__NR_ptrace, 4, before_ptrace, 0, 0);
    err |= fp_hook_syscalln(__NR_getppid, 6, 0, fake_getppid, 0);
    err |= inline_hook_syscalln(__NR_openat, 4, before_openat, 0, 0);
    err |= inline_hook_syscalln(__NR_readlink, 3, before_readlink, 0, 0);

    if (err)
        pr_err("[anti-debug] Hook failed: %d\n", err);
    else
        pr_info("[anti-debug] All hooks installed successfully\n");

    return 0;
}

// === CTL & EXIT ===
static long anti_debug_ctl(const char *args, char *__user out_msg, int outlen)
{
    pr_info("[anti-debug] control called: %s\n", args);
    return 0;
}

static long anti_debug_exit(void *__user reserved)
{
    pr_info("[anti-debug] exit\n");

    inline_unhook_syscalln(__NR_ptrace, before_ptrace, 0);
    fp_unhook_syscalln(__NR_getppid, 0, fake_getppid);
    inline_unhook_syscalln(__NR_openat, before_openat, 0);
    inline_unhook_syscalln(__NR_readlink, before_readlink, 0);

    return 0;
}

KPM_INIT(anti_debug_init);
KPM_CTL0(anti_debug_ctl);
KPM_EXIT(anti_debug_exit);
