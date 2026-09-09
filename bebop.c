static long w(int fd, const char *s, long n) {
    long r;
    __asm__ volatile("syscall" : "=a"(r)
        : "0"(1L), "D"((long)fd), "S"(s), "d"(n) : "rcx","r11","memory");
    return r;
}
static __attribute__((noreturn)) void ex(int c) {
    __asm__ volatile("syscall" : : "a"(60L), "D"((long)c));
    __builtin_unreachable();
}
static long readlink_s(const char *p, char *b, long n) {
    long r;
    __asm__ volatile("syscall" : "=a"(r)
        : "0"(89L), "D"(p), "S"(b), "d"(n) : "rcx","r11","memory");
    return r;
}
static long getpid_s(void) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "0"(39L) : "rcx","r11","memory");
    return r;
}
static long nanosleep_s(long sec) {
    long ts[2]; ts[0] = sec; ts[1] = 0;
    long r;
    __asm__ volatile("syscall" : "=a"(r)
        : "0"(35L), "D"(ts), "S"((long*)0) : "rcx","r11","memory");
    return r;
}

static long xstrlen(const char *s) { long n=0; while(s[n])n++; return n; }
static void puts_s(const char *s) { w(1, s, xstrlen(s)); }

static char *ltoa(long v, char *buf, int sz) {
    buf[--sz] = 0;
    if (v == 0) { buf[--sz] = '0'; return buf + sz; }
    while (v && sz > 1) { buf[--sz] = '0' + (v % 10); v /= 10; }
    return buf + sz;
}

void _start(void) {
    char exe[256] = {0};
    long n = readlink_s("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0) { exe[0]='?'; exe[1]=0; }

    long pid = getpid_s();
    char pidbuf[32];
    char *pidstr = ltoa(pid, pidbuf, sizeof(pidbuf));

    puts_s("\n[keyring exec] payload running\n");
    puts_s("  pid  -> ");
    puts_s(pidstr);
    puts_s("\n  exe  -> ");
    puts_s(exe);
    puts_s("\n  stored in kernel keyring, never on disk\n\n");
    puts_s("  sleeping for 30s, go check /proc/");
    puts_s(pidstr);
    puts_s("/fd  /proc/");
    puts_s(pidstr);
    puts_s("/maps  /proc/");
    puts_s(pidstr);
    puts_s("/exe\n\n");

    nanosleep_s(30);
    ex(0);
}
