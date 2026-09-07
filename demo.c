#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static void print_separator(void) {
    printf("─────────────────────────────────────────\n");
}

static void show_proc_exe(void) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0)
        printf("  /proc/self/exe  ->  %s\n", exe);
    else
        printf("  /proc/self/exe  ->  (unreadable)\n");
}

static void show_proc_name(void) {
    char name[64] = {0};
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Name:", 5) == 0) {
            char *p = line + 5;
            while (*p == '\t' || *p == ' ') p++;
            p[strcspn(p, "\n")] = 0;
            printf("  process name    ->  %s\n", p);
            break;
        }
    }
    fclose(f);
}

static void show_maps_excerpt(void) {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    int shown = 0;
    printf("  /proc/self/maps (executable regions):\n");
    while (fgets(line, sizeof(line), f) && shown < 6) {
        if (strstr(line, "r-xp") || strstr(line, "r--p")) {
            line[strcspn(line, "\n")] = 0;
            printf("    %s\n", line);
            shown++;
        }
    }
    fclose(f);
}

static void check_on_disk(void) {
    char exe[512] = {0};
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n <= 0) { printf("  on disk        ->  unknown\n"); return; }

    char path[512];
    strncpy(path, exe, sizeof(path) - 1);
    char *del = strstr(path, " (deleted)");
    if (del) *del = 0;

    struct stat st;
    if (stat(path, &st) == 0)
        printf("  on disk        ->  YES (inode %lu)\n", (unsigned long)st.st_ino);
    else
        printf("  on disk        ->  NO  (no directory entry)\n");
}

int main(int argc, char *argv[]) {
    printf("\n");
    print_separator();
    printf("  FILELESS PAYLOAD RUNNING\n");
    print_separator();
    printf("  pid             ->  %d\n", getpid());
    printf("  argv[0]         ->  %s\n", argv[0]);
    show_proc_name();
    show_proc_exe();
    check_on_disk();
    print_separator();
    show_maps_excerpt();
    print_separator();
    printf("\n");
    return 0;
}
