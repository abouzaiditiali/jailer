# quickC jailer

This directory contains one small Linux container runtime.

## Files

- `src/main.c` — creates one child, handles signals, and cleans up
- `src/child.c` — child startup plus forced stop/reap behavior
- `src/cgroup.c` — opens and later removes a prepared jail cgroup
- `src/userns.c` — maps and selects the unprivileged workload identity
- `src/rootfs.c` — installs the jail root using `pivot_root`
- `src/security.c` — removes capabilities and prevents privilege gain
- `src/util.c` — writes values to procfs and cgroupfs files
- `include/jailer.h` — shared configuration and function declarations

## Execution flow

```text
open the cgroup prepared by the trusted launcher
        ↓
clone one child into new namespaces and the cgroup
        ↓
install the UID/GID mapping 
        ↓
child selects namespace UID/GID 1000
        ↓
child installs its rootfs
        ↓
child sets no_new_privs and drops every capability
        ↓
execute /program
        ↓
parent reaps child and removes cgroup
```

## Rootfs layout

Each jail uses a directory directly under `/var/lib/quickc`:

```text
/var/lib/quickc/jail-1/
├── program
└── oldroot/
```

Run it with:

```sh
sudo ./jailer \
    jail-1 \
    /var/lib/quickc/jail-1 \
    /sys/fs/cgroup/quickc/jail-1
```
