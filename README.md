# quickC jailer

A minimal Linux single-process container runtime for statically linked executables.

## Files

- `src/main.c` — creates one child, handles signals, and cleans up
- `src/child.c` — child startup plus forced stop/reap behavior
- `src/cgroup.c` — opens and later removes a prepared jail cgroup
- `src/userns.c` — maps and selects the unprivileged workload identity
- `src/rootfs.c` — installs the jail root using `pivot_root`
- `src/security.c` — removes capabilities and prevents privilege gain
- `src/util.c` — writes values to procfs and cgroupfs files
- `include/jailer.h` — shared configuration and function declarations

## Functionality

- New user, PID, mount, network, UTS, and IPC namespaces
- UID/GID mapping to a dedicated host account
- pivot_root() filesystem isolation
- Preconfigured cgroup resource limits
- Capability removal
- no_new_privs
- Inherited file-descriptor cleanup
- Signal handling, child reaping, and cgroup cleanup
- Empty environment and one static /program
