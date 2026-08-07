#define _GNU_SOURCE

#include "jailer.h"

#include <limits.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int rootfs_setup(const char *rootfs)
{
    char oldroot[PATH_MAX];

    int length = snprintf(oldroot, sizeof(oldroot), "%s/oldroot", rootfs);
    if (length < 0 || (size_t)length >= sizeof(oldroot)) {
        fprintf(stderr, "oldroot path is too long\n");
        return -1;
    }

    struct stat st;
    if (stat(oldroot, &st) == -1 || !S_ISDIR(st.st_mode)) {
        perror("oldroot must be an existing directory");
        return -1;
    }

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("make mounts private");
        return -1;
    }

    if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL) == -1) {
        perror("bind mount rootfs");
        return -1;
    }

    if (syscall(SYS_pivot_root, rootfs, oldroot) == -1) {
        perror("pivot_root");
        return -1;
    }

    if (chdir("/") == -1) {
        perror("chdir");
        return -1;
    }

    if (umount2("/oldroot", MNT_DETACH) == -1) {
        perror("unmount old root");
        return -1;
    }

    return 0;
}
