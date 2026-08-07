#define _GNU_SOURCE

#include "jailer.h"

#include <grp.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>

static int proc_path(char *path, size_t size, pid_t pid, const char *file)
{
    int length = snprintf(path, size, "/proc/%d/%s", pid, file);
    if (length < 0 || (size_t)length >= size) {
        fprintf(stderr, "user namespace path is too long\n");
        return -1;
    }
    return 0;
}

int userns_write_maps(pid_t child_pid)
{
    char path[PATH_MAX];
    char mapping[64];

    if (proc_path(path, sizeof(path), child_pid, "setgroups") == -1 ||
        write_file(path, "deny\n") == -1)
        return -1;

    int length = snprintf(mapping, sizeof(mapping), "%u %u 1\n",
                          (unsigned int)QUICKC_NAMESPACE_UID,
                          (unsigned int)QUICKC_HOST_UID);
    if (length < 0 || (size_t)length >= sizeof(mapping))
        return -1;
    if (proc_path(path, sizeof(path), child_pid, "uid_map") == -1 ||
        write_file(path, mapping) == -1)
        return -1;

    length = snprintf(mapping, sizeof(mapping), "%u %u 1\n",
                      (unsigned int)QUICKC_NAMESPACE_GID,
                      (unsigned int)QUICKC_HOST_GID);
    if (length < 0 || (size_t)length >= sizeof(mapping))
        return -1;
    if (proc_path(path, sizeof(path), child_pid, "gid_map") == -1 ||
        write_file(path, mapping) == -1)
        return -1;

    return 0;
}

int userns_clear_supplementary_groups(void)
{
    if (setgroups(0, NULL) == -1) {
        perror("clear supplementary groups");
        return -1;
    }
    return 0;
}

int userns_set_child_identity(void)
{
    if (setresgid(QUICKC_NAMESPACE_GID, QUICKC_NAMESPACE_GID,
                  QUICKC_NAMESPACE_GID) == -1) {
        perror("set child GID");
        return -1;
    }

    if (setresuid(QUICKC_NAMESPACE_UID, QUICKC_NAMESPACE_UID,
                  QUICKC_NAMESPACE_UID) == -1) {
        perror("set child UID");
        return -1;
    }

    return 0;
}
