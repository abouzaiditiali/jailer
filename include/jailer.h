#ifndef QUICKC_JAILER_H
#define QUICKC_JAILER_H

#include <signal.h>
#include <sys/types.h>

struct jail_config {
    const char *jail_id;
    const char *rootfs;
    const char *cgroup;
};

#define QUICKC_NAMESPACE_UID ((uid_t)1000)
#define QUICKC_NAMESPACE_GID ((gid_t)1000)
#define QUICKC_HOST_UID      ((uid_t)999)
#define QUICKC_HOST_GID      ((gid_t)983)

int write_file(const char *path, const char *contents);

int cgroup_open(const char *path);
int cgroup_remove(const char *path);

int userns_clear_supplementary_groups(void);
int userns_write_maps(pid_t child_pid);
int userns_set_child_identity(void);

int rootfs_setup(const char *rootfs);
int security_lock_down(void);

void child_stop(pid_t pid);
int child_wait(pid_t pid, int *status, const sigset_t *signals,
               const char *jail_id);
_Noreturn void child_run(const struct jail_config *config, int cgroup_fd,
                         int pipefd[2], const sigset_t *parent_signals);

#endif
