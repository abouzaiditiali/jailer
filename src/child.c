#define _GNU_SOURCE

#include "jailer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

void child_stop(pid_t pid)
{
    if (kill(pid, SIGKILL) == -1 && errno != ESRCH)
        perror("kill child");

    while (waitpid(pid, NULL, 0) == -1 && errno == EINTR)
        ;
}

int child_wait(pid_t pid, int *status, const sigset_t *signals,
               const char *jail_id)
{
    for (;;) {
        pid_t waited = waitpid(pid, status, WNOHANG);
        if (waited == pid)
            return 0;
        if (waited == -1) {
            perror("waitpid");
            return -1;
        }

        int received = sigwaitinfo(signals, NULL);
        if (received == -1) {
            if (errno == EINTR)
                continue;
            perror("sigwaitinfo");
            return -1;
        }

        if (received == SIGCHLD)
            continue;

        fprintf(stderr, "received signal %d; stopping jail %s\n",
                received, jail_id);
        child_stop(pid);
        return 128 + received;
    }
}

_Noreturn void child_run(const struct jail_config *config, int cgroup_fd,
                         int pipefd[2], const sigset_t *parent_signals)
{
    close(cgroup_fd);
    close(pipefd[1]);

    /* The workload must not inherit the parent's blocked signal mask. */
    if (sigprocmask(SIG_UNBLOCK, parent_signals, NULL) == -1)
        _exit(EXIT_FAILURE);

    char ready;
    if (read(pipefd[0], &ready, 1) != 1)
        _exit(EXIT_FAILURE);
    close(pipefd[0]);

    if (userns_set_child_identity() == -1)
        _exit(EXIT_FAILURE);

    if (rootfs_setup(config->rootfs) == -1)
        _exit(EXIT_FAILURE);

    if (security_lock_down() == -1)
        _exit(EXIT_FAILURE);

    char *child_argv[] = {"/program", NULL};
    char *child_env[] = {NULL};
    execve(child_argv[0], child_argv, child_env);

    perror("execve");
    _exit(127);
}
