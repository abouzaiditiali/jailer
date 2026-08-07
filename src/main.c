#define _GNU_SOURCE

#include "jailer.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int read_config(int argc, char *argv[], struct jail_config *config)
{
    if (argc != 4) {
        fprintf(stderr, "Usage: %s JAIL_ID ROOTFS CGROUP\n", argv[0]);
        return -1;
    }

    *config = (struct jail_config) {
        .jail_id = argv[1],
        .rootfs = argv[2],
        .cgroup = argv[3],
    };
    return 0;
}

static int block_parent_signals(sigset_t *signals)
{
    sigemptyset(signals);
    sigaddset(signals, SIGINT);
    sigaddset(signals, SIGTERM);
    sigaddset(signals, SIGHUP);
    sigaddset(signals, SIGQUIT);
    sigaddset(signals, SIGPIPE);
    sigaddset(signals, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, signals, NULL) == -1) {
        perror("block signals");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct jail_config config;
    if (read_config(argc, argv, &config) == -1)
        return EXIT_FAILURE;

    /* Block before clone so there is no signal race while creating the child. */
    sigset_t parent_signals;
    if (block_parent_signals(&parent_signals) == -1)
        return EXIT_FAILURE;

    /* The child cannot clear these after setgroups is denied for its GID map. */
    if (userns_clear_supplementary_groups() == -1)
        return EXIT_FAILURE;

    int cgroup_fd = cgroup_open(config.cgroup);
    if (cgroup_fd == -1)
        return EXIT_FAILURE;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        perror("pipe2");
        close(cgroup_fd);
        cgroup_remove(config.cgroup);
        return EXIT_FAILURE;
    }

    struct clone_args args = {
        .flags = CLONE_INTO_CGROUP | CLONE_NEWIPC | CLONE_NEWNET |
                 CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWUTS,
        .exit_signal = SIGCHLD,
        .cgroup = (unsigned long long)cgroup_fd,
    };

    pid_t pid = (pid_t)syscall(SYS_clone3, &args, sizeof(args));
    if (pid == -1) {
        perror("clone3");
        close(pipefd[0]);
        close(pipefd[1]);
        close(cgroup_fd);
        cgroup_remove(config.cgroup);
        return EXIT_FAILURE;
    }

    if (pid == 0)
        child_run(&config, cgroup_fd, pipefd, &parent_signals);

    close(cgroup_fd);
    close(pipefd[0]);

    if (userns_write_maps(pid) == -1) {
        close(pipefd[1]);
        child_stop(pid);
        cgroup_remove(config.cgroup);
        return EXIT_FAILURE;
    }

    char ready = 'X';
    if (write(pipefd[1], &ready, 1) != 1) {
        perror("release child");
        close(pipefd[1]);
        child_stop(pid);
        cgroup_remove(config.cgroup);
        return EXIT_FAILURE;
    }
    close(pipefd[1]);

    int status;
    int wait_result = child_wait(pid, &status, &parent_signals,
                                 config.jail_id);
    if (wait_result == -1) {
        child_stop(pid);
        cgroup_remove(config.cgroup);
        return EXIT_FAILURE;
    }

    if (wait_result >= 128) {
        if (cgroup_remove(config.cgroup) == -1)
            return EXIT_FAILURE;
        return wait_result;
    }

    if (cgroup_remove(config.cgroup) == -1)
        return EXIT_FAILURE;

    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return EXIT_FAILURE;
}
