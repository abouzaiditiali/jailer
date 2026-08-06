#define _GNU_SOURCE

#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <err.h>
#include <string.h>
#include <errno.h>

int write_file(const char *path, const char *contents) {
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open write_file");
        return -1;
    }

    size_t len = strlen(contents);

    if (write(fd, contents, len) != (ssize_t)len) {
        perror("write write_file");
        if (close(fd) == -1) {
            perror("close write_file");
        }
        return -1;
    }

    if (close(fd) == -1) {
        perror("close 2 write_file");
        return -1;
    }
    return 0;
}

int rmdir_cgroup(int jail_id) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "/sys/fs/cgroup/quickc/jail-%d", jail_id) < 0) {
        perror("snprintf path remove_cgroup");
        return -1;
    }
    if (rmdir(path) == -1) {    
        perror("rmdir path remove_cgroup"); 
        return -1;
    }
    return 0;
}

int create_cgroup(int jail_id) {
    char path[PATH_MAX];
    char memory_path[PATH_MAX];
    char pids_path[PATH_MAX];
    char cpu_path[PATH_MAX];

    /* build paths for cgroup and resource controllers */
    if (snprintf(path, sizeof(path), "/sys/fs/cgroup/quickc/jail-%d", jail_id) < 0) {
        perror("snprintf path create_cgroup");
        return -1;
    }

    if (snprintf(memory_path, sizeof(memory_path), "%s/memory.max", path) < 0) {
        perror("snprintf memory_path create_cgroup");
        return -1;
    }
    if (snprintf(pids_path, sizeof(pids_path), "%s/pids.max", path) < 0) {
        perror("snprintf pids_path create_cgroup");
        return -1;
    }
    if (snprintf(cpu_path, sizeof(cpu_path), "%s/cpu.max", path) < 0) {
        perror("snprintf cpu_path create_cgroup");
        return -1;
    }

    /* create cgroup directory for the current jail */
    if (mkdir(path, 0755) == -1) {
        perror("mkdir path create_cgroup");
        return -1;
    }

    /* configure cgroup limits */
    //64 × 1024 × 1024 = 67,108,864 bytes
    if (write_file(memory_path, "67108864") == -1) {
        rmdir_cgroup(jail_id);
        return -1;
    }
    //number of tasks allowed (threads)
    if (write_file(pids_path, "1") == -1) {
        rmdir_cgroup(jail_id);
        return -1;
    }
    //For every 100,000 microseconds = 100 ms, the tasks in this cgroup are 
    //allowed to run for a total of 50,000 microseconds = 50 ms
    if (write_file(cpu_path, "50000 100000") == -1) {
        rmdir_cgroup(jail_id);
        return -1;
    }
    
    int cgfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    //set close-on-exec flag so child program doesn't inherit cgfd on exec
    if (cgfd == -1) {
        perror("open path create_cgroup");
        if (rmdir(path) == -1) {
            perror("rmdir path create_cgroup");
        }
        return -1;
    }

    return cgfd;
}

int setup_rootfs(int jail_id) {
    /* change propagation type to private over whole tree */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount propagation setup_rootfs");
        return -1;
    }

    /* locate rootfs for the current jail */
    //consider overlayFS later on
    char rootfs[PATH_MAX];
    if (snprintf(rootfs, sizeof(rootfs), "/var/lib/quickC/rootfs/jail-%d", jail_id) < 0) {
        perror("snprintf rootfs setup_rootfs");
        return -1;
    }
    
    /* new root must be a mount point so we bind mount it onto itself */
    if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL)) {
        perror("mount bind setup_rootfs");
        return -1;
    }
    
    char oldroot[PATH_MAX];
    if (snprintf(oldroot, sizeof(oldroot), "/var/lib/quickC/rootfs/jail-%d/oldroot", jail_id) < 0) {
        perror("snprintf oldroot setup_rootfs");
        return -1;
    }

    /* oldroot must already exist */
    struct stat st;
    
    if (stat(oldroot, &st) == -1) {
        perror("stat oldroot");
        return -1;
    }
    
    if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "oldroot is not a directory\n");
        return -1;
    }

    /* change root mount in the mount namespace of the current jail */
    if (syscall(SYS_pivot_root, rootfs, oldroot) == -1) {
        perror("SYS_pivot_root setup_rootfs");
        return -1;
    }
    if (chdir("/") == -1) {
        perror("chdir setup_rootfs");
        return -1;
    }
    
    if (umount2("/oldroot", MNT_DETACH) == -1) {
        perror("umount2 oldroot setup_rootfs");
        return -1;
    }

    return 0;    
}

int setup_clone_arguments(struct clone_args *cl_args, int jail_id) {
    cl_args->exit_signal = SIGCHLD;
    cl_args->flags = CLONE_INTO_CGROUP | 
                    CLONE_NEWIPC | 
                    CLONE_NEWNET |
                    CLONE_NEWNS |
                    CLONE_NEWPID |
                    CLONE_NEWUSER |
                    CLONE_NEWUTS;

    int cgfd = create_cgroup(jail_id);
    if (cgfd == -1) {
        return -1;
    }
    cl_args->cgroup = cgfd; //child never runs outside specified cgroup
    return 0;
}

int extract_argument(int argc, char *argv[]) {
    if (argc != 2) { 
        fprintf(stderr, "Usage: %s <jail_id>\n", argv[0]);
        return -1;
    }
    char *endptr; //endptr points at the character immediately after the number 
    long jail_id = strtol(argv[1], &endptr, 10); //10 is base
    
    //handle more error cases, for now input is controlled
    return jail_id; 
}

int setup_userspace(pid_t cpid) {
    char setgroups_path[PATH_MAX];
    char uid_map_path[PATH_MAX];
    char gid_map_path[PATH_MAX];
    if (snprintf(setgroups_path, sizeof(setgroups_path), "/proc/%d/setgroups", cpid) < 0) {
        perror("snprintf setgroups_path setup_userspace");
        return -1;
    }
    if (snprintf(uid_map_path, sizeof(uid_map_path), "/proc/%d/uid_map", cpid) < 0) {
        perror("snprintf uid_map_path setup_userspace");
        return -1;
    }
    if (snprintf(gid_map_path, sizeof(gid_map_path), "/proc/%d/gid_map", cpid) < 0) {
        perror("snprintf gid_map_path setup_userspace");
        return -1;
    }
    if (write_file(setgroups_path, "deny\n") == -1) {
        return -1;
    }
        
    //create an actual unprivileged user for running jails and change these
    //jailUID HostUID
    if (write_file(uid_map_path, "0 1000 1\n") == -1) {
        return -1;
    }
    if (write_file(gid_map_path, "0 1000 1\n") == -1) {
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int jail_id = extract_argument(argc, argv);
    if (jail_id == -1)
        return EXIT_FAILURE;

    struct clone_args cl_args = {0};
    if (setup_clone_arguments(&cl_args, jail_id) == -1)
        return EXIT_FAILURE;

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        perror("pipe2");
        close((int)cl_args.cgroup);
        rmdir_cgroup(jail_id);
        return EXIT_FAILURE;
    }

    pid_t pid = (pid_t)syscall(SYS_clone3, &cl_args, sizeof(cl_args));
    if (pid == -1) {
        perror("clone3");
        close(pipefd[0]);
        close(pipefd[1]);
        close((int)cl_args.cgroup);
        rmdir_cgroup(jail_id);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        close((int)cl_args.cgroup);
        close(pipefd[1]);

        char c;
        if (read(pipefd[0], &c, 1) != 1)
            _exit(EXIT_FAILURE);

        close(pipefd[0]);

        if (setup_rootfs(jail_id) == -1)
            _exit(EXIT_FAILURE);

        char *child_argv[] = {"/program", NULL};
        char *env[] = {NULL};
        execve("/program", child_argv, env);

        perror("execve");
        _exit(127);
    }

    /* Only the parent reaches this point. */
    close((int)cl_args.cgroup);
    close(pipefd[0]);

    if (setup_userspace(pid) == -1) {
        /* Closing the pipe wakes the blocked child with EOF. */
        close(pipefd[1]);
        waitpid(pid, NULL, 0);
        rmdir_cgroup(jail_id);
        return EXIT_FAILURE;
    }

    char ready = 'X';
    if (write(pipefd[1], &ready, 1) != 1) {
        perror("release child");
        close(pipefd[1]);
        waitpid(pid, NULL, 0);
        rmdir_cgroup(jail_id);
        return EXIT_FAILURE;
    }
    close(pipefd[1]);

    int status;
    pid_t waited;

    do {
        waited = waitpid(pid, &status, 0);
    } while (waited == -1 && errno == EINTR);

    if (waited == -1) {
        perror("waitpid");
        rmdir_cgroup(jail_id);
        return EXIT_FAILURE;
    }

    /* The only child is gone, so its cgroup is now empty. */
    if (rmdir_cgroup(jail_id) == -1) {
        return EXIT_FAILURE;
    }

    if (WIFEXITED(status)) {
        printf("Exited with code %d\n", WEXITSTATUS(status));
        return WEXITSTATUS(status);
    }

    if (WIFSIGNALED(status)) {
        printf("Killed by signal %d\n", WTERMSIG(status));
        return 128 + WTERMSIG(status);
    }

    return EXIT_FAILURE;
}
