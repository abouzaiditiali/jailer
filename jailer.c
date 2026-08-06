#include <linux/sched.h>    /* Definition of struct clone_args */
#include <sched.h>          /* Definition of CLONE_* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>

#include <sys/mount.h>


int create_cgroup(int jail_id) {
    char path[PATH_MAX];
    char memory_path[PATH_MAX];
    char pids_path[PATH_MAX];
    char cpu_path[PATH_MAX];

    /* build paths for cgroup and resource controllers */
    if (snprintf(path, sizeof(path), "/sys/fs/cgroup/system.slice/quickC.slice/runtime.service/jails/jail-%d", jail_id) < 0) {
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
        return -1;
    }
    //number of tasks allowed (threads)
    if (write_file(pids_path, "1") == -1) {
        return -1;
    }
    //For every 100,000 microseconds = 100 ms, the tasks in this cgroup are 
    //allowed to run for a total of 50,000 microseconds = 50 ms
    if (write_file(cpu_path, "50000 100000") == -1) {
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

    if (mkdir(oldroot, 0755) == -1) {
        perror("mkdir oldroot setup_rootfs");   
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

    if (rmdir("/oldroot") == -1) {
        perror("rmdir oldroot setup_rootfs");
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

int extract_argument(int argc, char* argv[]) {
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
    if (snprintf(uid_map_path, sizeof(uid_map_path), "/proc/%d/uid_map_path", cpid) < 0) {
        perror("snprintf uid_map_path setup_userspace");
        return -1;
    }
    if (snprintf(gid_map_path, sizeof(gid_map_path), "/proc/%d/gid_map_path", cpid) < 0) {
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

int main(int argc, char* argv[]) {
    /* extract arguments */
    int jail_id = extract_argument(argc, argv);
    if (jail_id == -1) {
        exit(EXIT_FAILURE);
    }

    /* setup clone arguments + create cgroup */
    struct clone_args cl_args = {0};
    if (setup_clone_arguments(&cl_args, jail_id) == -1) {
        exit(EXIT_FAILURE);
    }
    //new cgroup directory created for current jail at path + open cgfd 
    //make sure to delete directory at path. cgfd will be closed on child exec

    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) == -1) {
        err(EXIT_FAILURE, "pipe2");
    }

    /* call clone3 */
    pid_t pid = syscall(SYS_clone3, &cl_args, sizeof(cl_args));
    if (pid == -1) {
        err(EXIT_FAILURE, "SYS_clone3 main");
    }

    if (pid == 0) { 
        if (close(pipefd[1]) == -1) {
            err(EXIT_FAILURE, "close write end child"); 
        }
        char c;
        /* sleeps until write end is written to, fails if write end is closed */
        /* waits for parent to setup UID/GID mappings for new userspace */
        if (read(pipefd[0], &c, 1) != 1) {
            _exit(EXIT_FAILURE);
        }
        if (close(pipefd[0]) == -1) {
            err(EXIT_FAILURE, "close read end child");
        }
        
        /* private propagation + bind mount + pivot_root */
        if (setup_rootfs(jail_id) == -1) {
            _exit(EXIT_FAILURE);
        }
        
        /* execute 'arbitrary' C code */
        char *child_argv[] = {"/program", NULL};
        char *env[] = {NULL}; //start child with empty environment
        execve("/program", child_argv, env);

        //execve failed
        perror("execve");
        _exit(EXIT_FAILURE);
    }
    
    if (close(pipefd[0]) == -1) {
        err(EXIT_FAILURE, "close read end parent");
    }
    if (setup_userspace(pid) == -1) {
        //close on success will have read return 0 (EOF) in child
        //child exits with failure
        if (close(pipefd[1]) == -1) {
            err(EXIT_FAILURE, "close write end parent");  
        }
        fprintf(stderr, "setup_userspace failed");
    } else {
        char ready = 'X';
        if (write(pipefd[1], &ready, 1)  != 1) {
            err(EXIT_FAILURE, "write to write end parent");   
        }
        if (close(pipefd[1]) == -1) {
            err(EXIT_FAILURE, "close write end parent");  
        }
    }
    

    int status;
    if (waitpid(pid, &status, 0) == -1) {
        perror("waitpid main");
        exit(EXIT_FAILURE);
    }
    if (WIFEXITED(status)) {
        //program succeeded or execve failed
        printf("Exited with code %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        //execve succeeded, program crashed
        printf("Killed by signal %d\n", WTERMSIG(status));
    }

    return 0;
}
