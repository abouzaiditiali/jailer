#include <linux/sched.h>    /* Definition of struct clone_args */
#include <sched.h>          /* Definition of CLONE_* constants */
#include <sys/syscall.h>    /* Definition of SYS_* constants */
#include <unistd.h>

#include <sys/mount.h>


int create_cgroup(int jail_id) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/fs/cgroup/system.slice/quickC.slice/runtime.service/jails/jail-%d", jail_id);

    mkdir(path, 0755);

    char memory_path[PATH_MAX];
    char pids_path[PATH_MAX];
    char cpu_path[PATH_MAX];

    snprintf(memory_path, sizeof(memory_path), "%s/memory.max", path);
    snprintf(pids_path, sizeof(pids_path), "%s/pids.max", path);
    snprintf(cpu_path, sizeof(cpu_path), "%s/cpu.max", path);

    //configure cgroup limits
    write_file(memory_path, "268435456");
    write_file(pids_path, "32");
    write_file(cpu_path, "50000 100000");
    
    int cgfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgfd == -1) {
        perror("open cgroup");
        rmdir(path);
        return -1;
    }

    return cgfd;
}

int setup_rootfs(int jail_id) {
    /* change propagation type to private over whole tree */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount propagation failed");
        return -1;
    }

    /* locate rootfs for the specific jail */
    char rootfs[PATH_MAX];
    snprintf(rootfs, sizeof(rootfs), "/var/lib/quickC/rootfs/jail-%d", jail_id);
    
    /* new root must be a mount point so we bind mount it onto itself */
    if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL)) {
        perror("bind mount failed");
        return -1;
    }
    
    char oldroot[PATH_MAX];
    snprintf(oldroot, sizeof(oldroot), "/var/lib/quickC/rootfs/jail-%d/oldroot", jail_id);

    mkdir(oldroot, 0755);

    /* change root mount in the mount namespace of the calling process */
    syscall(SYS_pivot_root, rootfs, oldroot);
    chdir("/");
    
    umount2("/oldroot", MNT_DETACH);
    rmdir("/oldroot");

    return 0;    
}

int setup_clargs(struct clone_args *cl_args) {
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
        perror("create cgroup failed");
        return -1;
    }
    cl_args->cgroup = cgfd; //child never runs outside specified cgroup
    return 0;
}


int main(int argc, char* argv[]) {
    if (validate_arguments(argc, argv) 
    int jail_id = argv[1];

    /* setup clone arguments */
    struct clone_args cl_args = {0};
    if (setup_clargs(&cl_args) == -1) {
        perror("setup clargs");
        exit(EXIT_FAILURE);
    }

    /* call clone3 */
    pid_t pid = syscall(SYS_clone3, &cl_args, sizeof(cl_args));
    if (pid == -1) {
        perror("clone3");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        /*
        --Child inherits copy of file descriptor table. Both parent and child
        tables point to the same open files.
        */
        /* Child needs a mounted directory that can become its new root */
        if (setup_rootfs(jail_id) == -1) {
            exit(EXIT_FAILURE);
        }
        
        char exec_path[PATH_MAX];
        snprintf(exec_path, sizeof(exec_path), "/var/lib/quickC/rootfs/jail-%d/program", jail_id);
        execve(exec_path);

        //execve failed
        perror("execve");
        exit(EXIT_FAILURE).
    }

    int status;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status)) {
        //program succeeded or execve failed
        printf("Exited with code %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        //execve succeeded, program crashed
        printf("Killed by signal %d\n", WTERMSIG(status));
    }

    return 0;
}
