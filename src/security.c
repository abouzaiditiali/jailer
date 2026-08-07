#define _GNU_SOURCE

#include "jailer.h"

#include <errno.h>
#include <linux/capability.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

static int drop_bounding_set(void)
{
    for (int capability = 0; ; capability++) {
        errno = 0;
        int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (present == -1 && errno == EINVAL)
            return 0;
        if (present == -1) {
            perror("read capability bounding set");
            return -1;
        }
        if (present == 1 &&
            prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) == -1) {
            perror("drop capability from bounding set");
            return -1;
        }
    }
}

static int clear_current_capabilities(void)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct empty[2] = {{0}};

    if (syscall(SYS_capset, &header, empty) == -1) {
        perror("clear capabilities");
        return -1;
    }
    return 0;
}

static int verify_lockdown(void)
{
    if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        fprintf(stderr, "no_new_privs verification failed\n");
        return -1;
    }

    for (int capability = 0; ; capability++) {
        errno = 0;
        int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
        if (present == -1 && errno == EINVAL)
            break;
        if (present != 0) {
            fprintf(stderr, "capability %d remains in bounding set\n",
                    capability);
            return -1;
        }

        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
                            capability, 0, 0);
        if (ambient != 0) {
            fprintf(stderr, "capability %d remains ambient\n", capability);
            return -1;
        }
    }

    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct current[2] = {{0}};
    if (syscall(SYS_capget, &header, current) == -1) {
        perror("read capabilities");
        return -1;
    }

    for (size_t i = 0; i < 2; i++) {
        if (current[i].effective != 0 || current[i].permitted != 0 ||
            current[i].inheritable != 0) {
            fprintf(stderr, "current capability set is not empty\n");
            return -1;
        }
    }

    return 0;
}

int security_lock_down(void)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("set no_new_privs");
        return -1;
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == -1) {
        perror("clear ambient capabilities");
        return -1;
    }

    if (drop_bounding_set() == -1)
        return -1;

    if (clear_current_capabilities() == -1)
        return -1;

    return verify_lockdown();
}
