#include "jailer.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int cgroup_open(const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd == -1)
        perror("open cgroup");
    return fd;
}

int cgroup_remove(const char *path)
{
    if (rmdir(path) == -1) {
        perror("remove cgroup");
        return -1;
    }
    return 0;
}
