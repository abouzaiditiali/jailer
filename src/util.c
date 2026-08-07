#include "jailer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int write_file(const char *path, const char *contents)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1) {
        perror(path);
        return -1;
    }

    size_t remaining = strlen(contents);
    const char *cursor = contents;

    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written == -1 && errno == EINTR)
            continue;
        if (written <= 0) {
            perror(path);
            close(fd);
            return -1;
        }
        cursor += written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1) {
        perror("close");
        return -1;
    }

    return 0;
}
