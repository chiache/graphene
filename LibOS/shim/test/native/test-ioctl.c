#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ioctl-dummy-driver/dummy.h"

int main(int argc, char **argv)
{
    int fd = open("/dev/dummy", O_RDWR);
    if (fd < 0) {
            perror("open");
            return 1;
    }

    for (int i = 1; i < argc; i++) {
        struct dummy_print arg;
        arg.str = argv[i];
        arg.size = strlen(argv[i]);

        if (ioctl(fd, DUMMY_IOCTL_PRINT, &arg)) {
            perror("ioctl");
            return 1;
        }
    }

    return 0;
}

