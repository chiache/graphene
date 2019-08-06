#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char** argv)
{
    int fd = open("/dev/random", O_RDWR);
    if (fd < 0) {
            perror("open");
            return 1;
    }

    void* mem = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_FILE,
                     fd, 0);

    if (mem != (void*)-1) {
        fprintf(stderr, "mapped /dev/host-random at %p\n", mem);
    } else {
        perror("mmap");
    }

    char data[16];
    if (read(fd, data, 16) < 0) {
        perror("file read");
        return 1;
    }

    return 0;
}

