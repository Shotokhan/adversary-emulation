#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>


#define MAP_SIZE 4096UL


int do_shmem(char* filename, off_t target, size_t len, u_int8_t* read_result, u_int8_t* write_data) {
    // performs write if write_data is not NULL
    unsigned long map_size = MAP_SIZE;
    while ((len * 8) > map_size) {
        map_size = map_size * 2;
    }
    unsigned long map_mask = map_size - 1;
    int fd;
    void *map_base, *virt_addr;
    if((fd = open(filename, O_RDWR | O_SYNC, 0)) == -1) return 1;
    map_base = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~map_mask);
    if(map_base == (void *) -1) return 2;
    virt_addr = map_base + (target & map_mask);
    for (unsigned int i=0; i<len; i++) {
        read_result[i] = *((u_int8_t *) virt_addr + i);
        if (write_data != (u_int8_t*) NULL) {
            *((u_int8_t *) virt_addr + i) = write_data[i];
        }
    }
    munmap(map_base, map_size);
    close(fd);
    return 0;
}



int main(int argc, char **argv) {
    printf("This is a shared library: use the exported 'do_shmem' function.\n");
    return 0;
}

 
