/*
 * shmem2.c: Simple program to read/write from/to any location in shared memory file.
 *
 *  Copyright (C) 2000, Jan-Derk Bakker (jdb@lartmaker.nl)
 *  Copyright (C) 2021, Rick Wertenbroek (rick.wertenbroek@heig-vd.ch)
 *
 *
 * This software has been developed for the LART computing board
 * (http://www.lart.tudelft.nl/). The development has been sponsored by
 * the Mobile MultiMedia Communications (http://www.mmc.tudelft.nl/)
 * and Ubiquitous Communications (http://www.ubicom.tudelft.nl/)
 * projects.
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

// Link with -lrt
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

#define FATAL do { fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
  __LINE__, __FILE__, errno, strerror(errno)); exit(1); } while(0)

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

int main(int argc, char **argv) {
    int fd;
    void *map_base, *virt_addr;
	u_int64_t read_result, writeval;
	off_t target;
	int access_type = 'w';

	if(argc < 3) {
		fprintf(stderr, "\nUsage:\t%s { shm file } { address } [ type [ data ] ]\n"
			"\tshm file : filename as in /dev/shm/filename, full path\n"
			"\taddress  : memory address to act upon\n"
			"\ttype     : access operation type : [b]yte 8-bit, [h]alfword 16-bit, [w]ord 32-bit, [d]oubleword 64-bit\n"
			"\tdata     : data to be written\n\n",
			argv[0]);
		exit(1);
	}
	target = strtoul(argv[2], 0, 0);

	if(argc > 3)
		access_type = tolower(argv[3][0]);


    if((fd = open(argv[1], O_RDWR | O_SYNC, 0)) == -1) FATAL;
    printf("%s opened.\n", argv[1]);
    fflush(stdout);

    /* Map one page */
    map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
    if(map_base == (void *) -1) FATAL;
    printf("Memory mapped at address %p.\n", map_base);
    fflush(stdout);

    virt_addr = map_base + (target & MAP_MASK);
    switch(access_type) {
		case 'b':
			read_result = *((u_int8_t *) virt_addr);
			break;
		case 'h':
			read_result = *((u_int16_t *) virt_addr);
			break;
		case 'w':
			read_result = *((u_int32_t *) virt_addr);
			break;
		case 'd':
			read_result = *((u_int64_t *) virt_addr);
			break;
		default:
			fprintf(stderr, "Illegal data type '%c'.\n", access_type);
			exit(2);
	}
    printf("Value at address 0x%lX (%p): 0x%llX\n", target, virt_addr, read_result);
    fflush(stdout);

	if(argc > 4) {
		writeval = strtoull(argv[4], 0, 0);
		switch(access_type) {
			case 'b':
				*((u_int8_t *) virt_addr) = writeval;
				read_result = *((u_int8_t *) virt_addr);
				break;
			case 'h':
				*((u_int16_t *) virt_addr) = writeval;
				read_result = *((u_int16_t *) virt_addr);
				break;
			case 'w':
				*((u_int32_t *) virt_addr) = writeval;
				read_result = *((u_int32_t *) virt_addr);
				break;
			case 'd':
				*((u_int64_t *) virt_addr) = writeval;
				read_result = *((u_int64_t *) virt_addr);
				break;
		}
		printf("Written 0x%llX; readback 0x%llX\n", writeval, read_result);
		fflush(stdout);
	}

	if(munmap(map_base, MAP_SIZE) == -1) FATAL;
    close(fd);
    return 0;
}

