/*
 * devmem2.c: Simple program to read/write from/to any location in memory.
 *
 *  Copyright (C) 2000, Jan-Derk Bakker (jdb@lartmaker.nl)
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
 *  Copyright (C) 2024, Mani Subramaniyan(mani.subramaniyan@gmail.com)
 *  Adding options to read/write 64 bits, read/write arbitrary lengths, write patterns
 *  Adding option to avoid reading back for writes!
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
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
 
#define MAP_PAGESIZE 4096UL
#define MAP_MASK (MAP_PAGESIZE - 1)
#define STAGE_BUF_SIZE	128

enum OP_Sizes {
	SIZE_UNKNOWN=0,
	SIZE_BYTE,
	SIZE_HW,
	SIZE_WORD,
	SIZE_DW,
	SIZE_BLOCK,
	SIZE_PATTERN,
};

enum OP_Types {
	OP_UNKNOWN=0,
	OP_READ,
	OP_READBLK,
	OP_WRITE,
	OP_WRITEBLK,
	OP_WRITEP
};
	
/* command line argument settings  and related global variables  with their defaults*/
bool	verify = true;
bool	writeop = false;
int 	access_length = SIZE_WORD;	
int	op_type = OP_READ;
uint64_t 	target =0;
uint64_t	writevalue=0;
uint64_t	tgt_length=0;


int process_args(int argc, char **argv) {

	char access =' ';
	uint64_t	numvalue=0;

	target = strtoul(argv[1], 0, 0);

	op_type = OP_UNKNOWN;
	access_length = SIZE_UNKNOWN;
	writeop=false;

	if(argc > 2) { //process access type
		access = tolower(argv[2][0]);

		switch (access) {
			case 'b': 
				access_length = SIZE_BYTE;
				break;
			case 'h': 
				access_length = SIZE_HW;
				break;
			case 'w': 
				access_length = SIZE_WORD;
				break;
			case 'd': 
				access_length = SIZE_DW;
				break;
			case 's':
				op_type = OP_READBLK;
				access_length = SIZE_BLOCK;
				break;
			case 'i':
				op_type = OP_WRITEBLK;
				access_length = SIZE_BLOCK;
				writeop=true;
				break;
			case 'p':
				op_type = OP_WRITEP;
				access_length = SIZE_BLOCK;
				writeop=true;
				break;
			default:
				fprintf(stderr, "\ninvalid access type =%c\n",access);
				access_length = SIZE_WORD;
				break;
		}
		// check for no verify option
		if(tolower(argv[2][1]) == 'n')
			verify = false;
		else	verify = true;
	}
	if(argc > 3) {
		numvalue = strtoul(argv[3], 0, 0);
		if (access_length== SIZE_BLOCK) // pattern write or set or show options?
			tgt_length = numvalue;
		else {
			if (argc == 4)	{
				writevalue = numvalue;	// simple writes up to 64bits
				op_type = OP_WRITE;
				writeop=true;
			}
			else {
				fprintf(stderr, "\ntoo many parameters?\n");
				return -1;
			}
		}
	}
	else if (access_length != SIZE_BLOCK)	// only simple read operations
		op_type = OP_READ;
	else  {
		fprintf(stderr, "\nNot enough parameters?\n");
		return -1;
	}
	if ((op_type == OP_WRITEP) && (argc == 5)) {
		writevalue = strtoul(argv[4], 0, 0);
	}
	return 0;
}

void print_buffer(uint8_t *buffer, size_t size, uint64_t alias_addr) {
    size_t offset = ((uint64_t)alias_addr) % 16;
    size_t i = 0,j=0;
    uint64_t lineaddr;

    // Print initial partial line if alias address is not 16-byte aligned
    offset = offset & ~3;	// floor to a word boundary always and print words always
    if (offset != 0) {
	lineaddr = (alias_addr - offset);
        printf("%08lx: ", alias_addr);
        for (j= 0; j < offset; j += 4) {
                printf("           ");
	}
	for (j; j < 16; j+=4) { 
		if (i <size)
			printf("%08x   ", *(uint32_t *)(buffer + i));
                i += 4;
        }
        printf("\n");
        alias_addr = (alias_addr + 16) & ~15;
    }

    // Print full lines
    while (i < size) {
        printf("%08lx: ", alias_addr);
        for (size_t j = 0; j < 16; j += 4) {
            if (i < size) {
                printf("%08x   ", *(uint32_t *)(buffer + i));
                i += 4;
            } else {
                printf("         ");
            }
        }
        printf("\n");
        alias_addr += 16;
    }
}

void print_data_block(uint64_t target, void *virt_addr,uint64_t tgt_length)
{
	uint8_t stagebuf[STAGE_BUF_SIZE];
	uint	start_offset =0;
	uint	newsize =0;

	start_offset = target & (STAGE_BUF_SIZE -1);
	
	if (start_offset) {
		newsize = STAGE_BUF_SIZE - start_offset;
		if (newsize > tgt_length) newsize = tgt_length;
		memcpy(&stagebuf[0], virt_addr,newsize);	// get a local copy of data from device memory
		print_buffer(&stagebuf[0],newsize,target);
		// move on to next section
		virt_addr += newsize;
		target += newsize;
		tgt_length -= newsize;
		
	}
	while (tgt_length > STAGE_BUF_SIZE) { // get and print one stage buffer at a time

		memcpy(stagebuf, virt_addr,STAGE_BUF_SIZE);	// get a local copy of data from device memory
		print_buffer(stagebuf,STAGE_BUF_SIZE,target);
		virt_addr += STAGE_BUF_SIZE;
		target += STAGE_BUF_SIZE;
		tgt_length -= STAGE_BUF_SIZE;
	}
	// now for the last reminder after the boundary
	if (tgt_length) {
		memcpy(stagebuf, virt_addr,tgt_length);	// get a local copy of data from device memory
		print_buffer(stagebuf,tgt_length,target);
	}
}


void write_and_print_block(uint64_t target,void *virt_addr,uint64_t tgt_length)
{
}


int main(int argc, char **argv) {
    int fd;
    void *map_base, *virt_addr; 
	int map_size =0; 
	unsigned long read_result = 0;
	
	if(argc < 2) {
		fprintf(stderr, "\nUsage:\t%s { address } [ type[attrib] [[length]  data ] ]\n"
			"\taddress : memory address to act upon\n"
			"\ttype    : access operation type : [b]yte, [h]alfword, [w]ord [d]oubleword [p]attern [i]nitialize [s]how\n"
			"\tattrib  : [n]o_verify/read back - only applies on write operations; ignored otherwise\n"
			"\tlength  : length for Pattern writes or show(read); not valid for others\n"
			"\tdata    : data to be written\n\n"
			" Example 1: %s 0xf8001000 wn 0x55AAAA55 - write 0x55aaaa55 to given address (no reads to verify)\n"
			" Example 2: %s 0xf8001000 p 0x100 0x55AAAA55 - write pattern repeating it for length of 0x100 bytes and verify it\n"
			" Example 3: %s 0xf8001000 s 0x100 - read and display contents of 0x100 bytes at target address\n"
			" Example 4: %s 0xf8001000 i 0x1122 0x3344 0x5566 0x7788 0x99xaa 0xbbcc - initialize arbitrary data and verify\n",
			argv[0],argv[0],argv[0],argv[0],argv[0]);
		exit(1);
	}

	if (process_args(argc,argv))
		exit(1);



    if((fd = open("/dev/mem", O_RDWR | O_SYNC)) == -1) FATAL;
    printf("/dev/mem opened.\n"); 
    fflush(stdout);
    
    /* Map as many pages as we need, taking into consideration start offset not aligned with the page boundary*/
    map_size = ((access_length == SIZE_BLOCK) ? (tgt_length + MAP_PAGESIZE - 1)/MAP_PAGESIZE : 1) * MAP_PAGESIZE;

    map_base = mmap(0, map_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, target & ~MAP_MASK);
    if(map_base == (void *) -1) FATAL;
    printf("Memory mapped at address %p.\n", map_base); 
    fflush(stdout);
    
    virt_addr = map_base + (target & MAP_MASK);
    if (!writeop || verify) {
	    switch(access_length) {
			case SIZE_BYTE:
				read_result = *((uint8_t *) virt_addr);
				break;
			case SIZE_HW:
				read_result = *((uint16_t *) virt_addr);
				break;
			case SIZE_WORD:
				read_result = *((uint32_t *) virt_addr);
				break;
			case SIZE_DW:
				read_result = *((uint64_t *) virt_addr);
				break;
			case SIZE_BLOCK:
				print_data_block(target, virt_addr,tgt_length);
				break;
			default:
				fprintf(stderr, "Illegal data type '%d'.\n", access_length);
				exit(2);
		}
	    if (access_length != SIZE_BLOCK)
		    printf("Value at address 0x%lX (%p): 0x%1lX\n", target, virt_addr, read_result); 
	    fflush(stdout);
	}
	if (writeop) {
		switch(access_length) {
			case SIZE_BYTE:
				*((uint8_t *) virt_addr) = writevalue;
				if (verify)
					read_result = *((uint8_t *) virt_addr);
				break;
			case SIZE_HW:
				*((uint16_t *) virt_addr) = writevalue;
				if (verify)
					read_result = *((uint16_t *) virt_addr);
				break;
			case SIZE_WORD:
				*((uint32_t *) virt_addr) = writevalue;
				if (verify)
					read_result = *((uint32_t *) virt_addr);
				printf("Written 0x%1lX; readback 0x%1lX\n", writevalue, read_result); 
				break;
			case SIZE_DW:
				*((uint64_t *) virt_addr) = writevalue;
				if (verify)
					read_result = *((uint64_t *) virt_addr);
				break;
			case SIZE_BLOCK:
				write_and_print_block(target,virt_addr,tgt_length);
				break;
		}
		if (access_length == SIZE_BLOCK) {
			if (verify)
				 print_data_block(target,virt_addr, tgt_length);
		}
		else {
			if (verify)
				printf("Written 0x%1lX; readback 0x%1lX\n", writevalue, read_result); 
			else
				printf("Written 0x%1lX\n", writevalue); 
		}
			
		fflush(stdout);
	}
	
	if(munmap(map_base, map_size) == -1) FATAL;
    close(fd);
    return 0;
}

