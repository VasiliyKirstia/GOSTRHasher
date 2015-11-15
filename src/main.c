#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "gostRHasher.h"


void printResult(uint8_t *data,long long length){
	for (long long i = length - 1; i > -1; --i) {
		printf("%x", (data[i] >> 4) );
		printf("%x", data[i] & 0b1111);
	};
	puts("");
}

int main (int argc, char* argv[]){
	int fd;
	HashCodeLength hash_lengt;

	if(argc > 1){
		fd = open(argv[1], O_RDONLY);
		if(-1 == fd){
			puts("can`t open file");
			return 1;
		}

		if(argc > 2){
			if( 0 == strcmp(argv[2], "256") ){
				hash_lengt = HASH_256;
			}
			else{
				if( 0 == strcmp(argv[2], "512") ){
					hash_lengt = HASH_512;
				}
				else{
					puts("unknown hash length");
					close(fd);
					return 1;
				}
			}
		}
		else{
			hash_lengt = HASH_512;
		}
	}
	else{
		puts("use: prog_name [file_for_hashing] [256|512]");
	}


	struct stat fs;
	fstat(fd, &fs);

	void *data = mmap(NULL, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);



	if(hash_lengt == HASH_256){
		uint8_t *dest[32];
		Encrypt(hash_lengt, data, fs.st_size * 8, dest);
		printResult(dest, 32);
	}
	else{
		if( hash_lengt == HASH_512 ){
			uint8_t *dest[64];
			Encrypt(hash_lengt, data, fs.st_size * 8, dest);
			printResult(dest, 64);
		}
	}
	return 0;
}

