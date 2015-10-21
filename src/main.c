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
	puts("\n");
}

typedef struct {
	uint8_t *array;
	long long int length;
}ArrayOfByte;

ArrayOfByte convertToArray(char *str, long long int length){
	long long int a_len = (length >> 1) + (length & 1); //количество байтов требуемое для хранения результата.
	uint8_t *buff = calloc(a_len, sizeof(uint8_t));

	long long int j = 0;
	for(long long int i = length - 1; i > -1; --i){
		switch (str[i]) {
			case '0':
				buff[ j>>1 ] += 0U << ( (j & 1)*4 );
				break;
			case '1':
				buff[ j>>1 ] += 1U << ( (j & 1)*4 );
				break;
			case '2':
				buff[ j>>1 ] += 2U << ( (j & 1)*4 );
				break;
			case '3':
				buff[ j>>1 ] += 3U << ( (j & 1)*4 );
				break;
			case '4':
				buff[ j>>1 ] += 4U << ( (j & 1)*4 );
				break;
			case '5':
				buff[ j>>1 ] += 5U << ( (j & 1)*4 );
				break;
			case '6':
				buff[ j>>1 ] += 6U << ( (j & 1)*4 );
				break;
			case '7':
				buff[ j>>1 ] += 7U << ( (j & 1)*4 );
				break;
			case '8':
				buff[ j>>1 ] += 8U << ( (j & 1)*4 );
				break;
			case '9':
				buff[ j>>1 ] += 9U << ( (j & 1)*4 );
				break;
			case 'a':
			case 'A':
				buff[ j>>1 ] += 10U << ( (j & 1)*4 );
				break;
			case 'b':
			case 'B':
				buff[ j>>1 ] += 11U << ( (j & 1)*4 );
				break;
			case 'c':
			case 'C':
				buff[ j>>1 ] += 12U << ( (j & 1)*4 );
				break;
			case 'd':
			case 'D':
				buff[ j>>1 ] += 13U << ( (j & 1)*4 );
				break;
			case 'e':
			case 'E':
				buff[ j>>1 ] += 14U << ( (j & 1)*4 );
				break;
			case 'f':
			case 'F':
				buff[ j>>1 ] += 15U << ( (j & 1)*4 );
				break;
			default:
				puts("ERROR");
				exit(1);
				break;
		}

		++j;
	}

	ArrayOfByte result;
	result.array = buff;
	result.length = a_len;

	return result;
}

int main (void){
	int fd = open("/tmp/f2", O_RDONLY);

	struct stat fs;
	fstat(fd, &fs);

	void *data = mmap(NULL, fs.st_size, PROT_READ, MAP_SHARED, fd, 0);

	uint8_t *dest[64];

	Encrypt(HASH_512, data, fs.st_size * 8, dest);
	printResult(dest, 64);
	return 0;
}

