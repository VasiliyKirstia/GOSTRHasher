#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>

typedef enum{HASH_512,HASH_256}HashCodeLength;

// Матрица над полем GF(2) в шестнадцатеричном виде
const uint64_t Matrix_64[64] =
{
	0x8e20faa72ba0b470UL, 0x47107ddd9b505a38UL, 0xad08b0e0c3282d1cUL, 0xd8045870ef14980eUL,
	0x6c022c38f90a4c07UL, 0x3601161cf205268dUL, 0x1b8e0b0e798c13c8UL, 0x83478b07b2468764UL,
	0xa011d380818e8f40UL, 0x5086e740ce47c920UL, 0x2843fd2067adea10UL, 0x14aff010bdd87508UL,
	0x0ad97808d06cb404UL, 0x05e23c0468365a02UL, 0x8c711e02341b2d01UL, 0x46b60f011a83988eUL,
	0x90dab52a387ae76fUL, 0x486dd4151c3dfdb9UL, 0x24b86a840e90f0d2UL, 0x125c354207487869UL,
	0x092e94218d243cbaUL, 0x8a174a9ec8121e5dUL, 0x4585254f64090fa0UL, 0xaccc9ca9328a8950UL,
	0x9d4df05d5f661451UL, 0xc0a878a0a1330aa6UL, 0x60543c50de970553UL, 0x302a1e286fc58ca7UL,
	0x18150f14b9ec46ddUL, 0x0c84890ad27623e0UL, 0x0642ca05693b9f70UL, 0x0321658cba93c138UL,
	0x86275df09ce8aaa8UL, 0x439da0784e745554UL, 0xafc0503c273aa42aUL, 0xd960281e9d1d5215UL,
	0xe230140fc0802984UL, 0x71180a8960409a42UL, 0xb60c05ca30204d21UL, 0x5b068c651810a89eUL,
	0x456c34887a3805b9UL, 0xac361a443d1c8cd2UL, 0x561b0d22900e4669UL, 0x2b838811480723baUL,
	0x9bcf4486248d9f5dUL, 0xc3e9224312c8c1a0UL, 0xeffa11af0964ee50UL, 0xf97d86d98a327728UL,
	0xe4fa2054a80b329cUL, 0x727d102a548b194eUL, 0x39b008152acb8227UL, 0x9258048415eb419dUL,
	0x492c024284fbaec0UL, 0xaa16012142f35760UL, 0x550b8e9e21f7a530UL, 0xa48b474f9ef5dc18UL,
	0x70a6a56e2440598eUL, 0x3853dc371220a247UL, 0x1ca76e95091051adUL, 0x0edd37c48a08a6d8UL,
	0x07e095624504536cUL, 0x8d70c431ac02a736UL, 0xc83862965601dd1bUL, 0x641c314b2b8ee083UL
};

// Итерационные константы в шестнадцатеричном виде
const uint8_t Constants_12_64[12][64] = {
	{7, 69, 166, 242, 89, 101, 128, 221, 35, 77, 116, 204, 54, 116, 118, 5, 21, 211, 96, 164, 8, 42, 66, 162, 1, 105, 103, 146, 145, 224, 124, 75, 252, 196, 133, 117, 141, 184, 78, 113, 22, 208, 69, 46, 67, 118, 106, 47, 31, 124, 101, 192, 129, 47, 203, 235, 233, 218, 202, 30, 218, 91, 8, 177, 0},
	{183, 155, 177, 33, 112, 4, 121, 230, 86, 205, 203, 215, 27, 162, 221, 85, 202, 167, 10, 219, 194, 97, 181, 92, 88, 153, 214, 18, 107, 23, 181, 154, 49, 1, 181, 22, 15, 94, 213, 97, 152, 43, 35, 10, 114, 234, 254, 243, 215, 181, 112, 15, 70, 157, 227, 79, 26, 47, 157, 169, 138, 181, 163, 111},
	{178, 10, 186, 10, 245, 150, 30, 153, 49, 219, 122, 134, 67, 244, 182, 194, 9, 219, 98, 96, 55, 58, 201, 193, 177, 158, 53, 144, 228, 15, 226, 211, 123, 123, 41, 177, 20, 117, 234, 242, 139, 31, 156, 82, 95, 94, 241, 6, 53, 132, 61, 106, 40, 252, 57, 10, 199, 47, 206, 43, 172, 220, 116, 245, 0},
	{46, 209, 227, 132, 188, 190, 12, 34, 241, 55, 232, 147, 161, 234, 83, 52, 190, 3, 82, 147, 51, 19, 183, 216, 117, 214, 3, 237, 130, 44, 215, 169, 63, 53, 94, 104, 173, 28, 114, 157, 125, 60, 92, 51, 126, 133, 142, 72, 221, 228, 113, 93, 160, 225, 72, 249, 210, 102, 21, 232, 179, 223, 31, 239, 0},
	{87, 254, 108, 124, 253, 88, 23, 96, 245, 99, 234, 169, 126, 162, 86, 122, 22, 26, 39, 35, 183, 0, 255, 223, 163, 245, 58, 37, 71, 23, 205, 191, 189, 255, 15, 128, 215, 53, 158, 53, 74, 16, 134, 22, 31, 28, 21, 127, 99, 35, 169, 108, 12, 65, 63, 154, 153, 71, 71, 173, 172, 107, 234, 75},
	{110, 125, 100, 70, 122, 64, 104, 250, 53, 79, 144, 54, 114, 197, 113, 191, 182, 198, 190, 194, 102, 31, 242, 10, 180, 183, 154, 28, 183, 166, 250, 207, 198, 142, 240, 154, 180, 154, 127, 24, 108, 164, 66, 81, 249, 196, 102, 45, 192, 57, 48, 122, 59, 195, 164, 111, 217, 211, 58, 29, 174, 174, 79, 174, 0},
	{147, 212, 20, 58, 77, 86, 134, 136, 243, 74, 60, 162, 76, 69, 23, 53, 4, 5, 74, 40, 131, 105, 71, 6, 55, 44, 130, 45, 197, 171, 146, 9, 201, 147, 122, 25, 51, 62, 71, 211, 201, 135, 191, 230, 199, 198, 158, 57, 84, 9, 36, 191, 254, 134, 172, 81, 236, 197, 170, 238, 22, 14, 199, 244, 0},
	{30, 231, 2, 191, 212, 13, 127, 164, 217, 168, 81, 89, 53, 194, 172, 54, 47, 196, 165, 209, 43, 141, 209, 105, 144, 6, 155, 146, 203, 43, 137, 244, 154, 196, 219, 77, 59, 68, 180, 137, 30, 222, 54, 156, 113, 248, 183, 78, 65, 65, 110, 12, 2, 170, 231, 3, 167, 201, 147, 77, 66, 91, 31, 155, 0 },
	{219, 90, 35, 131, 81, 68, 97, 114, 96, 42, 31, 203, 146, 220, 56, 14, 84, 156, 7, 166, 154, 138, 43, 123, 177, 206, 178, 219, 11, 68, 10, 128, 132, 9, 13, 224, 183, 85, 217, 60, 36, 66, 137, 37, 27, 58, 125, 58, 222, 95, 22, 236, 216, 154, 76, 148, 155, 34, 49, 22, 84, 90, 143, 55 },
	{237, 156, 69, 152, 251, 199, 180, 116, 195, 182, 59, 21, 209, 250, 152, 54, 244, 82, 118, 59, 48, 108, 30, 122, 75, 51, 105, 175, 2, 103, 231, 159, 3, 97, 51, 27, 138, 225, 255, 31, 219, 120, 138, 255, 28, 231, 65, 137, 243, 243, 228, 178, 72, 229, 42, 56, 82, 111, 5, 128, 166, 222, 190, 171, 0 },
	{27, 45, 243, 129, 205, 164, 202, 107, 93, 216, 111, 192, 74, 89, 162, 222, 152, 110, 71, 125, 29, 205, 186, 239, 202, 185, 72, 234, 239, 113, 29, 138, 121, 102, 132, 20, 33, 128, 1, 32, 97, 7, 171, 235, 187, 107, 250, 216, 148, 254, 90, 99, 205, 198, 2, 48, 251, 137, 200, 239, 208, 158, 205, 123},
	{32, 215, 27, 241, 74, 146, 188, 72, 153, 27, 178, 217, 213, 23, 244, 250, 82, 40, 225, 136, 170, 164, 29, 231, 134, 204, 145, 24, 157, 239, 128, 93, 155, 159, 33, 48, 212, 18, 32, 248, 119, 29, 223, 188, 50, 60, 164, 205, 122, 177, 73, 4, 176, 128, 19, 210, 186, 49, 22, 241, 103, 231, 142, 55}
};

// Массив подстановок байт
const uint8_t pi_256[256] = { 252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182 };

// Массив перестановок байт
const uint8_t tau_64[64] = { 0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27, 35, 43, 51, 59, 4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61, 6, 14, 22, 30, 38, 46, 54, 62, 7, 15, 23, 31, 39, 47, 55, 63 };

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


// ксорит масив из 64 8битных целых чисел
void X( uint8_t *a, uint8_t *b, uint8_t *dest){
	for(size_t i = 0; i < 64; ++i)
		dest[i] = a[i]^b[i];
}

void S(uint8_t *arg, uint8_t *dest){
	for(size_t i=0; i<64; ++i)
		dest[i] = pi_256[ arg[i] ];
}

void P(uint8_t *arg, uint8_t *dest){
	for(size_t i = 0; i<64; ++i)
		dest[i] = arg[ tau_64[i] ];
}


void L(uint8_t *arg, uint8_t *dest){
	uint64_t  local_sum;
	uint8_t current_value;

	for(size_t n = 0; n < 8; ++n){
		local_sum = 0;
		for(size_t i = 0; i < 8; ++i){
			current_value = arg[n*8 + i];
			for(size_t j = 0; j < 8; ++j){
				if(current_value & 1){
					local_sum ^= Matrix_64[63 - (i*8 + j)];
				}
				current_value >>= 1;
			}
		}
		for(size_t i = 0; i < 8; ++i){
			dest[n*8 + i] = (uint8_t)(local_sum & 255);
			local_sum >>= 8;
		}
	}
}

void G(uint8_t *N, uint8_t *h, uint8_t *m, uint8_t *dest){
	uint8_t buf1[64],
			buf2[64];

	X(N, h, buf1);
	S(buf1, buf2);
	P(buf2, buf1);
	L(buf1, buf2);

	uint8_t KM1[64];
	memcpy(KM1, buf2, sizeof(uint8_t)*64);

	X(KM1, m, buf1);
	S(buf1, buf2);
	P(buf2, buf1);
	L(buf1, buf2);

	uint8_t temp[64];
	memcpy(temp, buf2, sizeof(uint8_t)*64);

	for(size_t i = 0; i < 12; ++i){

		X(KM1, Constants_12_64[i], buf1);
		S(buf1, buf2);
		P(buf2, buf1);
		L(buf1, KM1);

		if(i < 11){
			X(KM1, temp, buf1);
			S(buf1, buf2);
			P(buf2, buf1);
			L(buf1, temp);
		}else{
			X(KM1, temp, temp);
		}
	}

	X(temp, h, temp);
	X(temp, m, dest);
}

void init(uint8_t *arg, HashCodeLength hash){
	switch(hash){
		case HASH_256:
			for(uint8_t i = 0; i < 64; ++i){
				arg[i] = 0x01;
			}
			break;
		case HASH_512:
			for(uint8_t i = 0; i < 64; ++i){
				arg[i] = 0;
			}
			break;
		default:
			exit(1);
			break;
	}
}

void add_number(uint8_t *V, uint16_t N, uint8_t *dest){
	uint32_t current_sum = N;
	for(size_t i = 0; i < 64; ++i){
		current_sum += V[i];
		dest[i] = (uint8_t)(current_sum & 255);
		current_sum >>= 8;
	}
}

void add_vector(uint8_t *V1, uint8_t *V2, uint8_t *dest){
	uint32_t current_sum = 0;
	for(size_t i = 0; i < 64; ++i){
		current_sum += V1[i] + V2[i];
		dest[i] = (uint8_t)(current_sum & 255);
		current_sum >>= 8;
	}
}

void Encrypt(HashCodeLength hash, void *data, size_t data_bits_count, unsigned char *dest){
	uint8_t *M = (uint8_t*)data,
	        h[64],
			N[64],
			*m,
			SIGMA[64],
			ZEROS[64];

	init(h, hash);
	for(uint8_t i = 0; i<64; ++i){
		N[i] = 0;
		SIGMA[i] = 0;
		ZEROS[i] = 0;
	}

	while(data_bits_count >= 512){
		m = M;
		M = M + 64; //сдвигаем на 512 бит
		data_bits_count -= 512;

		G(N,h,m,h);
		add_number(N, 512, N);
		add_vector(SIGMA, m, SIGMA);
	}

	uint8_t result[64];
	int bytes_count = data_bits_count >> 3; //высчитываем количество оставшихся байт
	if(data_bits_count & 7){
		++bytes_count;
	}
	for(size_t i = 0; i < bytes_count; ++i ){
		result[i] = M[i]; //копируем оставшиеся значения
	}
	for(size_t i = bytes_count; i < 64; ++i){
		result[i] = 0; //записываем нули до конца
	}
	result[bytes_count] += (1U << (data_bits_count & 7) ); //записываем единицу

	G(N,h,result,result);

	printResult(result, 64);

	add_number(N, (uint16_t)data_bits_count, N);
	add_vector(SIGMA,result,SIGMA);

	G(ZEROS, h, N, h);

	switch (hash) {
		case HASH_512:
			G(ZEROS, h, SIGMA, dest);
			break;
		case HASH_256:
			G(ZEROS, h, SIGMA, N);
			for (size_t i = 0; i < 32; ++i) {
				dest[i] = N[256+i];
			}
			break;
		default:
			exit(1);
			break;
	}
}

int main (void){
	char * message1 = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
	ArrayOfByte ar = convertToArray(message1, strlen(message1));
	printResult(ar.array, ar.length);

	uint8_t *dest[64];

	Encrypt(HASH_512, ar.array, 504, dest);
	printResult(dest, 64);

	return 0;
}





















