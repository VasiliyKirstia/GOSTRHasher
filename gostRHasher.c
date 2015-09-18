#include <stdint.h>
#include <stdlib.h>

typedef static enum hashCodeLength
{
	HASH_256,
	HASH_512
} HashCodeLength;

// Матрица над полем GF(2) в шестнадцатеричном виде
const uint64_t Matrix_64 =
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
const uint64_t **Constants_12_8 = {
	{ 0xb1085bda1ecadae9, 0xebcb2f81c0657c1f, 0x2f6a76432e45d016, 0x714eb88d7585c4fc, 0x4b7ce09192676901, 0xa2422a08a460d315, 0x05767436cc744d23, 0xdd806559f2a64507},
	{ 0x6fa3b58aa99d2f1a, 0x4fe39d460f70b5d7, 0xf3feea720a232b98, 0x61d55e0f16b50131, 0x9ab5176b12d69958, 0x5cb561c2db0aa7ca, 0x55dda21bd7cbcd56, 0xe679047021b19bb7},
	{ 0xf574dcac2bce2fc7, 0x0a39fc286a3d8435, 0x06f15e5f529c1f8b, 0xf2ea7514b1297b7b, 0xd3e20fe490359eb1, 0xc1c93a376062db09, 0xc2b6f443867adb31, 0x991e96f50aba0ab2},
	{ 0xef1fdfb3e81566d2, 0xf948e1a05d71e4dd, 0x488e857e335c3c7d, 0x9d721cad685e353f, 0xa9d72c82ed03d675, 0xd8b71333935203be, 0x3453eaa193e837f1, 0x220cbebc84e3d12e},
	{ 0x4bea6bacad474799, 0x9a3f410c6ca92363, 0x7f151c1f1686104a, 0x359e35d7800fffbd, 0xbfcd1747253af5a3, 0xdfff00b723271a16, 0x7a56a27ea9ea63f5, 0x601758fd7c6cfe57},
	{ 0xae4faeae1d3ad3d9, 0x6fa4c33b7a3039c0, 0x2d66c4f95142a46c, 0x187f9ab49af08ec6, 0xcffaa6b71c9ab7b4, 0x0af21f66c2bec6b6, 0xbf71c57236904f35, 0xfa68407a46647d6e},
	{ 0xf4c70e16eeaac5ec, 0x51ac86febf240954, 0x399ec6c7e6bf87c9, 0xd3473e33197a93c9, 0x0992abc52d822c37, 0x06476983284a0504, 0x3517454ca23c4af3, 0x8886564d3a14d493},
	{ 0x9b1f5b424d93c9a7, 0x03e7aa020c6e4141, 0x4eb7f8719c36de1e, 0x89b4443b4ddbc49a, 0xf4892bcb929b0690, 0x69d18d2bd1a5c42f, 0x36acc2355951a8d9, 0xa47f0dd4bf02e71e},
	{ 0x378f5a541631229b, 0x944c9ad8ec165fde, 0x3a7d3a1b25894224, 0x3cd955b7e00d0984, 0x800a440bdbb2ceb1, 0x7b2b8a9aa6079c54, 0x0e38dc92cb1f2a60, 0x7261445183235adb},
	{ 0xabbedea680056f52, 0x382ae548b2e4f3f3, 0x8941e71cff8a78db, 0x1fffe18a1b336103, 0x9fe76702af69334b, 0x7a1e6c303b7652f4, 0x3698fad1153bb6c3, 0x74b4c7fb98459ced},
	{ 0x7bcd9ed0efc889fb, 0x3002c6cd635afe94, 0xd8fa6bbbebab0761, 0x2001802114846679, 0x8a1d71efea48b9ca, 0xefbacd1d7d476e98, 0xdea2594ac06fd85d, 0x6bcaa4cd81f32d1b},
	{ 0x378ee767f11631ba, 0xd21380b00449b17a, 0xcda43c32bcdf1d77, 0xf82012d430219f9b, 0x5d80ef9d1891cc86, 0xe71da4aa88e12852, 0xfaf417d5d9b21b99, 0x48bc924af11bd720}
};

// Массив подстановок байт
const uint8_t pi_256 = { 252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182 };

// Массив перестановок байт
const uint8_t tau_64 = { 0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58, 3, 11, 19, 27, 35, 43, 51, 59, 4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61, 6, 14, 22, 30, 38, 46, 54, 62, 7, 15, 23, 31, 39, 47, 55, 63 };

// ксорит масив из восьми 64битных целых чисел
void X( uint64_t *a, uint64_t *b, uint64_t *dest){
	dest[0] = a[0] ^ b[0];
	dest[1] = a[1] ^ b[1];
	dest[2] = a[2] ^ b[2];
	dest[3] = a[3] ^ b[3];
	dest[4] = a[4] ^ b[4];
	dest[5] = a[5] ^ b[5];
	dest[6] = a[6] ^ b[6];
	dest[7] = a[7] ^ b[7];
}

void S(uint8_t *arg, uint8_t *dest){
	for(uint8_t i=0; i<64; i++)
		dest[i] = pi_256[ arg[i] ];
}

void P(uint8_t *arg, uint8_t *dest){
	for(uint8_t i = 0; i<64; i++)
		dest[i] = arg[ tau_64[i] ];
}


void L(uint64_t *arg, uint64_t *dest){
	for(uint8_t i = 0; i<8; i++){
		dest[i] = 0;

		for(uint8_t mask=0x01, j = 0; mask; mask <<= 1, j++){
			if( arg[i] & mask ){
				dest[i] ^= Matrix_64[j];
			}
		}
	}
}

void G(uint64_t *N, uint64_t *h, uint64_t *m, uint64_t *dest){
	uint64_t buf1[8],
			 buf2[8];

	X(N, h, &buf1);
	S(buf1, &buf2);
	P(&buf2, &buf1);
	L(&buf1, &buf2);

	uint64_t KM1[8];
	mmemcpy(&KM1, &buf2, sizeof(uint64_t)*8);

	X(&KM1, m, &buf1);
	S(buf1, &buf2);
	P(&buf2, &buf1);
	L(&buf1, &buf2);

	uint64_t temp[8];
	mmemcpy(&temp, &buf2, sizeof(uint64_t)*8);

	for(uint8_t i = 0; i < 12; i++){

		X(&KM1, &Constants_12_8[i], &buf1);
		S(buf1, &buf2);
		P(&buf2, &buf1);
		L(&buf1, &KM1);

		if(i < 11){
			X(&KM1, &temp, &buf1);
			S(buf1, &buf2);
			P(&buf2, &buf1);
			L(&buf1, &temp);
		}else{
			X(&KM1, &temp, &temp);
		}
	}

	X(&temp, h, &temp);
	X(&temp, m, &dest);
}

void init(uint64_t *arg, HashCodeLength hash = HASH_512){
	switch(hash){
		case HASH_256:
			uint8_t *arg_8 = (uint8_t*)arg;
			for(uint8_t i = 0; i < 8; i++){
				arg_8[i] = 0x01;
			}
		break;

		case HASH_512:
			for(uint8_t i = 0; i < 8; i++){
				arg[i] = 0;
			}
		break;

		default:
			exit(1);
		break;
	}
}

void MSB(uint64_t* data,uint64_t data_64_count, uint64_t tail_64_count, uint64_t *head, uint64_t *tail){
	for(uint64_t i = 0; i < tail_64_count; i++){

	}
}

void Encrypt(HashCodeLength hash = HASH_512, void *data, uint64_t data_bits_count, uint64_t *dest){
	uint64_t h[8],
			 N[8],
			 m[8],
			 SIGMA[8];
	init(h, hash);

	for(uint8_t i = 0; i<8; i++){
		N[i] = 0;
		m[i] = 0;
		SIGMA[i] = 0;
	}

	if(data_bits_count < 512){
		//goto шаг 3
	}else{
		// шаг 2

	}

}





















