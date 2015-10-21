#ifndef GOSTRHASHER_H_
#define GOSTRHASHER_H_

#include <stdint.h>
#include <stdlib.h>
typedef enum{HASH_512,HASH_256}HashCodeLength;

extern void Encrypt(HashCodeLength hash, void *data, size_t data_bits_count, unsigned char *dest);

#endif /* GOSTRHASHER_H_ */
