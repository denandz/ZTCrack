#ifndef ZT_SALSA20_HPP
#define ZT_SALSA20_HPP

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * Salsa20 stream cipher
 */
class Salsa20
{
public:
	__device__ Salsa20() {}
	__device__ ~Salsa20() {}

	/**
	 * XOR d with s
	 *
	 * This is done efficiently using e.g. SSE if available. It's used when
	 * alternative Salsa20 implementations are used in Packet and is here
	 * since this is where all the SSE stuff is already included.
	 *
	 * @param d Destination to XOR
	 * @param s Source bytes to XOR with destination
	 * @param len Length of s and d
	 */
     __device__ static inline void memxor(uint8_t *d,const uint8_t *s,unsigned int len)
	{
		while (len) {
			--len;
			*(d++) ^= *(s++);
		}
	}

	/**
	 * @param key 256-bit (32 byte) key
	 * @param iv 64-bit initialization vector
	 */
     __device__ Salsa20(const void *key,const void *iv)
	{
		init(key,iv);
	}

	/**
	 * Initialize cipher
	 *
	 * @param key Key bits
	 * @param iv 64-bit initialization vector
	 */
     __device__ void init(const void *key,const void *iv);

	/**
	 * Encrypt/decrypt data using Salsa20/12
	 *
	 * @param in Input data
	 * @param out Output buffer
	 * @param bytes Length of data
	 */
     __device__ void crypt12(const void *in,void *out,unsigned int bytes);

	/**
	 * Encrypt/decrypt data using Salsa20/20
	 *
	 * @param in Input data
	 * @param out Output buffer
	 * @param bytes Length of data
	 */
	__device__ void crypt20(const void *in,void *out,unsigned int bytes);

private:
	union {
		uint32_t i[16];
	} _state;
};

#endif