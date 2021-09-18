#ifndef SHA512_H
#define SHA512_H

#include <stdint.h>

#define I64(x) x##LL
#define ROTL32(dword, n) ((dword) << (n) ^ ((dword) >> (32 - (n))))
#define ROTR32(dword, n) ((dword) >> (n) ^ ((dword) << (32 - (n))))
#define ROTL64(qword, n) ((qword) << (n) ^ ((qword) >> (64 - (n))))
#define ROTR64(qword, n) ((qword) >> (n) ^ ((qword) << (64 - (n))))

#define sha512_block_size 128
#define sha512_hash_size  64
#define sha384_hash_size  48

#define bswap_32(x) ((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >>  8) | \
	(((x) & 0x0000ff00) <<  8) | (((x) & 0x000000ff) << 24))

__device__ static inline uint64_t bswap_64(uint64_t x) {
        union {
            uint64_t ll;
            uint32_t l[2];
        } w, r;
        w.ll = x;
        r.l[0] = bswap_32(w.l[1]);
        r.l[1] = bswap_32(w.l[0]);
        return r.ll;
    }

#define IS_ALIGNED_64(p) (0 == (7 & ((const char*)(p) - (const char*)0)))

# define be2me_32(x) bswap_32(x)
# define be2me_64(x) bswap_64(x)
# define le2me_32(x) (x)
# define le2me_64(x) (x)
# define be64_copy(to, index, from, length) rhash_swap_copy_str_to_u64((to), (index), (from), (length))
    
/* algorithm context */
typedef struct sha512_ctx
{
	uint64_t message[16];   /* 1024-bit buffer for leftovers */
	uint64_t length;        /* number of processed bytes */
	uint64_t hash[8];       /* 512-bit algorithm internal hashing state */
	unsigned digest_length; /* length of the algorithm digest in bytes */
} sha512_ctx;

__device__ void rhash_sha512_init(sha512_ctx *ctx);
__device__ void rhash_sha512_update(sha512_ctx *ctx, const unsigned char* data, size_t length);
__device__ void rhash_sha512_final(sha512_ctx *ctx, unsigned char* result);
__device__ void rhash_swap_copy_str_to_u64(void* to, int index, const void* from, size_t length);
__device__ void SHA512(void *digest,const void *data,unsigned int len);

#endif