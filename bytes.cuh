#ifndef BYTES_H
#define BYTES_H

/* Swap bytes in 16 bit value.  */
#define __bswap_constant_16(x) \
     ((unsigned short int) ((((x) >> 8) & 0xff) | (((x) & 0xff) << 8)))

__device__ static inline unsigned short int
__bswap_16 (unsigned short int __bsx)
{
  return __bswap_constant_16 (__bsx);
}

#define htons(x)	__bswap_16 (x)

__device__ static inline uint16_t swapBytes(const uint16_t n) noexcept
{
    return htons(n);
}

__device__  static inline uint64_t swapBytes(const uint64_t n) noexcept
	{
	
		return (
			((n & 0x00000000000000ffULL) << 56) |
			((n & 0x000000000000ff00ULL) << 40) |
			((n & 0x0000000000ff0000ULL) << 24) |
			((n & 0x00000000ff000000ULL) <<  8) |
			((n & 0x000000ff00000000ULL) >>  8) |
			((n & 0x0000ff0000000000ULL) >> 24) |
			((n & 0x00ff000000000000ULL) >> 40) |
			((n & 0xff00000000000000ULL) >> 56)
		);
	}

template< typename I, unsigned int S >
class _swap_bytes_bysize;

template< typename I >
class _swap_bytes_bysize< I, 1 >
{
public:
  __device__ static inline I s(const I n) noexcept
  { return n; }
};

template< typename I >
class _swap_bytes_bysize< I, 2 >
{
public:
  __device__ static inline I s(const I n) noexcept
  { return (I)swapBytes((uint16_t)n); }
};

template< typename I >
class _swap_bytes_bysize< I, 4 >
{
public:
  __device__ static inline I s(const I n) noexcept
  { return (I)  ((uint32_t)n); }
};

template< typename I >
class _swap_bytes_bysize< I, 8 >
{
public:
  __device__ static inline I s(const I n) noexcept
  { return (I)swapBytes((uint64_t)n); }
};

template< typename I >
__device__ static inline I ntoh(const I n) noexcept
{
  return _swap_bytes_bysize< I, sizeof(I) >::s(n);
}

#endif