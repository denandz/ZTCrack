/*
 * Copyright (c)2019 ZeroTier, Inc.
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file in the project's root directory.
 *
 * Change Date: 2025-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2.0 of the Apache License.
 */
/****/

#ifndef ZT_C25519_HPP
#define ZT_C25519_HPP

#define ZT_C25519_PUBLIC_KEY_LEN 64
#define ZT_C25519_PRIVATE_KEY_LEN 64
#define ZT_C25519_SIGNATURE_LEN 96

/**
 * A combined Curve25519 ECDH and Ed25519 signature engine
 */
class C25519
{
public:
        struct Public { uint8_t data[ZT_C25519_PUBLIC_KEY_LEN]; };
        struct Private { uint8_t data[ZT_C25519_PRIVATE_KEY_LEN]; };
        struct Signature { uint8_t data[ZT_C25519_SIGNATURE_LEN]; };
        struct Pair { Public pub; Private priv; };

        /**
        * Generate a keypair from a given buffer - read overflow if inputbuf is not long enough!
        **/
        __device__ static inline void calcPubKeys(Pair * kp){
                _calcPubED(*kp);
                _calcPubDH(*kp);
        }

private:
        // derive first 32 bytes of kp.pub from first 32 bytes of kp.priv
        // this is the ECDH key
        __device__  static void _calcPubDH(Pair &kp);

        // derive 2nd 32 bytes of kp.pub from 2nd 32 bytes of kp.priv
        // this is the Ed25519 sign/verify key
        __device__  static void _calcPubED(Pair &kp);
};

#endif