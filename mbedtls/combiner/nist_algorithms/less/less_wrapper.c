#include "rng.h"
#include <api.h>
#include <stdlib.h>
#include <stdio.h>

int less_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int less_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int less_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int less_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    // TODO: Get a better understanding of the seeding and posssible impact on performance!
    uint8_t seed[] ={0x83,0xC6,0x53,0x70,0x8F,0xAF,0x3E,0x5F,0x6F,0xBC,0x9D,0xFB,0xE6,0xFB,0x5E,0x83,0xE5,0x72,0xA7,0x68,0x86,0x45,0xD7,0x5D,0x2C,0x48,0x35,0xB2,0x86,0x95,0xDE,0xA4,0xBD,0x70,0x93,0x74,0x0D,0x0F,0xF4,0x32,0x37,0x35,0x4E,0xAD,0x1C,0x97,0x8B,0xC2};
    initialize_csprng(&LESS_platform_csprng_state,
                      (const unsigned char *)seed,
                      48);

	return LESS_crypto_sign_keypair(pk, sk);
}

int less_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

	return LESS_crypto_sign(*sm, (unsigned long long*)smlen, m, mlen, sk);
}

int less_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk,
                 size_t orig_msg_len, size_t hybrid_len) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
	return LESS_crypto_sign_open(*m, (unsigned long long*)mlen, sm, smlen, pk);
}
