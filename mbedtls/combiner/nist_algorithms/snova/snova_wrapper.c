#include <stdio.h>

#include "api.h"
#include "util/util.h"
#include "nistkat/rng.h"

int snova_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int snova_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int snova_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int snova_crypto_sign_keypair(unsigned char **pk, unsigned char **sk) {
    snova_init();
    uint8_t entropy_input[48];
    for (int i = 0; i < 48; i++) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);

    *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    *sk = malloc(CRYPTO_SECRETKEYBYTES);
	return SNOVA_crypto_sign_keypair(*pk, *sk);
}

int snova_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

	return SNOVA_crypto_sign(*sm, (unsigned long long*)smlen, m, mlen, sk);
}

int snova_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk,
                 size_t orig_msg_len, size_t hybrid_len) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    int size = (sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    if (size == 0) {
        return -1;
    }
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
	return SNOVA_crypto_sign_open(*m, (unsigned long long*)mlen, sm, smlen, pk);
}
