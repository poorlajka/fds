#include <api.h>
#include <stdlib.h>
#include <stdio.h>

int sdith_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int sdith_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int sdith_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int sdith_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {

	return SDITH_crypto_sign_keypair(pk, sk);
}

int sdith_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

	return SDITH_crypto_sign(*sm, (unsigned long long*)smlen, m, mlen, sk);
}

int sdith_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk,
                 size_t orig_msg_len, size_t hybrid_len) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
	int ret = SDITH_crypto_sign_open(*m, (unsigned long long*)mlen, sm, smlen, pk);
    return ret;
}
