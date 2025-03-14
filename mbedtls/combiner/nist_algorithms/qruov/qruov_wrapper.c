#include <api.h>
#include <stdlib.h>
#include <stdio.h>

int qruov_crypto_secretkeybytes(void) {
    return CRYPTO_SECRETKEYBYTES;
}

int qruov_crypto_publickeybytes(void) {
    return CRYPTO_PUBLICKEYBYTES;
}

int qruov_crypto_bytes(void) {
    return CRYPTO_BYTES;
}

int qruov_crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
	return QRUOV_crypto_sign_keypair(pk, sk);
}

int qruov_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk) {
    *sm = malloc(sizeof(**sm) * (mlen + CRYPTO_BYTES)); 

	return QRUOV_crypto_sign(*sm, smlen, m, mlen, sk);
}

int qruov_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk,
                 size_t orig_msg_len, size_t hybrid_len) {

    //*m = malloc(sizeof(**m) * (orig_msg_len + CRYPTO_BYTES) * hybrid_len);
    *m = malloc(sizeof(*m) * smlen - CRYPTO_BYTES);
	return QRUOV_crypto_sign_open(*m, mlen, sm, smlen, pk);
}
