#pragma once

#include <stdlib.h>

int less_crypto_secretkeybytes(void); 

int less_crypto_publickeybytes(void);

int less_crypto_bytes(void);

int less_crypto_sign_keypair(unsigned char **pk, unsigned char **sk);

int less_crypto_sign(unsigned char **sm, unsigned long long *smlen,
            const unsigned char *m, unsigned long long mlen,
            const unsigned char *sk);

int less_crypto_sign_open(unsigned char **m, unsigned long long *mlen,
                 const unsigned char *sm, unsigned long long smlen,
                 const unsigned char *pk,
                 size_t orig_msg_len, size_t hybrid_len);

