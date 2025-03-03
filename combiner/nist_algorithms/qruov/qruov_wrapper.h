#pragma once

#include <stdlib.h>

int qruov_crypto_sign_keypair(unsigned char **pk, unsigned char **sk);

int qruov_crypto_sign(unsigned char **sm, size_t *smlen,
            const unsigned char *m, size_t mlen,
            const unsigned char *sk);

int qruov_crypto_sign_open(unsigned char **m, size_t *mlen,
                 const unsigned char *sm, size_t smlen,
                 const unsigned char *pk,
                 size_t orig_msg_len, size_t hybrid_len);

