#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "combiner.h"

#include "mayo_wrapper.h"
#include "less_wrapper.h"
#include "cross_wrapper.h"
#include "snova_wrapper.h"
#include "qruov_wrapper.h"
#include "uov_wrapper.h"
#include "sdith_wrapper.h"
#include "faest_wrapper.h"

char* scheme_t_to_str(scheme_t scheme) {
    switch (scheme) {
        case CROSS:
            return "CROSS";
        case LESS:
            return "LESS";
        case MAYO:
            return "MAYO";
        case SNOVA:
            return "SNOVA";
        case QRUOV:
            return "QRUOV";
        case UOV:
            return "UOV";
        case SDITH:
            return "SDITH";
        case FAEST:
            return "FAEST";
    }
    return "Unknown!";
}

typedef int (*crypto_sign_keypair_t)(unsigned char **pk, unsigned char **sk);

typedef int (*crypto_sign_t)(unsigned char **sm, size_t *smlen, 
    const unsigned char *m, size_t mlen,
    const unsigned char *sk);

typedef int (*crypto_sign_open_t)(unsigned char **m, size_t *mlen, 
    const unsigned char *sm, size_t smlen,
    const unsigned char *pk,
    size_t orig_msg_len, size_t hybrid_len);

crypto_sign_keypair_t crypto_sign_keypair_algorithms[] = {
    cross_crypto_sign_keypair,
    less_crypto_sign_keypair,
    snova_crypto_sign_keypair,
    mayo_crypto_sign_keypair,
    qruov_crypto_sign_keypair,
    uov_crypto_sign_keypair,
    sdith_crypto_sign_keypair,
    faest_crypto_sign_keypair,
};

crypto_sign_t crypto_sign_algorithms[] = {
    cross_crypto_sign,
    less_crypto_sign,
    snova_crypto_sign,
    mayo_crypto_sign,
    qruov_crypto_sign,
    uov_crypto_sign,
    sdith_crypto_sign,
    faest_crypto_sign,
};

crypto_sign_open_t crypto_sign_open_algorithms[] = {
    cross_crypto_sign_open,
    less_crypto_sign_open,
    snova_crypto_sign_open,
    mayo_crypto_sign_open,
    qruov_crypto_sign_open,
    uov_crypto_sign_open,
    sdith_crypto_sign_open,
    faest_crypto_sign_open,
};

int combiner_keygen (hybrid_t hybrid, key_pair_t* key_pair) {
    int ret;
    for (int i = 0; i < hybrid.len; ++i) {
        ret = crypto_sign_keypair_algorithms[hybrid.schemes[i]](
            &key_pair->public_key[i],
            &key_pair->secret_key[i]
        );
        if (ret != 0) {
            fprintf(stderr, "Keypair generation failed!\n");
            return ret;
        }
    }
    return 0;
}

int concat_sign (hybrid_t* hybrid, unsigned char** secret_key,
                   msg_t message) {
    unsigned char* signature;
    size_t signature_len;
    int ret;
    for (int i = 0; i < hybrid->len; ++i) {
        ret = crypto_sign_algorithms[hybrid->schemes[i]](
            &signature,
            &signature_len,
            message.content,
            message.len,
            secret_key[i]
        );

        if (ret != 0) {
            fprintf(stderr, "Concat signature generation failed!\n");
            return ret;
        } 

        hybrid->signature.concat.contents[i] = signature;
        hybrid->signature.concat.lens[i] = signature_len;
    }
    return 0;
}

int nesting_sign (hybrid_t* hybrid, unsigned char** secret_key,
                   msg_t message) {
    unsigned char* signature;
    size_t signature_len;

    int ret;
    ret = crypto_sign_algorithms[hybrid->schemes[0]](
        &signature,
        &signature_len,
        message.content,
        message.len,
        secret_key[0]
    );

    if (ret != 0) {
        fprintf(stderr, "Nesting signature generation failed!\n");
        return ret;
    } 

    msg_t original_message = message;

    unsigned char* new_message;
    for (int i = 1; i < hybrid->len; ++i) {
        new_message = malloc(
            sizeof(*new_message) * (original_message.len + signature_len)
        );
        if (new_message == NULL) {
            fprintf(stderr, "Malloc failed in nesting_sign!\n");
            return -1;
        }

        memcpy(
            new_message, 
            original_message.content, 
            sizeof(*original_message.content) * original_message.len
        );
        memcpy(
            new_message + sizeof(*message.content) * original_message.len, 
            signature, 
            sizeof(*signature) * signature_len
        );

        message.len = original_message.len + signature_len;
        message.content = new_message;

        ret = crypto_sign_algorithms[hybrid->schemes[i]](
            &signature,
            &signature_len,
            message.content,
            message.len,
            secret_key[i]
        );

        if (ret != 0) {
            fprintf(stderr, "Nesting signature generation failed!\n");
            return ret;
        } 

        if (new_message != NULL) {
            free(new_message);
        }
    }

    hybrid->signature.nesting.content = signature;
    hybrid->signature.nesting.len = signature_len;
    return 0;
}

int combiner_sign (hybrid_t* hybrid, unsigned char** secret_key,
                   msg_t message) {
    switch (hybrid->combiner) {
        case CONCATENATION:
            return concat_sign(hybrid, secret_key, message);
        case STRONG_NESTING:
            return nesting_sign(hybrid, secret_key, message);
    }
    return -1;
}

int concat_verify (hybrid_t hybrid, unsigned char** public_key,
                    msg_t message) {

    unsigned char* decrypted_msg;
    size_t decrypted_msg_len;
    int ret;

    for (int i = 0; i < hybrid.len; ++i) {
        unsigned char* signature = hybrid.signature.concat.contents[i];
        size_t signature_len = hybrid.signature.concat.lens[i];

        ret = crypto_sign_open_algorithms[hybrid.schemes[i]](
            &decrypted_msg,
            &decrypted_msg_len,
            signature,
            signature_len,
            public_key[i],
            message.len,
            hybrid.len
        );

        if (ret != 0) {
            fprintf(stderr, "Concat signature verification failed!\n");
        }

        if (decrypted_msg_len != message.len
            || memcmp(decrypted_msg, message.content, message.len) != 0) {
            return 0;
        }
        printf("Recovered msg: \"%.*s\"\n", decrypted_msg_len, decrypted_msg);
    }
    return 1;
}

int nesting_verify (hybrid_t hybrid, unsigned char** public_key, 
                     msg_t message) {

    unsigned char* signature = hybrid.signature.nesting.content;
    size_t signature_len = hybrid.signature.nesting.len;
    unsigned char* decrypted_msg;
    size_t decrypted_msg_len;
    int ret;

    for (int i = hybrid.len-1; i > -1; i--) {

        ret = crypto_sign_open_algorithms[hybrid.schemes[i]](
            &decrypted_msg,
            &decrypted_msg_len,
            signature,
            signature_len,
            public_key[i],
            message.len,
            hybrid.len
        );

        if (ret != 0) {
            fprintf(stderr, "Nesting signature verification failed!\n");
        }

        signature = decrypted_msg + message.len;
        signature_len = decrypted_msg_len - message.len;
    }

    if (decrypted_msg_len == message.len
        && memcmp(decrypted_msg, message.content, message.len) == 0) {
        printf("Recovered msg: \"%.*s\"\n", decrypted_msg_len, decrypted_msg);
        return 1;
    }
    return 0;
}

int combiner_verify (hybrid_t hybrid, unsigned char** public_key,
                      msg_t message) {
    switch (hybrid.combiner) {
        case CONCATENATION:
            return concat_verify(hybrid, public_key, message);
        case STRONG_NESTING:
            return nesting_verify(hybrid, public_key, message);
    }
    return 0;
}




