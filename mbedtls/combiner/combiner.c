#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "combiner.h"

#include "mayo_wrapper.h"
#include "less_wrapper.h"
#include "cross_wrapper.h"
#include "snova_wrapper.h"
#include "qruov_wrapper.h"
#include "uov_wrapper.h"
#include "sdith_wrapper.h"
#include "faest_wrapper.h"

void print_b (const void *ptr, size_t n) {
    const unsigned char *byte = (const unsigned char *)ptr;
    for (size_t i = 0; i < n; i++) {
        printf("%02X", byte[i]); 
    }
    printf("\n");
}

char* scheme_t_to_str (scheme_t scheme) {
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

scheme_t str_to_scheme_t (char* str) {
    if (strncmp(str, "CROSS", strlen(str)) == 0) {
        return CROSS;
    }
    else if (strncmp(str, "LESS", strlen(str)) == 0) {
        return LESS;
    }
    else if (strncmp(str, "MAYO", strlen(str)) == 0) {
        return MAYO;
    }
    else if (strncmp(str, "SNOVA", strlen(str)) == 0) {
        return SNOVA;
    }
    else if (strncmp(str, "QRUOV", strlen(str)) == 0) {
        return QRUOV;
    }
    else if (strncmp(str, "UOV", strlen(str)) == 0) {
        return UOV;
    }
    else if (strncmp(str, "SDITH", strlen(str)) == 0) {
        return SDITH;
    }
    else if (strncmp(str, "FAEST", strlen(str)) == 0) {
        return FAEST;
    }
}

typedef int (*crypto_sign_keypair_t)(unsigned char *pk, unsigned char *sk);

typedef int (*crypto_sign_t)(unsigned char **sm, unsigned long long *smlen, 
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk);

typedef int (*crypto_sign_open_t)(unsigned char **m, unsigned long long *mlen, 
    const unsigned char *sm, unsigned long long smlen,
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

int (*crypto_secretkeybytes_constants[]) (void) = {
    cross_crypto_secretkeybytes,
    less_crypto_secretkeybytes,
    snova_crypto_secretkeybytes,
    mayo_crypto_secretkeybytes,
    qruov_crypto_secretkeybytes,
    uov_crypto_secretkeybytes,
    sdith_crypto_secretkeybytes,
    faest_crypto_secretkeybytes,
};

int (*crypto_publickeybytes_constants[]) (void) = {
    cross_crypto_publickeybytes,
    less_crypto_publickeybytes,
    snova_crypto_publickeybytes,
    mayo_crypto_publickeybytes,
    qruov_crypto_publickeybytes,
    uov_crypto_publickeybytes,
    sdith_crypto_publickeybytes,
    faest_crypto_publickeybytes,
};

int (*crypto_bytes_constants[]) (void) = {
    cross_crypto_bytes,
    less_crypto_bytes,
    snova_crypto_bytes,
    mayo_crypto_bytes,
    qruov_crypto_bytes,
    uov_crypto_bytes,
    sdith_crypto_bytes,
    faest_crypto_bytes,
};

int combiner_keygen (hybrid_t* hybrid) {

    size_t public_key_len = 0, secret_key_len = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        public_key_len += crypto_publickeybytes_constants[scheme]();
        secret_key_len += crypto_secretkeybytes_constants[scheme]();
    }


    hybrid->keypair.public_key_len = public_key_len;
    hybrid->keypair.secret_key_len = secret_key_len;

    hybrid->keypair.public_key = malloc(sizeof(*hybrid->keypair.public_key) * public_key_len);
    hybrid->keypair.secret_key = malloc(sizeof(*hybrid->keypair.secret_key) * secret_key_len);

    int ret;
    size_t pk_offset = 0, sk_offset = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        ret = crypto_sign_keypair_algorithms[hybrid->schemes[i]](
            hybrid->keypair.public_key + pk_offset,
            hybrid->keypair.secret_key + sk_offset
        );

        if (ret != 0) {
            fprintf(stderr, "Keypair generation failed!\n");
            return ret;
        }

        pk_offset += crypto_publickeybytes_constants[scheme]();
        sk_offset += crypto_secretkeybytes_constants[scheme]();
    }
    return 0;
}

int concat_sign (hybrid_t* hybrid, unsigned char* secret_key,
                   msg_t message) {
    unsigned char* signature;
    unsigned long long signature_len;
    int ret;
    size_t sk_offset = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        ret = crypto_sign_algorithms[hybrid->schemes[i]](
            &signature,
            &signature_len,
            message.content,
            message.len,
            secret_key + sk_offset
        );

        if (ret != 0) {
            fprintf(stderr, "Concat signature generation failed!\n");
            return ret;
        } 

        hybrid->signature.concat.contents[i] = signature;
        hybrid->signature.concat.lens[i] = signature_len;

        sk_offset += crypto_secretkeybytes_constants[scheme]();
    }
    return 0;
}

int nesting_sign (hybrid_t* hybrid, unsigned char* secret_key,
                   msg_t message) {
    unsigned char* signature;
    unsigned long long signature_len;

    int ret;
    ret = crypto_sign_algorithms[hybrid->schemes[0]](
        &signature,
        &signature_len,
        message.content,
        message.len,
        secret_key
    );

    if (ret != 0) {
        fprintf(stderr, "Nesting signature generation failed!\n");
        return ret;
    } 

    msg_t original_message = message;

    unsigned char* new_message;
    size_t sk_offset = crypto_secretkeybytes_constants[hybrid->schemes[0]]();
    for (int i = 1; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
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

        //printf("\nkey len = %zu\n", hybrid->keypair.secret_key_len);
        printf("\nskey offset = %zu\n", sk_offset);

        ret = crypto_sign_algorithms[hybrid->schemes[i]](
            &signature,
            &signature_len,
            message.content,
            message.len,
            secret_key + sk_offset
        );

        sk_offset += crypto_secretkeybytes_constants[scheme]();
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

int combiner_sign (hybrid_t* hybrid, msg_t message) {
    switch (hybrid->combiner) {
        case CONCATENATION:
            return concat_sign(hybrid, hybrid->keypair.secret_key, message);
        case STRONG_NESTING:
            return nesting_sign(hybrid, hybrid->keypair.secret_key, message);
    }
    return -1;
}

int concat_verify (const hybrid_t hybrid, unsigned char* public_key,
                    msg_t message) {

    unsigned char* decrypted_msg;
    unsigned long long decrypted_msg_len;
    int ret;

    size_t pk_offset = 0;
    for (int i = 0; i < hybrid.len; ++i) {
        scheme_t scheme = hybrid.schemes[i];
        unsigned char* signature = hybrid.signature.concat.contents[i];
        unsigned long long signature_len = hybrid.signature.concat.lens[i];

        ret = crypto_sign_open_algorithms[hybrid.schemes[i]](
            &decrypted_msg,
            &decrypted_msg_len,
            signature,
            signature_len,
            public_key + pk_offset,
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
        pk_offset += crypto_publickeybytes_constants[scheme]();
    }
    return 1;
}

int nesting_verify (hybrid_t hybrid, unsigned char* public_key, 
                     msg_t message) {

    unsigned char* signature = hybrid.signature.nesting.content;
    unsigned long long signature_len = hybrid.signature.nesting.len;
    unsigned char* decrypted_msg;
    unsigned long long decrypted_msg_len;
    int ret;

    // TODO

    size_t pk_offset = hybrid.keypair.public_key_len;
    for (int i = hybrid.len-1; i > -1; i--) {
        scheme_t scheme = hybrid.schemes[i];
        pk_offset -= crypto_publickeybytes_constants[scheme]();

        ret = crypto_sign_open_algorithms[hybrid.schemes[i]](
            &decrypted_msg,
            &decrypted_msg_len,
            signature,
            signature_len,
            public_key += pk_offset,
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

int combiner_verify (hybrid_t hybrid, msg_t message) {
    switch (hybrid.combiner) {
        case CONCATENATION:
            return concat_verify(hybrid, hybrid.keypair.public_key, message);
        case STRONG_NESTING:
            return nesting_verify(hybrid, hybrid.keypair.public_key, message);
    }
    return 0;
}

int combiner_save_keypair(hybrid_t* hybrid, const char* file_name) {

    FILE* file_ptr;
    if ((file_ptr = fopen(file_name, "w+b")) == NULL) {
        return -1;
    }

    printf("\npkey len: %zu, skey len: %zu\n", hybrid->keypair.public_key_len, hybrid->keypair.secret_key_len);
    if (fwrite(
        hybrid->keypair.secret_key, 
        sizeof(*hybrid->keypair.secret_key), 
        hybrid->keypair.secret_key_len, 
        file_ptr) != hybrid->keypair.secret_key_len) {
        fclose(file_ptr);
        return -1;
    }

    if (fwrite(
        hybrid->keypair.public_key, 
        sizeof(*hybrid->keypair.public_key), 
        hybrid->keypair.public_key_len, 
        file_ptr) != hybrid->keypair.public_key_len) {
        fclose(file_ptr);
        return -1;
    }
    fclose(file_ptr);
    return 0;
}

int combiner_read_keypair(hybrid_t* hybrid, const char* file_name) {

    size_t public_key_len = 0, secret_key_len = 0;
    for (int i = 0; i < hybrid->len; ++i) {
        scheme_t scheme = hybrid->schemes[i];
        public_key_len += crypto_publickeybytes_constants[scheme]();
        secret_key_len += crypto_secretkeybytes_constants[scheme]();
    }

    hybrid->keypair.public_key_len = public_key_len;
    hybrid->keypair.secret_key_len = secret_key_len;

    hybrid->keypair.public_key = malloc(sizeof(*hybrid->keypair.public_key) * public_key_len);
    hybrid->keypair.secret_key = malloc(sizeof(*hybrid->keypair.secret_key) * secret_key_len);

    FILE* file_ptr;
    if ((file_ptr = fopen(file_name, "r+b")) == NULL) {
        return -1;
    }

    if (fread(
        hybrid->keypair.secret_key, 
        sizeof(*hybrid->keypair.secret_key), 
        secret_key_len, 
        file_ptr) != secret_key_len) {
        fclose(file_ptr);
        return -1;
    }

    if (fread(
        hybrid->keypair.public_key, 
        sizeof(*hybrid->keypair.public_key), 
        public_key_len, 
        file_ptr) != public_key_len) {
        fclose(file_ptr);
        return -1;
    }

    fclose(file_ptr);
    return 0;
}

int combiner_read_signature(const hybrid_t* hybrid, msg_t sig, msg_t hash) {
    switch (hybrid->combiner) {
        case CONCATENATION:
            size_t sig_offset = 0;
            for (int i = 0; i < hybrid->len; ++i) {
                scheme_t scheme = hybrid->schemes[i];
                size_t sig_len = hash.len + crypto_bytes_constants[scheme]();

                hybrid->signature.concat.lens[i] = sig_len;
                hybrid->signature.concat.contents[i] = malloc(sig_len);
                memcpy(hybrid->signature.concat.contents[i], sig.content + sig_offset, sig_len);

                sig_offset += sig_len;
            }
            break;
        case STRONG_NESTING:
            break;
    }
    return 0;
}

