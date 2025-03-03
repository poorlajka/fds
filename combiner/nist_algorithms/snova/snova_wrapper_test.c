#include "snova_wrapper.h"
#include <stdio.h>

int main () {
    unsigned char* pk;
    unsigned char* sk;
    unsigned char msg[] = "Hello, World!\n";
    unsigned char* signature;
    unsigned long long smlen;

    printf("generate_keys\n");
    snova_crypto_sign_keypair(&pk, &sk);
    /*
    printf("private key size: (%d bytes): \n", CRYPTO_SECRETKEYBYTES);
    print_byte(sk, CRYPTO_SECRETKEYBYTES);
    printf("=======================\n");
    printf("public key size: (%d bytes): \n", CRYPTO_PUBLICKEYBYTES);
    print_byte(pk, CRYPTO_PUBLICKEYBYTES);
    printf("=======================\n");
    */

    /*
    printf("text (%d byte): \n", sizeof(msg));
    print_byte(msg, sizeof(msg));
    printf("=======================\n");
    */
    /*
    snova_crypto_sign(sm, &smlen, text, text_len, sk);
    /*
    printf("sm gen (%lld byte): \n", smlen);
    print_byte(sm, smlen);
    printf("=======================\n");
    */

    /*
    unsigned long long mlan;
    uint8_t text1[text_len] = {0};
    int r = snova_crypto_sign_open(text1, &mlan, sm, CRYPTO_BYTES + text_len, pk);
    printf("crypto_sign_open: %d\n", r);
    print_byte(text1, mlan);
    */
    return 0;
}
