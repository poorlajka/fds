/// @file utils_randombytes.c
/// @brief wrappers for UOV_randombytes().
///

#include "utils_randombytes.h"


#if defined(_UTILS_SUPERCOP_)||defined(_UTILS_PQM4_)

// nothing to do.

#elif defined(_NIST_KAT_)

// UOV_randombytes() is defined in rng.h/c provided from nist.

#elif defined(_UTILS_OPENSSL_)

#include <openssl/rand.h>

void UOV_randombytes(unsigned char *x, unsigned long long xlen) {
    RAND_bytes(x, xlen);
}

#elif defined( _DEBUG_RANDOMBYTES_ )

#include <stdlib.h>
#include <string.h>

void UOV_randombytes(unsigned char *x, unsigned long long xlen) {
    while (xlen--) {
        *x++ = rand() & 0xff;
    }
}

#else

ERROR -- no implementaiton for UOV_randombytes()

#endif

