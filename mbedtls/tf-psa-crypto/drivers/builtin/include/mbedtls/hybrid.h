#include "mbedtls/private_access.h"
#include "combiner.h"

typedef struct mbedtls_hybrid_context {
    size_t MBEDTLS_PRIVATE(len);                 /*!<  The size of \p N in Bytes. */
    combiner_t MBEDTLS_PRIVATE(combiner);
    scheme_t* MBEDTLS_PRIVATE(schemes);
    keypair_t MBEDTLS_PRIVATE(keypair);
} mbedtls_rsa_context;