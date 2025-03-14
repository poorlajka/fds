#include "combiner.h"
#include <stdlib.h>
int main (void) {
    int hybrid_len = 2;
    scheme_t* schemes = malloc(hybrid_len * sizeof(scheme_t));
    schemes[0] = MAYO;
    schemes[1] = CROSS;

    hybrid_t hybrid = {
        .len = hybrid_len,
        .combiner = CONCATENATION,
        .schemes = schemes,
        .signature = {
            .concat = {
                .contents = malloc(hybrid_len * sizeof(unsigned char*)),
                .lens = malloc(hybrid_len * sizeof(size_t))
            }
        },
    };

    int ret = combiner_keygen(&hybrid);
    if (ret == -1) {
        printf("keygen failed \n");
        return 0;
    }
    ret = combiner_save_keypair(&hybrid, "combiner_keypair.txt");
    if (ret == -1) {
        printf("keysave failed \n");
        return 0;
    }

    return 0;
}

