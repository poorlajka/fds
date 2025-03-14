#pragma once 

#include <stddef.h>
#include <stdio.h>

typedef enum {
// Code-based
    CROSS,
    LESS,
// Isogeny 
//    SQI_SIGN,
// Lattice-based 
//    HAWK,
// Multivariate 
    SNOVA,
    MAYO,
    QRUOV,
    UOV,
// MPC-in-the-Head 
    SDITH,
//    MIRATH,
//    MQOM,
//    PERK,
//    RYDE,
// Symmetric-based
    FAEST,
} scheme_t;

typedef enum {
    CONCATENATION,
    STRONG_NESTING,
} combiner_t;

typedef union {
    struct {
        unsigned char** contents;
        size_t* lens;
    } concat;
    struct {
        unsigned char* content;
        size_t len;
    } nesting;
} signature_t;

typedef struct {
    size_t len;
    scheme_t* schemes;
    combiner_t combiner; 
    signature_t signature;
} hybrid_t;

typedef struct {
    unsigned char* content;
    size_t len;
} msg_t;

typedef struct {
    unsigned char** public_key;
    unsigned char** secret_key;
} key_pair_t;

char* scheme_t_to_str (scheme_t scheme);
int combiner_keygen (hybrid_t hybrid, key_pair_t* key_pair);

int combiner_sign (hybrid_t* hybrid, unsigned char** secret_key,
                   msg_t message);

int combiner_verify (hybrid_t hybrid, unsigned char** public_key,
                      msg_t message);

