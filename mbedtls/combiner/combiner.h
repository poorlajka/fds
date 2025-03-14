#pragma once 

#include <stddef.h>
#include <stdio.h>

void print_b(const void *ptr, size_t n);

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

typedef struct {
    unsigned char* public_key;
    size_t public_key_len;
    unsigned char* secret_key;
    size_t secret_key_len;
} keypair_t;

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
    keypair_t keypair;
} hybrid_t;

typedef struct {
    const unsigned char* content;
    size_t len;
} msg_t;

char* scheme_t_to_str (scheme_t scheme);

scheme_t str_to_scheme_t (char* str);

int combiner_keygen (hybrid_t* hybrid);

int combiner_sign (hybrid_t* hybrid, msg_t message);

int combiner_verify (const hybrid_t hybrid, msg_t message);

int combiner_read_keypair(hybrid_t* hybrid, const char* file_name);

int combiner_save_keypair(hybrid_t* hybrid, const char* file_name);

int combiner_read_signature(const hybrid_t* hybrid, msg_t sig, msg_t hash);

