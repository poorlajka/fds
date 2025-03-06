
find_package(OpenSSL REQUIRED)

set(TYPE "sdith_hypercube")
#set(TYPE "sdith_threshhold")

set(SDITH "${CMAKE_CURRENT_SOURCE_DIR}/sdith/${SDITH_VARIANT}/${SDITH_TYPE}/${TYPE}_${SDITH_SEC_LEVEL}_${SDITH_FIELD}")

set(SDITH_OBJS
    ${SDITH}/sdith.c
    ${SDITH}/rng.c
    ${SDITH}/generator/rng.c
    ${SDITH}/sign.c
    ${SDITH}/treeprg.c
    ${SDITH}/precomputed.c
    ${SDITH}/hash-sha3.c
    ${SDITH}/gf2p32.c
    ${SDITH}/gf256.c
)

set(SDITH_LIB
    ${SDITH}/sha3/libhash.a
)


add_custom_command(
    OUTPUT ${SDITH_LIB}
    COMMAND make -C ${SDITH}
    BYPRODUCTS ${SDITH_LIB}
)

add_custom_target(sdith_lib ALL DEPENDS ${SDITH_LIB})

add_library(
    sdith_wrapper STATIC
    sdith_wrapper.c
    ${SDITH_OBJS}
)

add_dependencies(sdith_wrapper
    sdith_lib
)

target_include_directories(sdith_wrapper PRIVATE
    ${SDITH}
    ${SDITH}/sha3
    ${SDITH}/sha3/avx2
    ${SDITH}/generator
)

target_link_libraries(sdith_wrapper PRIVATE
    ${SDITH_LIB}
    OpenSSL::Crypto
)

target_compile_options(sdith_wrapper PRIVATE
    -DCAT_5 -DNDEBUG
)






