set(UOV "${CMAKE_CURRENT_SOURCE_DIR}/pqov")
set(UOV_INCLUDE 
    "${CMAKE_CURRENT_SOURCE_DIR}/pqov/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/pqov/src/ref"
    "${CMAKE_CURRENT_SOURCE_DIR}/pqov/utils"
)

find_package(OpenSSL REQUIRED)

set(UOV_OBJS 
    ${UOV}/blas_matrix_ref.o
    ${UOV}/blas_matrix.o
    ${UOV}/ov.o
    ${UOV}/ov_keypair.o 
    ${UOV}/ov_keypair_computation.o 
    ${UOV}/ov_publicmap.o 
    ${UOV}/parallel_matrix_op.o 
    ${UOV}/sign.o 
    ${UOV}/aes128_4r_ffs.o 
    ${UOV}/fips202.o 
    ${UOV}/utils.o 
    ${UOV}/utils_hash.o 
    ${UOV}/utils_prng.o 
    ${UOV}/utils_randombytes.o 
)

add_custom_command(
    OUTPUT ${UOV_OBJS}
    COMMAND make -C ${UOV} PROJ=${UOV_PROJ} PARAM=${UOV_PARAM} VARIANT=${UOV_VARIANT}
    BYPRODUCTS ${UOV_OBJS}
)

add_custom_target(uov_objs ALL DEPENDS ${UOV_OBJS})

add_library(
    uov_wrapper STATIC
    uov_wrapper.c
)

add_dependencies(uov_wrapper
    uov_objs
)

target_include_directories(uov_wrapper PRIVATE
    ${UOV_INCLUDE}
)

target_link_libraries(uov_wrapper PRIVATE
    ${UOV_OBJS}
    OpenSSL::Crypto
)




