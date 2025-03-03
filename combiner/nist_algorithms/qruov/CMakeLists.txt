set(QRUOV_MAKE "${CMAKE_CURRENT_SOURCE_DIR}/round2/src")
set(QRUOV_VARIANT "qruov${QRUOV_security_strength_category}q${QRUOV_q}L${QRUOV_L}v${QRUOV_v}m${QRUOV_m}")
set(QRUOV_BUILD "${CMAKE_CURRENT_SOURCE_DIR}/round2/src/${QRUOV_VARIANT}/${QRUOV_OPTIMISATION}${QRUOV_PRG}")
set(QRUOV_INCLUDE "${QRUOV_MAKE}/${QRUOV_OPTIMISATION}")

find_package(OpenSSL REQUIRED)

set(QRUOV_OBJS 
    ${QRUOV_BUILD}/Fql.o
    ${QRUOV_BUILD}/qruov.o
    ${QRUOV_BUILD}/matrix.o 
    ${QRUOV_BUILD}/mgf.o
    ${QRUOV_BUILD}/rng.o 
    ${QRUOV_BUILD}/sign.o
)

add_custom_command(
    OUTPUT ${QRUOV_OBJS}
    COMMAND make -C ${QRUOV_MAKE} clean VARIANT=${QRUOV_VARIANT} && make -C ${QRUOV_MAKE} clean && make -C ${QRUOV_MAKE} VARIANT=${QRUOV_VARIANT} PLATFORM=${QRUOV_OPTIMISATION}
    BYPRODUCTS ${QRUOV_OBJS}
)

add_custom_target(qruov_objs ALL DEPENDS ${QRUOV_OBJS})

add_library(
    qruov_wrapper STATIC
    qruov_wrapper.c
)

add_dependencies(qruov_wrapper
    qruov_objs
)

target_include_directories(qruov_wrapper PRIVATE
    ${QRUOV_BUILD}
    ${QRUOV_INCLUDE}
)

target_link_libraries(qruov_wrapper PRIVATE
    ${QRUOV_OBJS}
    OpenSSL::Crypto
)




