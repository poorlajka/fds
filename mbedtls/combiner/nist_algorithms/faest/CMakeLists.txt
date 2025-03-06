set(FAEST_VER "${CMAKE_CURRENT_SOURCE_DIR}/faest-ref/build/faest_em_256f")
set(FAEST_BUILD "${CMAKE_CURRENT_SOURCE_DIR}/faest-ref/build")

set(FAEST_LIB
    ${FAEST_VER}/libfaest_em_256f.a
)

add_custom_command(
    OUTPUT ${FAEST_LIB}
    COMMAND mkdir -p ${FAEST_BUILD} && cd ${FAEST_BUILD} && meson .. && ninja
    BYPRODUCTS ${FAEST_LIB}
)

add_custom_target(faest_lib ALL DEPENDS ${FAEST_LIB})

add_library(
    faest_wrapper STATIC
    faest_wrapper.c
    ${FAEST_VER}/crypto_sign.c
)

add_dependencies(faest_wrapper
    faest_lib
)

target_include_directories(faest_wrapper PRIVATE
    ${FAEST_VER}
    ${CMAKE_CURRENT_SOURCE_DIR}/faest-ref/build
    ${CMAKE_CURRENT_SOURCE_DIR}/faest-ref
)

target_link_libraries(faest_wrapper PRIVATE
    ${FAEST_LIB}
    ${CMAKE_CURRENT_SOURCE_DIR}/faest-ref/build/libfaest.so
)




