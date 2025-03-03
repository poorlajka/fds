set(CROSS "CROSS-implementation/Reference_Implementation")

set(SRC "${CROSS}/lib")

set(SOURCES 
    ${SRC}/CROSS.c 
    ${SRC}/csprng_hash.c 
    ${SRC}/fips202.c 
    ${SRC}/keccakf1600.c 
    ${SRC}/merkle.c 
    ${SRC}/pack_unpack.c 
    ${SRC}/seedtree.c 
    ${SRC}/sign.c
)

add_library(
    cross_wrapper STATIC
    cross_wrapper.c
    ${SOURCES}
)

target_include_directories(cross_wrapper PRIVATE
    ${CROSS}/include
)

