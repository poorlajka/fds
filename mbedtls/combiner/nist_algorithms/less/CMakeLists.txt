set(LESS "LESS/Reference_Implementation")

set(SRC "${LESS}/lib")

set(SOURCES 
    ${SRC}/LESS.c 
    ${SRC}/canonical.c 
    ${SRC}/codes.c 
    ${SRC}/fips202.c 
    ${SRC}/keccakf1600.c 
    ${SRC}/monomial.c 
    ${SRC}/rng.c 
    ${SRC}/seedtree.c
    ${SRC}/sign.c
    ${SRC}/sort.c
    ${SRC}/transpose.c
    ${SRC}/utils.c
)

add_library(
    less_lib STATIC 
    ${SOURCES}
)

add_library(
    less_wrapper
    less_wrapper.c
)

target_include_directories(less_lib PRIVATE
    ${LESS}/include
)
target_include_directories(less_wrapper PRIVATE
    ${LESS}/include
)

target_link_libraries(less_wrapper PRIVATE
    less_lib
)



