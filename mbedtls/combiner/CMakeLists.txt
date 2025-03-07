cmake_minimum_required(VERSION 3.15...3.31)

project(
	combiner
	VERSION 1.0
	LANGUAGES C CXX ASM
)

#enable_testing()

#[[
    Configuration and building of NIST-schemes + linking to target wrappers
    performed in this subdirectory.
]]
add_subdirectory(nist_algorithms)
# These are the (directly used) target wrappers created.
set(WRAPPERS 
    less_wrapper
    cross_wrapper
    snova_wrapper
    mayo_wrapper
    qruov_wrapper
    uov_wrapper
    sdith_wrapper
    faest_wrapper
)

# Directories containing the headers for the wrappers.
set(WRAPPERS_INCLUDE
    "nist_algorithms/cross"
    "nist_algorithms/less"
    "nist_algorithms/qruov"
    "nist_algorithms/snova"
    "nist_algorithms/mayo"
    "nist_algorithms/uov"
    "nist_algorithms/sdith"
    "nist_algorithms/faest"
)

#[[
    Build combiner
]]
add_library(
    ${PROJECT_NAME} STATIC
    combiner.c
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${WRAPPERS}
)

target_include_directories(${PROJECT_NAME} PRIVATE 
    ${WRAPPERS_INCLUDE}
)

#[[    
    Build tests 
]]
add_executable(
    combiner_test 
    test/combiner_test.c
)

target_link_libraries(combiner_test PRIVATE 
    ${PROJECT_NAME}
)

target_include_directories(combiner_test PRIVATE 
    .
)

add_executable(
    combiner_keygen
    combiner_keygen.c
)

target_link_libraries(combiner_keygen PRIVATE 
    ${PROJECT_NAME}
)

target_include_directories(combiner_keygen PRIVATE 
    .
)

#[[
add_test(
    run_combiner_test
    combiner_test
)
]]

install(TARGETS mayo_5
    EXPORT MbedTLSTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(TARGETS less_lib mayo_5_nistapi
    EXPORT MbedTLSTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

install(TARGETS ${WRAPPERS}
    EXPORT MbedTLSTargets
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
