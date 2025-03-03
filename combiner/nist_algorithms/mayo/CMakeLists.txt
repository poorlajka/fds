set(MAYO "MAYO-C")

add_subdirectory(${MAYO})

add_library(
    mayo_wrapper 
    mayo_wrapper.c
)

# MAYO wrapper include headers
target_include_directories(mayo_wrapper PRIVATE
	${MAYO}/include
	${MAYO}/src
)

# MAYO wrapper link API
target_link_libraries(mayo_wrapper PRIVATE 
    mayo_5_nistapi
)