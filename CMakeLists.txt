file(GLOB SOURCES *.cpp *.hpp)

add_library(libcrypto STATIC ${SOURCES})

target_include_directories(libcrypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
