cmake_minimum_required ( VERSION 3.1 )

project ( "Crypto" CXX )
set ( CMAKE_CXX_STANDARD 11 )
set ( CMAKE_CXX_STANDARD_REQUIRED ON )

set ( CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
	CACHE STRING "Choose the type of build: None Release Debug ASan Coverage"
	FORCE )

if ( CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR )
	option ( ENABLE_TESTING "Build with tests." ON )
endif()

string ( REGEX MATCH "Clang" CMAKE_COMPILER_IS_CLANG "${CMAKE_CXX_COMPILER_ID}" )

if ( CMAKE_BUILD_TYPE STREQUAL "" )
	set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2" )
endif()

set ( CMAKE_CXX_FLAGS          "${CMAKE_CXX_FLAGS} -Wall -Wextra -W -Wwrite-strings" )
set ( CMAKE_CXX_FLAGS_RELEASE  "-O2" )
set ( CMAKE_CXX_FLAGS_DEBUG    "-O0 -g3" )
set ( CMAKE_CXX_FLAGS_ASAN     "-g3 -O2 -Werror -fsanitize=address -fno-common" )
set ( CMAKE_CXX_FLAGS_COVERAGE "-O0 -g3 --coverage" )

if ( CMAKE_COMPILER_IS_CLANG )
	set ( CMAKE_CXX_FLAGS        "${CMAKE_CXX_FLAGS} -Wpointer-arith -Wimplicit-fallthrough" )
	set ( CMAKE_CXX_FLAGS_ASAN   "${CMAKE_CXX_FLAGS_ASAN} -fsanitize=undefined -fno-sanitize-recover=all" )
endif ()

if ( CMAKE_BUILD_TYPE STREQUAL "Coverage" )
	set ( CMAKE_SHARED_LINKER_FLAGS "--coverage" )
endif ()

if ( NOT LIB_INSTALL_DIR )
    set ( LIB_INSTALL_DIR "lib" )
endif ()

include_directories ( "include" )

add_subdirectory ( "include" )
add_subdirectory ( "src" )

if ( ENABLE_TESTING )
	enable_testing ()
	add_subdirectory ( "tests" )
endif()
