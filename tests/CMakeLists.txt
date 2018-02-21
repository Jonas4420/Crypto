find_package ( Threads REQUIRED )
find_program ( MEMORYCHECK_COMMAND valgrind )

include ( CTest )

set ( MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full" )

configure_file ( "CMakeLists.txt.in" "googletest/CMakeLists.txt" )
execute_process ( COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/googletest" )
execute_process ( COMMAND "${CMAKE_COMMAND}" --build                 .  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/googletest" )

add_subdirectory ( "${CMAKE_CURRENT_BINARY_DIR}/googletest/src" "${CMAKE_CURRENT_BINARY_DIR}/googletest/build" )

file ( GLOB SOURCES *.cpp )

add_executable ( test_crypto ${SOURCES} )

target_link_libraries ( test_crypto crypto )
target_link_libraries ( test_crypto gtest gmock )

if ( CMAKE_BUILD_TYPE STREQUAL "Release" )
	add_test ( NAME "Crypto" COMMAND "test_crypto" )
else()
	add_test ( NAME "Crypto" COMMAND "test_crypto" "-fast" )
endif()
