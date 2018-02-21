find_package ( Threads REQUIRED )
find_program ( MEMORYCHECK_COMMAND valgrind )

include ( ExternalProject )
include ( CTest )

ExternalProject_Add ( googletest
	GIT_REPOSITORY "https://github.com/google/googletest.git"
	PREFIX "${CMAKE_CURRENT_BINARY_DIR}/gtest"
	INSTALL_COMMAND ""
	)

ExternalProject_Get_Property ( googletest
	source_dir
       	binary_dir
	)

add_library ( gtest IMPORTED STATIC GLOBAL )
add_library ( gmock IMPORTED STATIC GLOBAL )

add_dependencies ( gtest googletest )
add_dependencies ( gmock googletest )

set_target_properties ( gtest PROPERTIES
	"IMPORTED_LOCATION" "${binary_dir}/googlemock/gtest/libgtest.a"
	"IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
	)

set_target_properties ( gmock PROPERTIES
	"IMPORTED_LOCATION" "${binary_dir}/googlemock/libgmock.a"
	"IMPORTED_LINK_INTERFACE_LIBRARIES" "${CMAKE_THREAD_LIBS_INIT}"
	)

include_directories (
	"${source_dir}/googletest/include"
	"${source_dir}/googlemock/include"
	)

set ( MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full" )

file ( GLOB SOURCES *.cpp )

add_executable ( test_crypto ${SOURCES} )
add_dependencies ( test_crypto gtest gmock )

target_link_libraries ( test_crypto crypto )
target_link_libraries ( test_crypto gtest gmock )

add_test ( NAME "Crypto" COMMAND test_crypto )
