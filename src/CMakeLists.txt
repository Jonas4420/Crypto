option ( USE_STATIC_CRYPTO_LIBRARY "Build Crypto static library." ON )
option ( USE_SHARED_CRYPTO_LIBRARY "Build Crypto shared library." OFF )

file ( GLOB SOURCES *.cpp *.hpp )

if ( CMAKE_COMPILER_IS_CLANG )
	set ( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wunreachable-code" )
endif ()

if ( NOT USE_STATIC_CRYPTO_LIBRARY AND NOT USE_SHARED_CRYPTO_LIBRARY )
	message ( FATAL_ERROR "Need to choose static or shared Crypto build!" )
endif ( NOT USE_STATIC_CRYPTO_LIBRARY AND NOT USE_SHARED_CRYPTO_LIBRARY )

if ( USE_STATIC_CRYPTO_LIBRARY AND USE_SHARED_CRYPTO_LIBRARY )
	set ( crypto_static_target "crypto_static" )
elseif ( USE_STATIC_CRYPTO_LIBRARY )
	set ( crypto_static_target "crypto" )
endif()

if ( USE_STATIC_CRYPTO_LIBRARY )
	add_library ( ${crypto_static_target} STATIC ${SOURCES} )
	set_target_properties ( ${crypto_static_target} PROPERTIES OUTPUT_NAME "crypto" )

	install ( TARGETS ${crypto_static_target}
		DESTINATION ${LIB_INSTALL_DIR}
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE )
endif ()

if ( USE_SHARED_CRYPTO_LIBRARY )
	add_library ( "crypto" SHARED ${SOURCES} )
	set_target_properties ( "crypto" PROPERTIES VERSION 1.0.0 SOVERSION 0 )

	install ( TARGETS "crypto"
		DESTINATION ${LIB_INSTALL_DIR}
		PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE )
endif ()
