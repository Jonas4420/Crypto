option ( INSTALL_CRYPTO_HEADERS "Install Crypto headers." ON )

if ( INSTALL_CRYPTO_HEADERS )
	file ( GLOB HEADERS "crypto/*.hpp")

	install ( FILES ${HEADERS}
		DESTINATION "include/crypto"
		PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ )
endif ()
