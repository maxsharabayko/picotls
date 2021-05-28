FILE(GLOB SOURCES *.cpp *.hpp *.c)

add_executable(tls-client ${SOURCES})

target_include_directories(tls-client PUBLIC
	${CMAKE_SOURCE_DIR}/submodule/quicly/include
	${CMAKE_SOURCE_DIR}/submodule/quicly/deps/picotls/include
)

target_link_libraries(tls-client
	PRIVATE picotls-openssl
	PRIVATE picotls-core
)

if ( WIN32 AND (NOT MINGW AND NOT CYGWIN))
	target_link_libraries(tls-client PRIVATE ws2_32.lib)
endif()
