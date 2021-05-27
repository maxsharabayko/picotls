FILE(GLOB SOURCES *.cpp *.hpp *.c)

add_executable(tls-server ${SOURCES})

target_include_directories(tls-server PUBLIC
	${CMAKE_SOURCE_DIR}/submodule/quicly/include
	${CMAKE_SOURCE_DIR}/submodule/quicly/deps/picotls/include
)

target_link_libraries(tls-server
	PRIVATE picotls-openssl
	PRIVATE picotls-core
)

if ( WIN32 AND (NOT MINGW AND NOT CYGWIN))
	target_link_libraries(tls-server PRIVATE ws2_32.lib)
endif()
