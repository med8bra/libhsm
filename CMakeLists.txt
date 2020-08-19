cmake_minimum_required (VERSION 3.9)
project (libhsm VERSION 1.0.1 DESCRIPTION "a wrapper around OASIS PKCS#11 API")
include(GNUInstallDirs)

SET(CPPFLAGS "-DOS_UNIX -O3")
SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${CPPFLAGS}")

file(GLOB LIBHSM_SOURCES "src/*.cpp")

add_library(libhsm SHARED
	${LIBHSM_SOURCES}
	)

target_include_directories (libhsm PUBLIC include)

configure_file(libhsm.pc.in libhsm.pc @ONLY)

set_target_properties(libhsm PROPERTIES PREFIX "")

install(TARGETS libhsm
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/
	)
install(DIRECTORY include/
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/libhsm
	)
install(FILES ${CMAKE_BINARY_DIR}/libhsm.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)


if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()