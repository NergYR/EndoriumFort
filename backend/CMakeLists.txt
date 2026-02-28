cmake_minimum_required(VERSION 3.16)
project(endoriumfort_backend LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG asio-1-30-2
)

FetchContent_Declare(
  crow
  GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
  GIT_TAG v1.2.0
)

FetchContent_MakeAvailable(asio)
set(ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/asio/include" CACHE PATH "" FORCE)
FetchContent_MakeAvailable(crow)

find_package(SQLite3 REQUIRED)
find_package(LibSSH2 QUIET)
if (NOT LibSSH2_FOUND)
  find_package(PkgConfig QUIET)
  if (PkgConfig_FOUND)
    pkg_check_modules(LIBSSH2 QUIET IMPORTED_TARGET libssh2)
  endif()
endif()

# Version is now managed by build-all.sh/ps1 (change-detection based).
# Manual fallback: increment on every build if version.h is missing.
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/version.h")
  add_custom_target(increment_version
      COMMAND ${CMAKE_COMMAND} -DVERSION_FILE=${CMAKE_CURRENT_SOURCE_DIR}/VERSION -DVERSION_HEADER_FILE=${CMAKE_CURRENT_SOURCE_DIR}/src/version.h -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/increment_version.cmake
      COMMENT "Generating version.h (first build)..."
  )
else()
  add_custom_target(increment_version
      COMMENT "Version managed by build-all.sh — skipping auto-increment."
  )
endif()

add_executable(endoriumfort_backend
  src/main.cc
  src/app_context.cc
  src/http_proxy.cc
  src/routes.cc
  src/ssh.cc
  src/tunnel.cc
  src/session_recording.cc
  src/rdp.cc
)

add_dependencies(endoriumfort_backend increment_version)

target_include_directories(endoriumfort_backend
  PRIVATE
    ${crow_SOURCE_DIR}/include
    ${asio_SOURCE_DIR}/asio/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(endoriumfort_backend
  PRIVATE ASIO_STANDALONE
)

target_link_libraries(endoriumfort_backend PRIVATE SQLite::SQLite3)

if (LibSSH2_FOUND)
  target_link_libraries(endoriumfort_backend PRIVATE LibSSH2::LibSSH2)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_SSH_ENABLED)
elseif (TARGET PkgConfig::LIBSSH2)
  target_link_libraries(endoriumfort_backend PRIVATE PkgConfig::LIBSSH2)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_SSH_ENABLED)
else()
  message(WARNING "LibSSH2 not found: SSH proxy disabled")
endif()

if (WIN32)
  target_link_libraries(endoriumfort_backend PRIVATE ws2_32 mswsock)
endif()
