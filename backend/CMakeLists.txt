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
find_package(LibSSH2)

add_executable(endoriumfort_backend
  src/main.cc
)

target_include_directories(endoriumfort_backend
  PRIVATE
    ${crow_SOURCE_DIR}/include
    ${asio_SOURCE_DIR}/asio/include
)

target_compile_definitions(endoriumfort_backend
  PRIVATE ASIO_STANDALONE
)

target_link_libraries(endoriumfort_backend PRIVATE SQLite::SQLite3)

if (LibSSH2_FOUND)
  target_link_libraries(endoriumfort_backend PRIVATE LibSSH2::LibSSH2)
  target_compile_definitions(endoriumfort_backend PRIVATE ENDORIUMFORT_SSH_ENABLED)
else()
  message(WARNING "LibSSH2 not found: SSH proxy disabled")
endif()

if (WIN32)
  target_link_libraries(endoriumfort_backend PRIVATE ws2_32 mswsock)
endif()
