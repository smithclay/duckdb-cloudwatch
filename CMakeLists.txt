cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME cloudwatch)

# HTTPS uses DuckDB's bundled cpp-httplib with OpenSSL enabled; request/response JSON uses
# DuckDB's bundled yyjson. OpenSSL also provides the SHA-256/HMAC primitives for AWS SigV4.
find_package(OpenSSL REQUIRED)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD
    "17"
    CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CLOUDWATCH_DUCKDB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/duckdb")
if(NOT EXISTS "${CLOUDWATCH_DUCKDB_DIR}/third_party/httplib/httplib.hpp")
  set(CLOUDWATCH_DUCKDB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../duckdb")
endif()

include_directories(src/include)

set(EXTENSION_SOURCES
    src/cloudwatch_extension.cpp
    src/cloudwatch_catalog.cpp
    src/cloudwatch_secret.cpp
    src/cloudwatch_signing.cpp
    src/cloudwatch_client.cpp
    src/cloudwatch_json.cpp
    src/logs_table.cpp
	 src/metrics_table.cpp
    src/send_logs.cpp
    src/alerts_table.cpp
    src/service_dependencies.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
  target_include_directories(
    ${target} PRIVATE "${CLOUDWATCH_DUCKDB_DIR}/third_party/httplib"
                      "${CLOUDWATCH_DUCKDB_DIR}/third_party/yyjson/include")
  target_compile_definitions(${target} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
  target_link_libraries(${target} OpenSSL::SSL OpenSSL::Crypto)
endforeach()

add_executable(cloudwatch_json_test EXCLUDE_FROM_ALL test/cpp/cloudwatch_json_test.cpp
                                                    src/cloudwatch_json.cpp)
target_include_directories(
  cloudwatch_json_test PRIVATE src/include
                               "${CLOUDWATCH_DUCKDB_DIR}/third_party/yyjson/include")
target_link_libraries(cloudwatch_json_test duckdb_static dummy_static_extension_loader)
set_target_properties(
  cloudwatch_json_test
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
             "${CMAKE_BINARY_DIR}/extension/cloudwatch")

add_executable(cloudwatch_signing_test EXCLUDE_FROM_ALL test/cpp/cloudwatch_signing_test.cpp
                                                       src/cloudwatch_signing.cpp)
target_include_directories(cloudwatch_signing_test PRIVATE src/include)
target_link_libraries(cloudwatch_signing_test duckdb_static dummy_static_extension_loader
                                                  OpenSSL::Crypto)
set_target_properties(
  cloudwatch_signing_test
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
             "${CMAKE_BINARY_DIR}/extension/cloudwatch")

add_executable(cloudwatch_protocol_test EXCLUDE_FROM_ALL test/cpp/cloudwatch_protocol_test.cpp)
target_include_directories(cloudwatch_protocol_test PRIVATE src/include)
target_link_libraries(cloudwatch_protocol_test cloudwatch_extension duckdb_static dummy_static_extension_loader)
set_target_properties(
  cloudwatch_protocol_test
  PROPERTIES RUNTIME_OUTPUT_DIRECTORY
             "${CMAKE_BINARY_DIR}/extension/cloudwatch")

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
