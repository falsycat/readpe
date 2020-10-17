cmake_minimum_required(VERSION 3.1)
project(parsarg C)

include(CTest)

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-missing-field-initializers -Werror")
set(CMAKE_C_FLAGS_RELEASE
    "${CMAKE_C_FLAGS_RELEASE} -Wno-unused-parameter")

add_library(parsarg parsarg.c)

if(BUILD_TESTING AND EXISTS ${PROJECT_SOURCE_DIR}/test.c)
  add_executable(parsarg-test test.c)
  target_link_libraries(parsarg-test parsarg)

  add_test(parsarg-test parsarg-test)
endif()
