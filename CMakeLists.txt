cmake_minimum_required(VERSION 3.1)

project(sharedmem-c C)

include(CTest)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD          "11")

set(CMAKE_C_FLAGS
    "${CMAKE_C_FLAGS} -Wall -Wextra -Wno-missing-field-initializers")

include_directories(.)

add_subdirectory(app)
add_subdirectory(thirdparty)
