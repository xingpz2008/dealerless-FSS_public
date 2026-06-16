cmake_minimum_required(VERSION 3.13)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(DealerlessFSSDfssExtBench LANGUAGES CXX)
    get_filename_component(DEALERLESS_FSS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory("${DEALERLESS_FSS_ROOT}" dealerless-fss)
endif()

add_executable(DFSS_EXT_BENCH
    benchmark.cpp
    helper/cli.cpp
    helper/common.cpp
    helper/report.cpp
    protocol/buildingblocks.cpp
    protocol/dpf.cpp
    protocol/et.cpp
    microbench/payload_conversion.cpp)
target_include_directories(DFSS_EXT_BENCH PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/helper"
    "${CMAKE_CURRENT_LIST_DIR}/protocol")
target_link_libraries(DFSS_EXT_BENCH PRIVATE dfss)
