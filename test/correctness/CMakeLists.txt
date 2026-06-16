cmake_minimum_required(VERSION 3.13)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(DealerlessFSSCorrectnessTest LANGUAGES CXX)
    get_filename_component(DEALERLESS_FSS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory("${DEALERLESS_FSS_ROOT}" dealerless-fss)
endif()

add_executable(DFSS_CORRECTNESS_TEST
    correctness.cpp
    protocol/buildingblocks.cpp
    protocol/extensions.cpp
    protocol/primitives.cpp)
target_include_directories(DFSS_CORRECTNESS_TEST PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/common"
    "${CMAKE_CURRENT_LIST_DIR}/protocol")
target_link_libraries(DFSS_CORRECTNESS_TEST PRIVATE dfss)

add_executable(HELPER_CORRECTNESS_TEST
    helper/helper_correctness.cpp
    helper/cases.cpp)
target_include_directories(HELPER_CORRECTNESS_TEST PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}"
    "${CMAKE_CURRENT_LIST_DIR}/common"
    "${CMAKE_CURRENT_LIST_DIR}/helper")
target_link_libraries(HELPER_CORRECTNESS_TEST PRIVATE dfss_common)
