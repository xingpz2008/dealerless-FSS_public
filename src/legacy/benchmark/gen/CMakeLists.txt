cmake_minimum_required(VERSION 3.13)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(DealerlessFSSLegacyGenBench LANGUAGES CXX)
    get_filename_component(DEALERLESS_FSS_ROOT
        "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
    set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory("${DEALERLESS_FSS_ROOT}" dealerless-fss)
endif()

add_executable(LEGACY_GEN_BENCH genTest.cpp)
target_link_libraries(LEGACY_GEN_BENCH PRIVATE dfss_legacy)
