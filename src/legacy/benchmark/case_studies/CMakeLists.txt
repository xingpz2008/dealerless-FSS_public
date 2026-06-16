cmake_minimum_required(VERSION 3.13)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(DealerlessFSSLegacyCaseStudyBench LANGUAGES CXX)
    get_filename_component(DEALERLESS_FSS_ROOT
        "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
    set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory("${DEALERLESS_FSS_ROOT}" dealerless-fss)
endif()

add_executable(LEGACY_PROXIMITY_BENCH Proximity.cpp)
target_link_libraries(LEGACY_PROXIMITY_BENCH PRIVATE dfss_legacy)

add_executable(LEGACY_BIOMETRIC_BENCH Biometric.cpp)
target_link_libraries(LEGACY_BIOMETRIC_BENCH PRIVATE dfss_legacy)

add_executable(LEGACY_ULP_BENCH ULP.cpp)
target_link_libraries(LEGACY_ULP_BENCH PRIVATE dfss_legacy)
