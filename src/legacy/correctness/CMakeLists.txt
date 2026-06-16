cmake_minimum_required(VERSION 3.13)

add_executable(LEGACY_CORRECTNESS_TEST
    Legacy_Correctness_Test.cpp
    legacy_api_correctness.cpp
    math_correctness.cpp)
target_link_libraries(LEGACY_CORRECTNESS_TEST PRIVATE dfss_legacy)
