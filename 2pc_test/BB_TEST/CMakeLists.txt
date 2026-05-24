cmake_minimum_required(VERSION 3.13)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(DealerlessFSSBuildingBlockTest LANGUAGES CXX)
    get_filename_component(DEALERLESS_FSS_ROOT "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)
    set(DEALERLESS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    add_subdirectory("${DEALERLESS_FSS_ROOT}" dealerless-fss)
endif()

add_executable(BB_TEST BuildingBlock_Test.cpp)
target_link_libraries(BB_TEST PRIVATE dealerless_fss)
