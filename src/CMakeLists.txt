set(CMAKE_FIND_DEBUG_MODE 1)

SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
SET(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")
include_directories(${CMAKE_CURRENT_LIST_DIR})

set(PROJECT_SOURCE_DIR "/ezpc_dir/EzPC/FSS")
message(${PROJECT_SOURCE_DIR})
find_package(Eigen3 QUIET NO_MODULE PATHS "${PROJECT_SOURCE_DIR}/../SCI/extern/eigen/build" NO_DEFAULT_PATH)
# origin:
# find_package(Eigen3 3.3 QUIET NO_MODULE PATHS "${PROJECT_SOURCE_DIR}/../SCI/extern/eigen/build" NO_DEFAULT_PATH)
if (NOT Eigen3_FOUND)
    message(STATUS "Eigen 3.3 was not found: clone and install Eigen3 locally")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/../SCI/extern/eigen/CMakeLists.txt")
        find_package(Git REQUIRED)
        message(STATUS "initialize Git submodule: extern/eigen")
        execute_process(COMMAND git submodule update --init --recursive ../SCI/extern/eigen
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    execute_process(COMMAND ${CMAKE_COMMAND} -E make_directory build
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/../SCI/extern/eigen/")
    execute_process(COMMAND ${CMAKE_COMMAND} -DCMAKE_INSTALL_PREFIX=${PROJECT_SOURCE_DIR}/build ..
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/../SCI/extern/eigen/build")
    find_package(Eigen3 REQUIRED NO_MODULE PATHS "${PROJECT_SOURCE_DIR}/../../SCI/extern/eigen/build" NO_DEFAULT_PATH)
endif()

find_package(OpenSSL REQUIRED)

add_library(fss STATIC 
    api.cpp
    api_varied.cpp
    lib.cpp
    deps/cryptoTools/cryptoTools/Common/Defines.cpp
    deps/cryptoTools/cryptoTools/Common/Log.cpp
    deps/cryptoTools/cryptoTools/Crypto/AES.cpp
    deps/cryptoTools/cryptoTools/Crypto/PRNG.cpp
    prng.cpp
    comms.cpp
    dcf.cpp
    2pc_idpf.cpp
        2pc_dcf.cpp
    utils.cpp
    add.cpp
    mult.cpp 
    conv.cpp
    pubdiv.cpp
    spline.cpp
    input_prng.cpp
        2pcwrapper.cpp
    2pc_api.cpp)

find_package(Threads REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIRS})

target_link_libraries(fss
    PRIVATE
    Threads::Threads
    Eigen3::Eigen
        #origin: Eigen3::Eigen
)

target_include_directories(fss
    PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:./>)

include_directories(/usr/local/include/eigen3)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../SCI/extern/eigen/)



target_include_directories(fss PRIVATE deps/cryptoTools)

target_include_directories(fss PRIVATE deps/utils)

target_include_directories(fss PRIVATE deps/OT)

target_link_libraries(fss
        PUBLIC
        SCI-OTPrimitive
        SCI-utils)

target_link_libraries(fss PRIVATE "/usr/local/lib64/libssl.so")



target_compile_options(fss PRIVATE -std=c++17 -mcpu=native -Wno-parentheses-equality -Wno-ignored-attributes -maes -msse2 -msse4.1 -mpclmul -fPIC -no-pie)
# origin
# target_compile_options(fss PRIVATE -std=c++17 -march=native -Wno-parentheses-equality -Wno-ignored-attributes -maes -msse2 -msse4.1 -mpclmul -fPIC -no-pie)

install(
    TARGETS fss SCI-OTPrimitive SCI-utils
    EXPORT FSSTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(EXPORT FSSTargets
        FILE FSSTargets.cmake
        DESTINATION lib/cmake/FSS)

install(FILES
        "utils.h"
        "fss.h"
        "dcf.h"
        "2pc_idpf.h"
        "2pc_dcf.h"
        "group_element.h"
        "ArgMapping.h"
        "comms.h"
        "api.h"
        "api_varied.h"
        "array.h"
        "lib.h"
        "keypack.h"
        "conv.h"
        "spline.h"
        "add.h"
        "mult.h"
        "pubdiv.h"
        "input_prng.h"
        "config.h"
        "2pcwrapper.h"
        "2pc_api.h"
        DESTINATION include)

install(DIRECTORY
    "deps/cryptoTools/cryptoTools"
    "deps/OT"
    "deps/utils"
    DESTINATION include)
        
        