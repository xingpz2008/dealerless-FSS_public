cmake_minimum_required(VERSION 3.13)

project(DealerlessFSS LANGUAGES CXX)

option(DEALERLESS_BUILD_TESTS "Build dealerless FSS example programs" ON)

set(EZPC_ROOT "" CACHE PATH "Path to the EzPC checkout used as a dependency")
if(NOT EZPC_ROOT)
    get_filename_component(_dealerless_default_ezpc_root
        "${CMAKE_CURRENT_SOURCE_DIR}/../EzPC" ABSOLUTE)
    if(EXISTS "${_dealerless_default_ezpc_root}/FSS/src/CMakeLists.txt")
        set(EZPC_ROOT "${_dealerless_default_ezpc_root}" CACHE PATH
            "Path to the EzPC checkout used as a dependency" FORCE)
    endif()
endif()

if(NOT EXISTS "${EZPC_ROOT}/FSS/src/CMakeLists.txt")
    message(FATAL_ERROR
        "Set EZPC_ROOT to an EzPC checkout containing FSS/src. "
        "The current value is '${EZPC_ROOT}'.")
endif()

set(DEALERLESS_EZPC_FSS_SRC "${EZPC_ROOT}/FSS/src")
set(DEALERLESS_EZPC_SCI_SRC "${EZPC_ROOT}/SCI/src")
set(DEALERLESS_FSS_OVERLAY_SRC "${CMAKE_CURRENT_BINARY_DIR}/fss-overlay-src")

# Assemble a build-tree FSS source overlay so dealerless sources keep EzPC/FSS
# include semantics while EzPC remains an external dependency.
file(COPY "${DEALERLESS_EZPC_FSS_SRC}/"
    DESTINATION "${DEALERLESS_FSS_OVERLAY_SRC}")
set(DEALERLESS_OVERLAY_FILE_MAP
    "mpc/api.cpp|api.cpp"
    "mpc/comms.cpp|comms.cpp"
    "commons/public_data.cpp|public_data.cpp"
    "commons/utils.cpp|utils.cpp")
foreach(_dealerless_overlay_mapping IN LISTS DEALERLESS_OVERLAY_FILE_MAP)
    string(REPLACE "|" ";" _dealerless_overlay_pair
        "${_dealerless_overlay_mapping}")
    list(GET _dealerless_overlay_pair 0 _dealerless_overlay_src)
    list(GET _dealerless_overlay_pair 1 _dealerless_overlay_dst)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/${_dealerless_overlay_src}"
        "${DEALERLESS_FSS_OVERLAY_SRC}/${_dealerless_overlay_dst}"
        COPYONLY)
endforeach()
set(DEALERLESS_ROOT_HEADER_ALIASES
    "commons/keypack.h|keypack.h"
    "commons/utils.h|utils.h")
foreach(_dealerless_header_alias IN LISTS DEALERLESS_ROOT_HEADER_ALIASES)
    string(REPLACE "|" ";" _dealerless_header_alias_pair
        "${_dealerless_header_alias}")
    list(GET _dealerless_header_alias_pair 0 _dealerless_header_target)
    list(GET _dealerless_header_alias_pair 1 _dealerless_header_name)
    file(WRITE "${DEALERLESS_FSS_OVERLAY_SRC}/${_dealerless_header_name}"
        "#pragma once\n#include \"${_dealerless_header_target}\"\n")
endforeach()
foreach(_dealerless_overlay_dir IN ITEMS commons fss buildingblock math legacy mpc)
    file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/src/${_dealerless_overlay_dir}"
        DESTINATION "${DEALERLESS_FSS_OVERLAY_SRC}")
endforeach()

find_package(Threads REQUIRED)
find_package(Eigen3 3.3 QUIET NO_MODULE
    PATHS "${EZPC_ROOT}/SCI/extern/eigen/build"
    NO_DEFAULT_PATH)
if(NOT Eigen3_FOUND)
    find_package(Eigen3 3.3 REQUIRED NO_MODULE)
endif()
find_package(OpenMP QUIET)
list(APPEND CMAKE_MODULE_PATH "${EZPC_ROOT}/SCI/src/utils/cmake")
find_package(OpenSSL REQUIRED)
find_package(GMP REQUIRED)
if(APPLE)
    find_path(DEALERLESS_LIBOMP_INCLUDE_DIR omp.h
        PATHS /opt/homebrew/opt/libomp/include /usr/local/opt/libomp/include)
    find_library(DEALERLESS_LIBOMP_LIBRARY omp
        PATHS /opt/homebrew/opt/libomp/lib /usr/local/opt/libomp/lib)
    if(NOT DEALERLESS_LIBOMP_INCLUDE_DIR OR NOT DEALERLESS_LIBOMP_LIBRARY)
        message(FATAL_ERROR "SCI Millionaire requires libomp on macOS.")
    endif()
endif()

# Dealerless uses SCI's header-only OT and Millionaire pieces. Declare the
# utility requirements here instead of adding SCI's full source tree, which
# also configures unrelated backends and writes feature probes into its source.
add_library(dealerless_sci_headers INTERFACE)
target_include_directories(dealerless_sci_headers INTERFACE
    "${DEALERLESS_EZPC_SCI_SRC}"
    "${OPENSSL_INCLUDE_DIR}"
    "${GMP_INCLUDE_DIR}"
    "${DEALERLESS_LIBOMP_INCLUDE_DIR}")
target_compile_options(dealerless_sci_headers INTERFACE
    -pthread
    -faligned-new
    -Wno-parentheses-equality
    -Wno-deprecated-declarations
    -Wno-macro-redefined)
target_compile_definitions(dealerless_sci_headers INTERFACE
    EMP_USE_RANDOM_DEVICE=1)
target_link_libraries(dealerless_sci_headers INTERFACE
    ${OPENSSL_LIBRARIES}
    ${GMP_LIBRARIES})
if(APPLE)
    target_compile_options(dealerless_sci_headers INTERFACE
        -Xpreprocessor
        -fopenmp)
    target_link_libraries(dealerless_sci_headers INTERFACE
        "${DEALERLESS_LIBOMP_LIBRARY}")
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86")
    target_compile_options(dealerless_sci_headers INTERFACE
        -maes
        -msse4.1
        -mavx
        -mavx2)
endif()

function(dfss_apply_compile_options target_name)
    target_compile_features(${target_name} PUBLIC cxx_std_17)
    target_compile_options(${target_name} PRIVATE
        -Wno-parentheses-equality
        -Wno-ignored-attributes
        -fPIC)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${target_name} PUBLIC
            -Wno-unknown-attributes)
    endif()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86")
        target_compile_options(${target_name} PRIVATE
            -march=native
            -maes
            -msse2
            -msse4.1
            -mpclmul)
    endif()
endfunction()

add_library(dfss_common STATIC
    "${DEALERLESS_FSS_OVERLAY_SRC}/api.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/comms.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/utils.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/mpc/secure_ops.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/public_data.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Common/Defines.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Common/Log.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Crypto/AES.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Crypto/PRNG.cpp"
)

dfss_apply_compile_options(dfss_common)

target_include_directories(dfss_common
    PUBLIC
    "$<BUILD_INTERFACE:${DEALERLESS_FSS_OVERLAY_SRC}>"
    "$<BUILD_INTERFACE:${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools>"
    "$<BUILD_INTERFACE:${DEALERLESS_EZPC_SCI_SRC}>")

target_link_libraries(dfss_common
    PUBLIC
    Eigen3::Eigen
    dealerless_sci_headers
    Threads::Threads)
if(OpenMP_CXX_FOUND)
    target_link_libraries(dfss_common PUBLIC OpenMP::OpenMP_CXX)
endif()

add_library(dfss STATIC
    "${DEALERLESS_FSS_OVERLAY_SRC}/fss/dpf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/fss/idpf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/fss/fss_wrapper.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/fss/internal/ggm.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/fss/internal/correlated_ggm.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/fss/internal/payload_conversion.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/comparison.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/digit_decomposition.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/equality.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/lut.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/mic.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/modular.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/ring_extension.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/buildingblock/truncation.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/math/luteval.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/math/polyeval.cpp"
)

dfss_apply_compile_options(dfss)
target_link_libraries(dfss PUBLIC dfss_common)

add_subdirectory(src/legacy)

if(DEALERLESS_BUILD_TESTS)
    add_subdirectory(test/correctness)
    add_subdirectory(test/benchmark)
endif()
