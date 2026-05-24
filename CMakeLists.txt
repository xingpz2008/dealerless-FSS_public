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
set(DEALERLESS_OVERLAY_FILES
    2pc_api.cpp
    2pc_api.h
    2pc_cleartext.cpp
    2pc_cleartext.h
    2pc_dcf.cpp
    2pc_dcf.h
    2pc_idpf.cpp
    2pc_idpf.h
    2pc_math.cpp
    2pc_math.h
    2pcwrapper.cpp
    2pcwrapper.h
    api.cpp
    api.h
    comms.cpp
    comms.h
    group_element.h
    keypack.h
    utils.cpp
    utils.h)
foreach(_dealerless_overlay_file IN LISTS DEALERLESS_OVERLAY_FILES)
    configure_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/src/${_dealerless_overlay_file}"
        "${DEALERLESS_FSS_OVERLAY_SRC}/${_dealerless_overlay_file}"
        COPYONLY)
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

add_library(dealerless_fss STATIC
    "${DEALERLESS_FSS_OVERLAY_SRC}/api.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/comms.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/utils.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/2pc_api.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/2pc_cleartext.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/2pc_dcf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/2pc_idpf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/2pc_math.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/2pcwrapper.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/api_varied.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/lib.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/prng.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/dcf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/add.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/mult.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/conv.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/pubdiv.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/spline.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/input_prng.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Common/Defines.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Common/Log.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Crypto/AES.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools/cryptoTools/Crypto/PRNG.cpp"
)

target_compile_features(dealerless_fss PUBLIC cxx_std_17)
target_compile_options(dealerless_fss PRIVATE
    -Wno-parentheses-equality
    -Wno-ignored-attributes
    -fPIC)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(dealerless_fss PUBLIC
        -Wno-unknown-attributes)
endif()
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86")
    target_compile_options(dealerless_fss PRIVATE
        -march=native
        -maes
        -msse2
        -msse4.1
        -mpclmul)
endif()

target_include_directories(dealerless_fss
    PUBLIC
    "$<BUILD_INTERFACE:${DEALERLESS_FSS_OVERLAY_SRC}>"
    "$<BUILD_INTERFACE:${DEALERLESS_FSS_OVERLAY_SRC}/deps/cryptoTools>"
    "$<BUILD_INTERFACE:${DEALERLESS_EZPC_SCI_SRC}>")

target_link_libraries(dealerless_fss
    PUBLIC
    Eigen3::Eigen
    dealerless_sci_headers
    Threads::Threads)
if(OpenMP_CXX_FOUND)
    target_link_libraries(dealerless_fss PUBLIC OpenMP::OpenMP_CXX)
endif()

if(DEALERLESS_BUILD_TESTS)
    add_subdirectory(2pc_test/GEN_TEST)
    add_subdirectory(2pc_test/BB_TEST)
    add_subdirectory(2pc_test/TRI_TEST)
    add_subdirectory(2pc_test/CASE_STUDIES)
    add_subdirectory(2pc_test/CORRECTNESS_TEST)
endif()
