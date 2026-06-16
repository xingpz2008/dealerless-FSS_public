cmake_minimum_required(VERSION 3.13)

add_library(dfss_legacy STATIC
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/cleartext.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/dcf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/dpf.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/math.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/basic_ops.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/comparison.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/containment.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/lut.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/spline_approx.cpp"
    "${DEALERLESS_FSS_OVERLAY_SRC}/legacy/utils.cpp"
)

dfss_apply_compile_options(dfss_legacy)
target_link_libraries(dfss_legacy PUBLIC dfss_common)

if(DEALERLESS_BUILD_TESTS)
    add_subdirectory(correctness)
    add_subdirectory(benchmark)
endif()
