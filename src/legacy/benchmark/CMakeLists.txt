cmake_minimum_required(VERSION 3.13)

add_subdirectory(gen)
add_subdirectory(buildingblock)
add_subdirectory(trig)
add_subdirectory(case_studies)
add_subdirectory(safety)

add_custom_target(LEGACY_BENCH
    DEPENDS
    LEGACY_GEN_BENCH
    LEGACY_BUILDINGBLOCK_BENCH
    LEGACY_TRIG_BENCH
    LEGACY_PROXIMITY_BENCH
    LEGACY_BIOMETRIC_BENCH
    LEGACY_ULP_BENCH
    LEGACY_SAFETY_BENCH)
