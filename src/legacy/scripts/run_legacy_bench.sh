#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEFAULT_EZPC_ROOT="$(cd "${ROOT_DIR}/.." && pwd)/EzPC"
EZPC_ROOT="${EZPC_ROOT:-${DEFAULT_EZPC_ROOT}}"
BUILD_DIR="${ROOT_DIR}/build"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
OUT_DIR=""
PORT="$((32000 + RANDOM % 10000))"
GROUP="gen"
FUNCTION="0"
BIN="8"
BOUT="8"
SCALE="5"
USING_LUT="1"
PARTS="4"
CONFIGURE=1
BUILD=1
QUIET=0
JOBS=""

usage() {
    cat <<USAGE
Usage: src/legacy/scripts/run_legacy_bench.sh [options]

Options:
  --ezpc-root PATH     EzPC checkout used as the dependency
  --build-dir PATH     CMake build directory (default: ./build)
  --out-dir PATH       output directory for logs/results
  --port N             localhost port for two-party legacy runs
  --group NAME         gen|buildingblock|trig|proximity|biometric|ulp|safety|all
  --function N         legacy function selector for gen/buildingblock/trig
  --bits N             input bit length passed as i/b where applicable
  --output-bits N      output bit length passed as o where applicable
  --scale N            fixed-point scale for buildingblock/trig/case drivers
  --parts N            containment knot count for buildingblock f=3
  --using-lut 0|1      LUT selector for trig/proximity
  --jobs N             parallel build jobs
  --skip-configure     use the existing CMake configuration
  --skip-build         use existing legacy benchmark binaries
  --quiet              reduce terminal output; raw logs are still saved
  -h, --help           show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ezpc-root) EZPC_ROOT="$2"; shift 2 ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        --out-dir) OUT_DIR="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --group) GROUP="$2"; shift 2 ;;
        --function) FUNCTION="$2"; shift 2 ;;
        --bits) BIN="$2"; shift 2 ;;
        --output-bits) BOUT="$2"; shift 2 ;;
        --scale) SCALE="$2"; shift 2 ;;
        --parts) PARTS="$2"; shift 2 ;;
        --using-lut) USING_LUT="$2"; shift 2 ;;
        --jobs) JOBS="$2"; shift 2 ;;
        --skip-configure) CONFIGURE=0; shift ;;
        --skip-build) BUILD=0; shift ;;
        --quiet) QUIET=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

mkdir -p "$(dirname "${BUILD_DIR}")"
BUILD_DIR="$(cd "$(dirname "${BUILD_DIR}")" && pwd)/$(basename "${BUILD_DIR}")"
if [[ -z "${OUT_DIR}" ]]; then
    OUT_DIR="${BUILD_DIR}/legacy-bench-runs/${RUN_ID}"
fi
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

RUN_LOG="${OUT_DIR}/terminal.log"
RESULT_CSV="${OUT_DIR}/manifest.csv"
NOTES_FILE="${OUT_DIR}/notes.md"
: > "${RUN_LOG}"

log() {
    if [[ "${QUIET}" -eq 0 ]]; then
        echo "$@"
    fi
    echo "$@" >> "${RUN_LOG}"
}

run_logged() {
    "$@" 2>&1 | tee -a "${RUN_LOG}"
}

if [[ ! -d "${EZPC_ROOT}/FSS/src" ]]; then
    echo "EzPC root not found: ${EZPC_ROOT}" >&2
    exit 2
fi

if [[ "${CONFIGURE}" -eq 1 ]]; then
    run_logged cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
        -DEZPC_ROOT="${EZPC_ROOT}" \
        -DCMAKE_BUILD_TYPE=Release
fi

if [[ "${BUILD}" -eq 1 ]]; then
    BUILD_ARGS=(--build "${BUILD_DIR}" --target LEGACY_BENCH)
    if [[ -n "${JOBS}" ]]; then
        BUILD_ARGS+=(--parallel "${JOBS}")
    else
        BUILD_ARGS+=(--parallel)
    fi
    run_logged cmake "${BUILD_ARGS[@]}"
fi

cat > "${RESULT_CSV}" <<CSV
group,target,status,server_log,client_log,notes
CSV

{
    echo "# Legacy Benchmark Notes"
    echo
    echo "- Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "- Root: ${ROOT_DIR}"
    echo "- Build dir: ${BUILD_DIR}"
    echo "- Group: ${GROUP}"
    echo "- Function: ${FUNCTION}"
    echo "- Bits: ${BIN}"
    echo "- Output bits: ${BOUT}"
    echo "- Scale: ${SCALE}"
    echo "- Parts: ${PARTS}"
    echo "- Using LUT: ${USING_LUT}"
    echo "- Port base: ${PORT}"
    echo "- Manifest: ${RESULT_CSV}"
    echo "- Raw terminal log: ${RUN_LOG}"
} > "${NOTES_FILE}"

run_two_party() {
    local group="$1"
    local target="$2"
    local bin="$3"
    shift 3
    local args=("$@")
    local server_log="${OUT_DIR}/${group}.server.raw.log"
    local client_log="${OUT_DIR}/${group}.client.raw.log"
    local server_pid=""
    local status="ok"

    log "Running legacy group=${group} target=${target} port=${PORT}"
    "${bin}" r=2 p="${PORT}" "${args[@]}" >"${server_log}" 2>&1 &
    server_pid="$!"
    sleep 1
    if ! kill -0 "${server_pid}" 2>/dev/null; then
        wait "${server_pid}" || true
        status="server_start_failed"
    else
        if ! "${bin}" r=3 p="${PORT}" "${args[@]}" >"${client_log}" 2>&1; then
            status="client_failed"
        fi
        if ! wait "${server_pid}"; then
            status="server_failed"
        fi
    fi
    echo "${group},${target},${status},${server_log},${client_log},raw_legacy_output" >> "${RESULT_CSV}"
    [[ "${status}" == "ok" ]]
}

run_single_party() {
    local group="$1"
    local target="$2"
    local bin="$3"
    local log_file="${OUT_DIR}/${group}.raw.log"
    local status="ok"
    log "Running legacy single-process group=${group} target=${target}"
    if ! "${bin}" >"${log_file}" 2>&1; then
        status="failed"
    fi
    echo "${group},${target},${status},,${log_file},single_process_raw_legacy_output" >> "${RESULT_CSV}"
    [[ "${status}" == "ok" ]]
}

run_group() {
    case "$1" in
        gen)
            run_two_party gen LEGACY_GEN_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/gen/LEGACY_GEN_BENCH" \
                f="${FUNCTION}" i="${BIN}" o="${BOUT}"
            ;;
        buildingblock)
            run_two_party buildingblock LEGACY_BUILDINGBLOCK_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/buildingblock/LEGACY_BUILDINGBLOCK_BENCH" \
                f="${FUNCTION}" i="${BIN}" o="${BOUT}" s="${SCALE}" m="${PARTS}"
            ;;
        trig)
            run_two_party trig LEGACY_TRIG_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/trig/LEGACY_TRIG_BENCH" \
                f="${FUNCTION}" i="${BIN}" o="${BOUT}" s="${SCALE}" l="${USING_LUT}"
            ;;
        proximity)
            run_two_party proximity LEGACY_PROXIMITY_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/case_studies/LEGACY_PROXIMITY_BENCH" \
                i="${BIN}" s="${SCALE}" l="${USING_LUT}"
            ;;
        biometric)
            run_two_party biometric LEGACY_BIOMETRIC_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/case_studies/LEGACY_BIOMETRIC_BENCH"
            ;;
        ulp)
            run_single_party ulp LEGACY_ULP_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/case_studies/LEGACY_ULP_BENCH"
            ;;
        safety)
            run_two_party safety LEGACY_SAFETY_BENCH \
                "${BUILD_DIR}/src/legacy/benchmark/safety/LEGACY_SAFETY_BENCH" \
                b="${BIN}" o="${BOUT}" n=1 m=4 a=4
            ;;
        *)
            echo "Unknown legacy group: $1" >&2
            exit 2
            ;;
    esac
}

if [[ "${GROUP}" == "all" ]]; then
    run_group gen
    run_group buildingblock
    run_group trig
    run_group proximity
    run_group biometric
    run_group ulp
    run_group safety
else
    run_group "${GROUP}"
fi

log "Legacy benchmark manifest: ${RESULT_CSV}"
