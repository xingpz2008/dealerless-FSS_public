#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_EZPC_ROOT="$(cd "${ROOT_DIR}/.." && pwd)/EzPC"
EZPC_ROOT="${EZPC_ROOT:-${DEFAULT_EZPC_ROOT}}"
BUILD_DIR="${ROOT_DIR}/build"
PORT="$((32000 + RANDOM % 10000))"
BITS="19"
OUTPUT_BITS="16"
REPEAT="1"
DCF_BATCH_SIZE="128"
EVAL_ALL_BITS="12"
JOBS=""
CONFIGURE=1
BUILD=1
QUIET=0

usage() {
    cat <<USAGE
Usage: scripts/run_safety_perf.sh [options]

Options:
  --ezpc-root PATH     EzPC checkout used as the dependency
  --build-dir PATH     CMake build directory (default: ./build)
  --port N             localhost port for the two-party run
  --bits N             DPF/DCF input bit length (default: 19)
  --output-bits N      DPF/DCF output bit length (default: 16)
  --repeat N           number of repetitions (default: 1)
  --dcf-batch N        DCF batch evaluation size (default: 128)
  --eval-all-bits N    DPF evalAll bit length (default: 12)
  --jobs N             parallel build jobs
  --skip-configure     use the existing CMake configuration
  --skip-build         use the existing SAFETY_PERF_TEST binary
  --quiet              print only the final summary and timings
  -h, --help           show this help
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --ezpc-root)
            EZPC_ROOT="$2"
            shift 2
            ;;
        --build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --bits)
            BITS="$2"
            shift 2
            ;;
        --output-bits)
            OUTPUT_BITS="$2"
            shift 2
            ;;
        --repeat)
            REPEAT="$2"
            shift 2
            ;;
        --dcf-batch)
            DCF_BATCH_SIZE="$2"
            shift 2
            ;;
        --eval-all-bits)
            EVAL_ALL_BITS="$2"
            shift 2
            ;;
        --jobs)
            JOBS="$2"
            shift 2
            ;;
        --skip-configure)
            CONFIGURE=0
            shift
            ;;
        --skip-build)
            BUILD=0
            shift
            ;;
        --quiet)
            QUIET=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

mkdir -p "$(dirname "${BUILD_DIR}")"
BUILD_DIR="$(cd "$(dirname "${BUILD_DIR}")" && pwd)/$(basename "${BUILD_DIR}")"
LOG_DIR="${BUILD_DIR}/safety-perf-logs"
SERVER_LOG="${LOG_DIR}/server.log"
CLIENT_LOG="${LOG_DIR}/client.log"

if [[ ! -d "${EZPC_ROOT}/FSS/src" ]]; then
    echo "EzPC root not found: ${EZPC_ROOT}" >&2
    echo "Pass --ezpc-root PATH or set EZPC_ROOT." >&2
    exit 2
fi

if [[ "${CONFIGURE}" -eq 1 ]]; then
    cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
        -DEZPC_ROOT="${EZPC_ROOT}" \
        -DCMAKE_BUILD_TYPE=Release
fi

if [[ "${BUILD}" -eq 1 ]]; then
    BUILD_ARGS=(--build "${BUILD_DIR}" --target SAFETY_PERF_TEST)
    if [[ -n "${JOBS}" ]]; then
        BUILD_ARGS+=(--parallel "${JOBS}")
    else
        BUILD_ARGS+=(--parallel)
    fi
    cmake "${BUILD_ARGS[@]}"
fi

TEST_BIN="${BUILD_DIR}/2pc_test/SAFETY_TEST/SAFETY_PERF_TEST"
if [[ ! -x "${TEST_BIN}" ]]; then
    echo "Safety/performance binary not found: ${TEST_BIN}" >&2
    exit 2
fi

mkdir -p "${LOG_DIR}"
rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

SERVER_PID=""
cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "Running safety/performance stress b=${BITS} o=${OUTPUT_BITS} n=${REPEAT} dcf_batch=${DCF_BATCH_SIZE} eval_all_bits=${EVAL_ALL_BITS} on port ${PORT}"
"${TEST_BIN}" r=2 p="${PORT}" b="${BITS}" o="${OUTPUT_BITS}" n="${REPEAT}" m="${DCF_BATCH_SIZE}" a="${EVAL_ALL_BITS}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

sleep 1
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    wait "${SERVER_PID}" || true
    SERVER_PID=""
    echo "Server party exited before the client connected." >&2
    echo "Server log: ${SERVER_LOG}" >&2
    tail -n 40 "${SERVER_LOG}" >&2 || true
    exit 1
fi

CLIENT_STATUS=0
"${TEST_BIN}" r=3 p="${PORT}" b="${BITS}" o="${OUTPUT_BITS}" n="${REPEAT}" m="${DCF_BATCH_SIZE}" a="${EVAL_ALL_BITS}" >"${CLIENT_LOG}" 2>&1 || CLIENT_STATUS=$?

SERVER_STATUS=0
wait "${SERVER_PID}" || SERVER_STATUS=$?
SERVER_PID=""

if [[ "${CLIENT_STATUS}" -ne 0 || "${SERVER_STATUS}" -ne 0 ]]; then
    echo "Safety/performance run failed." >&2
    echo "Server log: ${SERVER_LOG}" >&2
    echo "Client log: ${CLIENT_LOG}" >&2
    tail -n 40 "${SERVER_LOG}" >&2 || true
    tail -n 40 "${CLIENT_LOG}" >&2 || true
    exit 1
fi

if [[ "${QUIET}" -eq 0 ]]; then
    echo
    echo "Detailed safety/performance results:"
    grep -E "^\\[(PASS|FAIL)\\]|Safety/performance checks:|Timing microseconds" "${SERVER_LOG}" || true
fi

if grep -q "Safety/performance checks: PASS (0 failed)" "${SERVER_LOG}"; then
    if [[ "${QUIET}" -eq 1 ]]; then
        grep -E "Safety/performance checks:|Timing microseconds" "${SERVER_LOG}"
    fi
    echo "Logs: ${LOG_DIR}"
else
    echo "Safety/performance result was not reported as PASS." >&2
    echo "Server log: ${SERVER_LOG}" >&2
    tail -n 60 "${SERVER_LOG}" >&2 || true
    exit 1
fi
