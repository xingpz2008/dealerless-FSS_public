#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
DEFAULT_EZPC_ROOT="$(cd "${ROOT_DIR}/.." && pwd)/EzPC"
EZPC_ROOT="${EZPC_ROOT:-${DEFAULT_EZPC_ROOT}}"
BUILD_DIR="${ROOT_DIR}/build"
TEST_CASE="0"
PORT="$((32000 + RANDOM % 10000))"
JOBS=""
CONFIGURE=1
BUILD=1
QUIET=0

usage() {
    cat <<USAGE
Usage: src/legacy/scripts/run_legacy_correctness.sh [options]

Options:
  --ezpc-root PATH     EzPC checkout used as the dependency
  --build-dir PATH     CMake build directory (default: ./build)
  --case N             legacy correctness case number (default: 0, all cases)
  --port N             localhost port for the two-party run
  --jobs N             parallel build jobs
  --skip-configure     use the existing CMake configuration
  --skip-build         use the existing legacy correctness binary
  --quiet              print only the final summary
  -h, --help           show this help

Legacy case numbers:
  0 all, 1 DPF, 2 DCF, 3 comparison, 4 modular, 5 truncate,
  6 containment, 7 public LUT, 8 private LUT,
  9 digit decomposition, 10 spline, 11 trigonometric, 12 proximity
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
        --case)
            TEST_CASE="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
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

TEST_TARGET="LEGACY_CORRECTNESS_TEST"

mkdir -p "$(dirname "${BUILD_DIR}")"
BUILD_DIR="$(cd "$(dirname "${BUILD_DIR}")" && pwd)/$(basename "${BUILD_DIR}")"
LOG_DIR="${BUILD_DIR}/legacy-correctness-logs"
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
    BUILD_ARGS=(--build "${BUILD_DIR}" --target "${TEST_TARGET}")
    if [[ -n "${JOBS}" ]]; then
        BUILD_ARGS+=(--parallel "${JOBS}")
    else
        BUILD_ARGS+=(--parallel)
    fi
    cmake "${BUILD_ARGS[@]}"
fi

TEST_BIN="${BUILD_DIR}/src/legacy/correctness/${TEST_TARGET}"
if [[ ! -x "${TEST_BIN}" ]]; then
    echo "Legacy correctness binary not found: ${TEST_BIN}" >&2
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

echo "Running legacy correctness case ${TEST_CASE} on port ${PORT}"
"${TEST_BIN}" r=2 p="${PORT}" t="${TEST_CASE}" >"${SERVER_LOG}" 2>&1 &
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
"${TEST_BIN}" r=3 p="${PORT}" t="${TEST_CASE}" >"${CLIENT_LOG}" 2>&1 || CLIENT_STATUS=$?

SERVER_STATUS=0
wait "${SERVER_PID}" || SERVER_STATUS=$?
SERVER_PID=""

if [[ "${CLIENT_STATUS}" -ne 0 || "${SERVER_STATUS}" -ne 0 ]]; then
    echo "Legacy correctness run failed." >&2
    echo "Server log: ${SERVER_LOG}" >&2
    echo "Client log: ${CLIENT_LOG}" >&2
    tail -n 40 "${SERVER_LOG}" >&2 || true
    tail -n 40 "${CLIENT_LOG}" >&2 || true
    exit 1
fi

if [[ "${QUIET}" -eq 0 ]]; then
    echo
    echo "Detailed legacy correctness results:"
    grep -E "^\\[(PASS|FAIL)\\]|Correctness checks:" "${SERVER_LOG}" || true
fi

if grep -q "Correctness checks: PASS (0 failed)" "${SERVER_LOG}"; then
    if [[ "${QUIET}" -eq 1 ]]; then
        grep "Correctness checks:" "${SERVER_LOG}"
    fi
    echo "Logs: ${LOG_DIR}"
else
    echo "Legacy correctness result was not reported as PASS." >&2
    echo "Server log: ${SERVER_LOG}" >&2
    tail -n 60 "${SERVER_LOG}" >&2 || true
    exit 1
fi
