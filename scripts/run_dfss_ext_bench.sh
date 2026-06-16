#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEFAULT_EZPC_ROOT="$(cd "${ROOT_DIR}/.." && pwd)/EzPC"
EZPC_ROOT="${EZPC_ROOT:-${DEFAULT_EZPC_ROOT}}"
BUILD_DIR="${ROOT_DIR}/build"
PORT="$((32000 + RANDOM % 10000))"
BENCH=""
BIN=""
BOUT=""
REPEAT="10"
ET=""
SUFFIX=""
PARTS=""
SCALE=""
DEGREE=""
PHASE="all"
PROTOCOL="all"
SKIP_CORRECTNESS=0
JOBS=""
CONFIGURE=1
BUILD=1
QUIET=0
RUN_ID="$(date +%Y%m%d_%H%M%S)_$$"
OUT_DIR=""

usage() {
    cat <<USAGE
Usage: scripts/run_dfss_ext_bench.sh [options]

Options:
  --ezpc-root PATH     EzPC checkout used as the dependency
  --build-dir PATH     CMake build directory (default: ./build)
  --out-dir PATH       output directory for logs/results
  --port N             localhost port for the two-party run
  --bench NAME         et|dpf|idpf|lut|mic|comparison|poly|equality|payload_conversion
  --bin N              input bit length (optional for payload_conversion)
  --bout N             output bit length (default: bin)
  --repeat N           repeat count (default: 10)
  --et 0|1             ET flag passed to the C++ benchmark
  --suffix N           ET suffix; -1 means default when et=1
  --parts N            MIC intervals or Poly segments
  --scale N            fixed-point scale for Poly
  --degree N           polynomial degree for Poly
  --phase NAME         all|offline (default: all)
  --protocol NAME      protocol selector passed through to C++ (default: all)
  --skip-correctness   pass skip_correctness=1 to C++
  --jobs N             parallel build jobs
  --skip-configure     use the existing CMake configuration
  --skip-build         use the existing DFSS_EXT_BENCH binary
  --quiet              reduce terminal output; raw logs are still saved
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
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --bench)
            BENCH="$2"
            shift 2
            ;;
        --bin)
            BIN="$2"
            shift 2
            ;;
        --bout)
            BOUT="$2"
            shift 2
            ;;
        --repeat)
            REPEAT="$2"
            shift 2
            ;;
        --et)
            ET="$2"
            shift 2
            ;;
        --suffix)
            SUFFIX="$2"
            shift 2
            ;;
        --parts)
            PARTS="$2"
            shift 2
            ;;
        --scale)
            SCALE="$2"
            shift 2
            ;;
        --degree)
            DEGREE="$2"
            shift 2
            ;;
        --phase)
            PHASE="$2"
            shift 2
            ;;
        --protocol)
            PROTOCOL="$2"
            shift 2
            ;;
        --skip-correctness)
            SKIP_CORRECTNESS=1
            shift
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

if [[ -z "${BENCH}" ]]; then
    echo "--bench is required" >&2
    usage >&2
    exit 2
fi
if [[ -z "${BIN}" && "${BENCH}" != "payload_conversion" ]]; then
    echo "--bin is required" >&2
    usage >&2
    exit 2
fi

mkdir -p "$(dirname "${BUILD_DIR}")"
BUILD_DIR="$(cd "$(dirname "${BUILD_DIR}")" && pwd)/$(basename "${BUILD_DIR}")"
if [[ -z "${OUT_DIR}" ]]; then
    OUT_DIR="${BUILD_DIR}/dfss-ext-bench-runs/${RUN_ID}"
fi
mkdir -p "${OUT_DIR}"
OUT_DIR="$(cd "${OUT_DIR}" && pwd)"

RUN_LOG="${OUT_DIR}/terminal.log"
SERVER_LOG="${OUT_DIR}/server.raw.log"
CLIENT_LOG="${OUT_DIR}/client.raw.log"
RESULT_CSV="${OUT_DIR}/results.csv"
AGGREGATE_CSV="${OUT_DIR}/aggregate_results.csv"
COMPACT_CSV="${OUT_DIR}/summary_compact.csv"
PAPER_CSV="${OUT_DIR}/paper_summary.csv"
RATIO_CSV="${OUT_DIR}/summary_ratios.csv"
NOTES_FILE="${OUT_DIR}/notes.md"
PROCESS_METRICS="${OUT_DIR}/process_metrics.csv"

: > "${RUN_LOG}"

log() {
    echo "$@" | tee -a "${RUN_LOG}"
}

run_logged() {
    "$@" 2>&1 | tee -a "${RUN_LOG}"
}

BENCH_ARGS=(
    "bench=${BENCH}"
    "repeat=${REPEAT}"
    "phase=${PHASE}"
    "protocol=${PROTOCOL}"
    "output=csv"
)
if [[ -n "${BIN}" ]]; then
    BENCH_ARGS+=("bin=${BIN}")
fi
if [[ -n "${BOUT}" ]]; then
    BENCH_ARGS+=("bout=${BOUT}")
fi
if [[ -n "${ET}" ]]; then
    BENCH_ARGS+=("et=${ET}")
fi
if [[ -n "${SUFFIX}" ]]; then
    BENCH_ARGS+=("suffix=${SUFFIX}")
fi
if [[ -n "${PARTS}" ]]; then
    BENCH_ARGS+=("parts=${PARTS}")
fi
if [[ -n "${SCALE}" ]]; then
    BENCH_ARGS+=("scale=${SCALE}")
fi
if [[ -n "${DEGREE}" ]]; then
    BENCH_ARGS+=("degree=${DEGREE}")
fi
if [[ "${SKIP_CORRECTNESS}" -eq 1 ]]; then
    BENCH_ARGS+=("skip_correctness=1")
fi

{
    echo "# dFSS Extension Benchmark Notes"
    echo
    echo "- Date: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "- Root: ${ROOT_DIR}"
    echo "- Build dir: ${BUILD_DIR}"
    echo "- Bench: ${BENCH}"
    echo "- Bin: ${BIN:-default}"
    echo "- Bout: ${BOUT:-default}"
    echo "- Repeat: ${REPEAT}"
    echo "- Phase: ${PHASE}"
    echo "- Protocol: ${PROTOCOL}"
    echo "- Port: ${PORT}"
    echo "- OMP_NUM_THREADS: ${OMP_NUM_THREADS:-unset}"
    echo "- Round source: peer->rounds delta"
    echo "- Reconstruct-round source: numRounds delta"
    echo "- Raw communication source: per-party peer->bytesSent/bytesReceived deltas"
    echo "- Aggregate communication source: bytes_sent_party2 + bytes_sent_party3"
    echo "- Aggregate time/round source: max over the two parties"
    echo "- Raw server log: ${SERVER_LOG}"
    echo "- Raw client log: ${CLIENT_LOG}"
    echo "- Terminal log: ${RUN_LOG}"
    echo "- Compact summary: ${COMPACT_CSV}"
    echo "- Paper-facing summary: ${PAPER_CSV}"
    echo "- Ratio summary: ${RATIO_CSV}"
} > "${NOTES_FILE}"

cat > "${RESULT_CSV}" <<CSV
party,group,protocol,phase,Bin,Bout,repeat,suffixBits,lambdaBits,degree,scale,segments,intervalCount,evaluatedPoints,time_us,bytes_sent,bytes_received,comm_bytes,peer_rounds,reconstruct_rounds,plaintext_max_abs_error,ciphertext_vs_plaintext_max_abs_error,status,notes
CSV
cat > "${PROCESS_METRICS}" <<CSV
party,max_resident_set_size_bytes
CSV

log "Benchmark output directory: ${OUT_DIR}"
log "Raw terminal log: ${RUN_LOG}"
log "Unified CSV: ${RESULT_CSV}"
log "Aggregate CSV: ${AGGREGATE_CSV}"
log "Compact summary: ${COMPACT_CSV}"
log "Paper summary: ${PAPER_CSV}"
log "Ratio summary: ${RATIO_CSV}"

if [[ ! -d "${EZPC_ROOT}/FSS/src" ]]; then
    log "EzPC root not found: ${EZPC_ROOT}"
    echo "- ERROR: EzPC root not found: ${EZPC_ROOT}" >> "${NOTES_FILE}"
    exit 2
fi

if [[ "${CONFIGURE}" -eq 1 ]]; then
    log "Configuring build..."
    run_logged cmake -S "${ROOT_DIR}" -B "${BUILD_DIR}" \
        -DEZPC_ROOT="${EZPC_ROOT}" \
        -DCMAKE_BUILD_TYPE=Release
fi

if [[ "${BUILD}" -eq 1 ]]; then
    log "Building DFSS_EXT_BENCH..."
    BUILD_ARGS=(--build "${BUILD_DIR}" --target DFSS_EXT_BENCH)
    if [[ -n "${JOBS}" ]]; then
        BUILD_ARGS+=(--parallel "${JOBS}")
    else
        BUILD_ARGS+=(--parallel)
    fi
    run_logged cmake "${BUILD_ARGS[@]}"
fi

TEST_BIN="${BUILD_DIR}/test/benchmark/DFSS_EXT_BENCH"
if [[ ! -x "${TEST_BIN}" ]]; then
    log "Benchmark binary not found: ${TEST_BIN}"
    echo "- ERROR: benchmark binary not found: ${TEST_BIN}" >> "${NOTES_FILE}"
    exit 2
fi

rm -f "${SERVER_LOG}" "${CLIENT_LOG}"

SERVER_PID=""
cleanup() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
        kill "${SERVER_PID}" 2>/dev/null || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

TIME_PREFIX=()
if [[ "$(uname -s)" == "Darwin" && -x /usr/bin/time ]]; then
    TIME_PREFIX=(/usr/bin/time -l)
fi

log "Running DFSS_EXT_BENCH bench=${BENCH} bin=${BIN:-default} repeat=${REPEAT} port=${PORT}"
"${TIME_PREFIX[@]}" "${TEST_BIN}" \
    role=server port="${PORT}" "${BENCH_ARGS[@]}" >"${SERVER_LOG}" 2>&1 &
SERVER_PID="$!"

sleep 1
if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    wait "${SERVER_PID}" || true
    SERVER_PID=""
    log "Server party exited before the client connected."
    echo "- ERROR: server exited before client connected" >> "${NOTES_FILE}"
    tail -n 80 "${SERVER_LOG}" 2>&1 | tee -a "${RUN_LOG}" || true
    exit 1
fi

CLIENT_STATUS=0
"${TIME_PREFIX[@]}" "${TEST_BIN}" \
    role=client port="${PORT}" "${BENCH_ARGS[@]}" >"${CLIENT_LOG}" 2>&1 || CLIENT_STATUS=$?

SERVER_STATUS=0
wait "${SERVER_PID}" || SERVER_STATUS=$?
SERVER_PID=""

if [[ "${CLIENT_STATUS}" -ne 0 || "${SERVER_STATUS}" -ne 0 ]]; then
    log "Benchmark run failed. server=${SERVER_STATUS} client=${CLIENT_STATUS}"
    echo "- ERROR: benchmark failed; server=${SERVER_STATUS}, client=${CLIENT_STATUS}" >> "${NOTES_FILE}"
    log "Server tail:"
    tail -n 80 "${SERVER_LOG}" 2>&1 | tee -a "${RUN_LOG}" || true
    log "Client tail:"
    tail -n 80 "${CLIENT_LOG}" 2>&1 | tee -a "${RUN_LOG}" || true
    exit 1
fi

grep '^CSV,' "${SERVER_LOG}" | sed 's/^CSV,//' >> "${RESULT_CSV}" || true
grep '^CSV,' "${CLIENT_LOG}" | sed 's/^CSV,//' >> "${RESULT_CSV}" || true
python3 "${ROOT_DIR}/scripts/summarize_dfss_ext_bench.py" \
    "${RESULT_CSV}" "${AGGREGATE_CSV}"
SERVER_RSS="$(awk '/maximum resident set size/ {print $1; exit}' "${SERVER_LOG}" || true)"
CLIENT_RSS="$(awk '/maximum resident set size/ {print $1; exit}' "${CLIENT_LOG}" || true)"
if [[ -n "${SERVER_RSS}" ]]; then
    echo "2,${SERVER_RSS}" >> "${PROCESS_METRICS}"
fi
if [[ -n "${CLIENT_RSS}" ]]; then
    echo "3,${CLIENT_RSS}" >> "${PROCESS_METRICS}"
fi

SERVER_ROWS="$(grep -c '^CSV,' "${SERVER_LOG}" || true)"
CLIENT_ROWS="$(grep -c '^CSV,' "${CLIENT_LOG}" || true)"
{
    echo
    echo "## Run Result"
    echo
    echo "- Status: PASS"
    echo "- Server CSV rows: ${SERVER_ROWS}"
    echo "- Client CSV rows: ${CLIENT_ROWS}"
    echo "- Results CSV: ${RESULT_CSV}"
    echo "- Aggregate results CSV: ${AGGREGATE_CSV}"
    echo "- Paper-facing summary CSV: ${PAPER_CSV}"
    echo "- Process metrics CSV: ${PROCESS_METRICS}"
    if [[ -n "${SERVER_RSS}" ]]; then
        echo "- Server max RSS bytes: ${SERVER_RSS}"
    fi
    if [[ -n "${CLIENT_RSS}" ]]; then
        echo "- Client max RSS bytes: ${CLIENT_RSS}"
    fi
} >> "${NOTES_FILE}"

log "Benchmark PASS"
log "Server CSV rows: ${SERVER_ROWS}"
log "Client CSV rows: ${CLIENT_ROWS}"
log "Aggregate results: ${AGGREGATE_CSV}"
log "Paper summary: ${PAPER_CSV}"
if [[ -n "${SERVER_RSS}" || -n "${CLIENT_RSS}" ]]; then
    log "Process metrics: ${PROCESS_METRICS}"
fi
if [[ "${QUIET}" -eq 0 ]]; then
    log ""
    log "First result rows:"
    sed -n '1,12p' "${RESULT_CSV}" | tee -a "${RUN_LOG}"
    log ""
    log "First aggregate rows:"
    sed -n '1,12p' "${AGGREGATE_CSV}" | tee -a "${RUN_LOG}"
    log ""
    log "First paper summary rows:"
    sed -n '1,12p' "${PAPER_CSV}" | tee -a "${RUN_LOG}"
fi
log "Logs and notes: ${OUT_DIR}"
