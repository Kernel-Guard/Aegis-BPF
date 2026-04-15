#!/usr/bin/env bash
# perf_exec_bench.sh — fork+execve microbenchmark for exec hook overhead.
#
# Measures the per-operation cost of fork() → execve(/bin/true) → waitpid().
# This exercises the bprm_check_security BPF LSM hook (exec identity + IMA)
# and the sched_process_fork / sched_process_exit tracepoints.
#
# Usage:
#   ITERATIONS=10000 FORMAT=json OUT=results.json ./scripts/perf_exec_bench.sh
#
# Note: exec_loop is inherently slower than open_close or connect_close
# (~100–500 µs/op vs ~1–4 µs/op), so the default iteration count is lower.
#
# Environment:
#   BIN              Path to aegisbpf binary (default: ./build/aegisbpf)
#   ITERATIONS       Number of fork+exec cycles (default: 10000)
#   WITH_AGENT       1 to start aegisbpf in audit mode (default: 0)
#   FORMAT           text or json (default: text)
#   OUT              Output file path (optional)
#   PIN_CPUS         1 to pin bench/agent to separate CPUs (default: 1)
#   BENCH_CPU        CPU for benchmark process (auto-selected if empty)
#   AGENT_CPU        CPU for agent process (auto-selected if empty)
#   EXEC_TARGET      Binary to exec (default: /bin/true)
#   WARMUP           Warmup iterations (default: 100)
#   REPEATS          Number of measurement repeats (default: 3 for json, 1 for text)
#   BURN_IN          Discarded initial repeats (default: 1 for json, 0 for text)

set -euo pipefail

BIN="${BIN:-./build/aegisbpf}"
ITERATIONS="${ITERATIONS:-10000}"
WITH_AGENT="${WITH_AGENT:-0}"
FORMAT="${FORMAT:-text}"
OUT="${OUT:-}"
PIN_CPUS="${PIN_CPUS:-1}"
BENCH_CPU="${BENCH_CPU:-}"
AGENT_CPU="${AGENT_CPU:-}"
EXEC_TARGET="${EXEC_TARGET:-/bin/true}"

if [[ "${PIN_CPUS}" -eq 1 ]] && command -v taskset >/dev/null 2>&1; then
    cpu_count="$(nproc 2>/dev/null || echo 1)"
    if [[ "${cpu_count}" -ge 2 ]]; then
        if [[ -z "${BENCH_CPU}" ]]; then
            BENCH_CPU="0"
        fi
        if [[ -z "${AGENT_CPU}" ]]; then
            AGENT_CPU="1"
        fi
    fi
fi

cleanup() {
    if [[ -n "${AGENT_PID:-}" ]]; then
        kill "${AGENT_PID}" 2>/dev/null || true
    fi
    rm -f "${LOGFILE:-}"
}
trap cleanup EXIT

if [[ ! -x "${EXEC_TARGET}" ]]; then
    echo "Exec target not found or not executable: ${EXEC_TARGET}" >&2
    exit 1
fi

if [[ "${WITH_AGENT}" -eq 1 ]]; then
    if [[ $EUID -ne 0 ]]; then
        echo "WITH_AGENT=1 requires root (BPF + cgroup access)." >&2
        exit 1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet aegisbpf.service; then
            echo "aegisbpf.service is active; stop it before WITH_AGENT=1." >&2
            exit 1
        fi
    fi
    if [[ ! -x "$BIN" ]]; then
        echo "Agent binary not found at $BIN. Build first (cmake --build build)." >&2
        exit 1
    fi
    LOGFILE=$(mktemp)
    if [[ -n "${AGENT_CPU}" ]] && command -v taskset >/dev/null 2>&1; then
        taskset -c "${AGENT_CPU}" "$BIN" run --audit >"$LOGFILE" 2>&1 &
    else
        "$BIN" run --audit >"$LOGFILE" 2>&1 &
    fi
    AGENT_PID=$!
    sleep 1
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
        echo "Agent failed to start; log follows:" >&2
        cat "$LOGFILE" >&2
        exit 1
    fi
    sleep "${AGENT_SETTLE_SECONDS:-1}"
fi

PYTHON_PREFIX=()
if [[ -n "${BENCH_CPU}" ]] && command -v taskset >/dev/null 2>&1; then
    PYTHON_PREFIX=(taskset -c "${BENCH_CPU}")
fi

"${PYTHON_PREFIX[@]}" python3 - <<PY
import json
import math
import os
import subprocess
import time

exec_target = "${EXEC_TARGET}"
iterations = int("${ITERATIONS}")
with_agent = int("${WITH_AGENT}") == 1
fmt = os.environ.get("FORMAT", "text").lower()
out_path = os.environ.get("OUT", "")
warmup = int(os.environ.get("WARMUP", "100"))
repeats = int(os.environ.get("REPEATS", "0"))
if repeats <= 0:
    repeats = 3 if fmt == "json" else 1
burn_in = int(os.environ.get("BURN_IN", "-1"))
if burn_in < 0:
    burn_in = 1 if fmt == "json" else 0

devnull = open(os.devnull, "w")

def percentile(sorted_samples, p):
    if not sorted_samples:
        return 0.0
    idx = (len(sorted_samples) - 1) * p
    lo = math.floor(idx)
    hi = math.ceil(idx)
    if lo == hi:
        return sorted_samples[lo] / 1000.0
    frac = idx - lo
    return (sorted_samples[lo] + (sorted_samples[hi] - sorted_samples[lo]) * frac) / 1000.0

def median(values):
    values = sorted(values)
    n = len(values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return float(values[mid])
    return (float(values[mid - 1]) + float(values[mid])) / 2.0

def run_once():
    # Warmup — prime caches and page tables.
    for _ in range(warmup):
        subprocess.run([exec_target], stdout=devnull, stderr=devnull)

    samples_ns = []
    start = time.perf_counter()
    for _ in range(iterations):
        op_start = time.perf_counter_ns()
        subprocess.run([exec_target], stdout=devnull, stderr=devnull)
        op_end = time.perf_counter_ns()
        samples_ns.append(op_end - op_start)
    end = time.perf_counter()
    samples_ns.sort()
    elapsed = end - start
    us_per_op = (elapsed / iterations) * 1e6
    return {
        "seconds": elapsed,
        "us_per_op": us_per_op,
        "p50_us": percentile(samples_ns, 0.50),
        "p95_us": percentile(samples_ns, 0.95),
        "p99_us": percentile(samples_ns, 0.99),
    }

runs = [run_once() for _ in range(repeats + burn_in)]
if burn_in:
    runs = runs[burn_in:]

elapsed = median([r["seconds"] for r in runs])
us_per_op = median([r["us_per_op"] for r in runs])
payload = {
    "workload": "exec_loop",
    "exec_target": exec_target,
    "iterations": iterations,
    "repeats": len(runs),
    "burn_in": burn_in,
    "seconds": round(elapsed, 6),
    "us_per_op": round(us_per_op, 2),
    "p50_us": round(median([r["p50_us"] for r in runs]), 2),
    "p95_us": round(median([r["p95_us"] for r in runs]), 2),
    "p99_us": round(median([r["p99_us"] for r in runs]), 2),
    "with_agent": with_agent,
}
if fmt == "json":
    text = json.dumps(payload, separators=(",", ":"))
else:
    text = (
        f"workload=exec_loop\n"
        f"exec_target={exec_target}\n"
        f"iterations={iterations}\n"
        f"seconds={elapsed:.6f}\n"
        f"us_per_op={us_per_op:.2f}\n"
        f"p50_us={payload['p50_us']:.2f}\n"
        f"p95_us={payload['p95_us']:.2f}\n"
        f"p99_us={payload['p99_us']:.2f}"
    )

if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text + "\n")
print(text)
devnull.close()
PY
