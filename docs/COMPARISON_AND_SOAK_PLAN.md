# AegisBPF: Peer Comparison & Soak Testing Roadmap

**Status:** Active plan
**Last updated:** 2026-04-15

---

## 1. Current State Assessment

### What Already Exists

| Asset | Purpose | Status |
|---|---|---|
| `scripts/soak_reliability.sh` | 5-min soak with RSS/drop/ratio gates | ✅ Production |
| `scripts/soak_monitor.sh` | Cron-based CSV metric collection | ✅ Working |
| `scripts/compare_runtime_security.sh` | Multi-agent comparison driver | ✅ Supports 6 agents |
| `scripts/perf_open_bench.sh` | open/read/close microbench with percentiles | ✅ JSON + text output |
| `.github/workflows/soak.yml` | Weekly 15-min CI soak + ASAN variant | ✅ Active |
| `docs/PERFORMANCE_COMPARISON.md` | Honest comparison doc (no fabricated numbers) | ✅ Published |
| `docs/SOAK_TESTING_GUIDE.md` | Manual soak testing runbook | ✅ Published |
| `docs/COMPETITIVE_BENCH_METHODOLOGY.md` | Comparison methodology doc | ✅ Published |

### What's Missing

1. **Falco and Tetragon not installed** — comparison script skips them
2. **No enforce-mode soak** — current soak only exercises audit mode
3. **No network-policy soak** — only file hooks are exercised
4. **No long-duration CI soak** — 15 min is too short for memory leak detection
5. **No multi-workload benchmark** — only `open_close` workload exists
6. **No automated comparison CI** — `compare_runtime_security.sh` is manual-only
7. **No Grafana/visualization pipeline** — soak CSV is not visualized

---

## 2. Peer Tool Installation

### 2.1 Falco (Modern eBPF, No Kernel Module)

Falco's modern eBPF probe is embedded in the binary — no driver download needed.
Requires kernel ≥5.8.

```bash
# Add Falco APT repo
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
  sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/falcosecurity.list

sudo apt-get update
sudo FALCO_FRONTEND=noninteractive apt-get install -y falco

# Verify modern-bpf service exists
systemctl list-unit-files "falco*"

# Enable modern eBPF (not kmod)
sudo systemctl enable --now falco-modern-bpf.service

# Verify
falco --version
falco --modern-bpf --dry-run    # quick startup check
```

**For benchmarking** — run with an empty rules file to measure baseline overhead:

```bash
echo "" > /tmp/falco-empty.yaml
sudo falco --modern-bpf -r /tmp/falco-empty.yaml -o log_level=error
```

The comparison script (`compare_runtime_security.sh`) already does this in `run_falco()`.

### 2.2 Tetragon (Standalone, No Cilium Required)

Tetragon works standalone — no Cilium dependency. Current stable: v1.6.0.

```bash
# Download and install
TETRAGON_VERSION="v1.6.0"
curl -LO "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-amd64.tar.gz"
tar -xvf "tetragon-${TETRAGON_VERSION}-amd64.tar.gz"
cd "tetragon-${TETRAGON_VERSION}-amd64/"
sudo ./install.sh

# Verify
tetragon version
sudo systemctl start tetragon
sudo systemctl status tetragon

# Install tetra CLI (for querying events)
curl -L "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetra-linux-amd64.tar.gz" | tar -xz
sudo mv tetra /usr/local/bin/
```

**For benchmarking** — run with no TracingPolicies to measure baseline overhead:

```bash
# Start with no policies, export disabled
sudo tetragon --export-file ""
```

The comparison script already handles this in `run_tetragon()`.

### 2.3 Optional: Tracee & KubeArmor

```bash
# Tracee (Aqua) — container image is easiest
docker run --name tracee -d --privileged \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /boot:/boot:ro \
  aquasec/tracee:latest

# KubeArmor — standalone host mode
curl -sfL https://raw.githubusercontent.com/kubearmor/kubearmor-client/main/install.sh | sudo sh -
```

---

## 3. Comparison Methodology

### 3.1 Metrics to Measure

| Metric | How | Why |
|---|---|---|
| **Syscall latency (µs/op)** | `perf_open_bench.sh` — p50/p95/p99 | Primary overhead indicator |
| **Delta vs bare baseline** | % change from no-agent run | Apples-to-apples overhead |
| **RSS at idle** | `/proc/$PID/status` VmRSS | Memory footprint |
| **RSS under load** | Same, during sustained workload | Memory scaling behavior |
| **CPU at idle** | `ps -p $PID -o %cpu=` | Background cost |
| **CPU under load** | Same, during sustained workload | Processing overhead |
| **Startup time** | `time $agent run` until ready | Deployment impact |
| **Event throughput** | Events/sec at saturation | Ring buffer capacity |
| **Ring buffer drops** | Agent-specific drop counters | Reliability under load |
| **Policy reload time** | Time to apply a 100-rule policy | Operational agility |

### 3.2 Workloads

Current: `open_close` (file open/read/close loop).

**Proposed additions:**

| Workload | What It Tests | Implementation |
|---|---|---|
| `open_close` | File hook overhead | ✅ Exists |
| `connect_close` | Network hook overhead | `socket()` → `connect()` → `close()` loop |
| `exec_loop` | Exec identity / bprm_check overhead | `fork()` + `execve("/bin/true")` loop |
| `mixed_io` | Realistic file + network combined | Interleaved file opens + TCP connects |
| `stress_ng` | Whole-system stress | `stress-ng --cpu 4 --io 4 --vm 2 --timeout 60s` |

### 3.3 Test Matrix

| Dimension | Values |
|---|---|
| **Agents** | none, aegisbpf, falco, tetragon, (tracee, kubearmor optional) |
| **Workloads** | open_close, connect_close, exec_loop |
| **Policy size** | empty, 10 rules, 100 rules, 1000 rules |
| **Iterations** | 200,000 per measurement (3 repeats, 1 burn-in) |
| **Duration per agent** | ~5 min per workload × policy combination |
| **Total estimated time** | ~2 hours for full matrix (3 agents × 3 workloads × 3 policy sizes) |

### 3.4 Statistical Rigor

- **Minimum 3 repeats** per measurement point (already in `perf_open_bench.sh`)
- **1 burn-in run** discarded (already implemented)
- **Report median**, not mean (already implemented)
- **Report p50/p95/p99** (already implemented)
- **CPU pinning** to reduce scheduler noise (already in `perf_open_bench.sh`)
- **Cooldown period** between agents (already in `compare_runtime_security.sh`)
- **Conflicting agent check** before starting (already implemented)
- **Add:** Confidence intervals (±) for repeated runs
- **Add:** Environment fingerprint (kernel, CPU, governor, turbo boost state)

### 3.5 Fair Comparison Rules

1. All agents run on the **same host, same kernel, same boot**
2. Each agent runs with the **most benign possible configuration** (audit/detect only, empty rules)
3. Only **one agent active** at a time — conflicting agents killed before each run
4. **CPU frequency governor** locked to `performance` during benchmarks
5. Results are **only valid within a single run** — never copy across hosts or dates
6. All numbers published must be **reproducible** via `scripts/compare_runtime_security.sh`

---

## 4. Soak Testing Roadmap

### Phase 1: Extend Current Soak (Week 1)

**Goal:** Fill gaps in the existing soak infrastructure.

#### 1a. Add enforce-mode soak variant

Currently `soak_reliability.sh` only runs `--audit`. Add an enforce-mode soak that:
- Adds a temporary deny rule, runs enforce mode, verifies blocks happen
- Gates on: same RSS/drop/ratio criteria + zero daemon crashes

#### 1b. Add network workload to soak

Current soak only exercises file hooks via `cat /etc/hosts`. Add:
- TCP connect loop to localhost (exercises `socket_connect` hook)
- UDP sendmsg to localhost (exercises `socket_sendmsg` hook)

#### 1c. Extend CI soak duration

The 15-minute weekly soak is too short for leak detection. Propose:
- **Weekly:** 1-hour soak (current 15 min → 60 min)
- **Release gate:** 4-hour soak before tagging a release
- Keep the existing 5-minute ASAN soak as-is (ASAN overhead makes long runs impractical)

### Phase 2: Install Peer Tools & Run Comparison (Week 2)

**Goal:** Produce the first real head-to-head numbers.

1. Install Falco (modern eBPF) and Tetragon (standalone) per Section 2
2. Run `compare_runtime_security.sh --agents none,aegisbpf,falco,tetragon`
3. Save results to `evidence/comparison/` with environment fingerprint
4. Update `docs/PERFORMANCE_COMPARISON.md` with measured numbers
5. **Do not fabricate or extrapolate** — only publish what was measured

### Phase 3: Multi-Workload Benchmarks (Week 3)

**Goal:** Expand beyond `open_close` to cover network and exec paths.

1. Implement `connect_close` workload in `perf_open_bench.sh` (or new script)
2. Implement `exec_loop` workload
3. Run full comparison matrix
4. Document results per workload

### Phase 4: Long-Duration Soak Comparison (Week 4+)

**Goal:** Prove stability advantage over time.

Run each agent for 24 hours under sustained workload:
- `stress-ng --cpu 4 --io 4 --vm 2` as background load
- Collect RSS every 60 seconds via `soak_monitor.sh`
- Plot memory curves for each agent
- Gate: zero crashes, RSS growth < 128 MB over 24 hours

### Phase 5: Automated Comparison CI (Future)

**Goal:** Catch performance regressions against peer tools automatically.

- Self-hosted runner with all agents pre-installed
- Weekly job runs `compare_runtime_security.sh`
- Results committed to `evidence/weekly-comparison/`
- Alert if AegisBPF overhead exceeds 2× Tetragon overhead (regression signal)

---

## 5. Implementation Priority

| # | Task | Effort | Impact | Depends On |
|---|---|---|---|---|
| 1 | Install Falco + Tetragon | 30 min | High | Nothing |
| 2 | Run first comparison | 15 min | **Critical** | #1 |
| 3 | Publish results to docs | 30 min | High | #2 |
| 4 | Add `connect_close` workload | 2 hrs | Medium | Nothing |
| 5 | Add enforce-mode soak | 2 hrs | Medium | Nothing |
| 6 | Extend CI soak to 1 hour | 15 min | Medium | Nothing |
| 7 | Add network workload to soak | 1 hr | Medium | Nothing |
| 8 | Add `exec_loop` workload | 2 hrs | Medium | Nothing |
| 9 | Run 24-hour soak comparison | 24 hrs (wall) | High | #1 |
| 10 | Automated comparison CI | 4 hrs | Medium | #1, runner setup |

---

## 6. Expected Architectural Advantages

Based on design analysis (these are predictions, not measurements):

| Metric | AegisBPF Expected Edge | Reasoning |
|---|---|---|
| **File open latency** | Competitive or better | O(1) hash-map lookup vs rule-engine walk |
| **Memory footprint** | Significantly lower | C++20 static binary, no Go GC heap |
| **GC pause impact** | Zero | No garbage collector (Tetragon/Tracee/KubeArmor are Go) |
| **Policy reload** | Fast (shadow-map swap) | Atomic map swap vs CRD reconciliation |
| **Enforcement latency** | Equal or better | In-kernel LSM decision, no userspace round-trip |
| **Startup time** | Faster | Single binary, no runtime reflection |
| **Event throughput** | Comparable | All tools use ring buffers; sizing matters more than language |

**Important:** These are hypotheses to be validated, not claims to publish.

---

## 7. Risk Assessment

| Risk | Mitigation |
|---|---|
| AegisBPF performs worse than expected | Document honestly; focus on unique capabilities (copy-up, IMA, break-glass) |
| Falco's modern eBPF conflicts with AegisBPF's LSM hooks | Run agents sequentially, never simultaneously |
| Tetragon's BPF programs conflict with kernel BPF state | Full agent stop + 5s cooldown between runs (already implemented) |
| Benchmark results vary across runs | Pin CPUs, lock governor, report median of 3 repeats |
| Self-hosted runner environment changes between weekly runs | Log full environment fingerprint; discard cross-boot comparisons |

---

## 8. References

- [Falco Performance Testing](https://falco.org/blog/falco-performance-testing/)
- [Falco Modern BPF](https://falco.org/blog/falco-modern-bpf/)
- [Falco Install Packages](https://falco.org/docs/setup/packages/)
- [Tetragon Standalone Installation](https://tetragon.io/docs/installation/package/)
- [Tetragon without Cilium](https://isovalent.com/blog/post/can-i-use-tetragon-without-cilium-yes/)
- [Tetragon GitHub Releases](https://github.com/cilium/tetragon/releases)
- [Comparative Analysis of eBPF-Based Runtime Security (2025 paper)](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- [Datadog: Hardening eBPF for Workload Protection](https://www.datadoghq.com/blog/engineering/ebpf-workload-protection-lessons/)
- [Falco vs Tetragon Showdown](https://medium.com/@mughal.asim/falco-vs-tetragon-a-runtime-security-showdown-for-kubernetes-a0e9fb9f30a0)
