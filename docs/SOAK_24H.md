# AegisBPF 24-Hour AWS Soak Results (2026-04-17)

Status: **passed** (exit code `0`, `pass=true`)
Run ID: `soak-20260417T150053Z`
Raw artifacts: [`evidence/soak-24h/`](../evidence/soak-24h/)

This is the first full 24-hour soak of AegisBPF run on a clean AWS EC2
instance, launched automatically by
[`scripts/aws_soak_24h.sh`](../scripts/aws_soak_24h.sh). The instance
self-terminated and uploaded results to S3 after the run completed.

## Headline numbers

| Metric | Value | Threshold | Result |
|---|---|---|---|
| Exit code | `0` | `0` | pass |
| Duration | 86,400 s (24 h) | 86,400 s | pass |
| RSS growth | **88 kB** | ≤ 131,072 kB | pass (0.067% of budget) |
| Ring-buffer drops (total) | **0** | ≤ 2,000 | pass |
| Ring-buffer drops (file) | **0** | — | pass |
| Ring-buffer drops (net) | **0** | — | pass |
| Drop ratio | **0.000%** | ≤ 0.1% | pass |
| Total decision events | **3,364,250** | ≥ 100 | pass (~39 events/s) |
| Workers | 4 file + UDP | — | pass |

Source: [`evidence/soak-24h/soak_summary.json`](../evidence/soak-24h/soak_summary.json)

## Environment

| Field | Value |
|---|---|
| Cloud | AWS EC2 (free tier) |
| Instance type | `t2.micro` (1 vCPU, 1 GB RAM) |
| Region | `us-east-1` |
| CPU | Intel Xeon E5-2686 v4 @ 2.30 GHz |
| OS | Ubuntu 24.04 LTS (Noble) |
| Kernel | `6.17.0-1010-aws` |
| LSMs active | `lockdown,capability,landlock,yama,apparmor,bpf,ima,evm` |
| Mode | audit |
| Branch | `main` @ `6ca1aa4` |

Captured environment is in
[`evidence/soak-24h/kernel.txt`](../evidence/soak-24h/kernel.txt),
[`evidence/soak-24h/lsm.txt`](../evidence/soak-24h/lsm.txt),
[`evidence/soak-24h/cpu.txt`](../evidence/soak-24h/cpu.txt),
[`evidence/soak-24h/memory.txt`](../evidence/soak-24h/memory.txt).

## Workload

Driven by [`scripts/soak_reliability.sh`](../scripts/soak_reliability.sh):

- **File workers** — 4 workers continuously touching a temporary deny-listed
  file to exercise `file_open` / `inode_permission` on every open.
- **Network workers** (enabled via `SOAK_NET_WORKLOAD=1`) — UDP connect
  workers driving `socket_connect` / `socket_sendmsg` LSM hooks against
  `127.0.0.1:9`.
- **Poll** — 5 s RSS / ring-buffer / event-counter sampling.

## Observations

- **Memory stability** — RSS moved from 50,616 kB at start to a peak of
  50,704 kB over the full 24 hours. An 88 kB delta in 24 hours on a
  single-vCPU VM with continuous file + network workload shows no
  resident-set growth attributable to AegisBPF.
- **Zero drops** — 3.36 M decision events processed with zero ring-buffer
  drops in either the file or network ring, consistent with the 16 MB
  ring sizing used in this run.
- **Baseline CPU idle** — the daemon stayed at ~0.5% CPU for the bulk of
  the run (sampled during monitoring), which matches the expectation that
  policy evaluation is dominated by kernel-side hash lookups.

## Reproducing

```bash
# From an AWS-configured shell with EC2 + S3 permissions
./scripts/aws_soak_24h.sh \
    --instance-type t2.micro \
    --branch main
```

The script:

1. Creates (or reuses) an IAM role, instance profile, security group, and
   SSH key pair.
2. Launches Ubuntu 24.04 with cloud-init that enables BPF LSM in GRUB,
   reboots, builds AegisBPF from the requested branch, and runs
   `soak_reliability.sh` for 24 hours.
3. Uploads `/opt/aegisbpf/artifacts/soak-24h/` to
   `s3://aegisbpf-soak-results/soak-<timestamp>/`.
4. Calls `ec2:TerminateInstances` on itself.

Artifacts retrieved via:

```bash
aws s3 cp --recursive \
    s3://aegisbpf-soak-results/soak-20260417T150053Z/ \
    ./evidence/soak-24h/
```

## Limitations / next steps

- **Audit mode only** — this run was `SOAK_MODE=audit`. A follow-up
  24-hour enforce-mode soak is planned to validate block-path stability.
- **Single vCPU** — `t2.micro` is 1 vCPU, so lock / contention behavior
  under multi-core pressure is not exercised here. A future `c7i.large`
  or `c7i.xlarge` soak will add that dimension.
- **Synthetic workload** — the file / UDP workers in
  `soak_reliability.sh` are synthetic. Realistic traffic patterns will be
  layered in via the workload replay work tracked in
  [`docs/REAL_WORKLOAD_TESTING.md`](REAL_WORKLOAD_TESTING.md).
