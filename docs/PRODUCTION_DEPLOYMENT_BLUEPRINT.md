# Production Deployment Blueprint

This blueprint provides a practical, conservative path to deploy AegisBPF in
production environments. It prioritizes safe rollout, explicit prerequisites,
and verifiable observability.

## 1) Preflight (must pass before rollout)

- Run diagnostics:
  - `aegisbpf health`
  - `aegisbpf doctor`
- Verify environment:
  - `scripts/verify_env.sh --strict`
- Confirm kernel prerequisites (BPF LSM, BTF, cgroup v2) per `docs/COMPATIBILITY.md`.

## 2) Systemd deployment (recommended baseline)

### Install artifacts
- Binary: `/usr/sbin/aegisbpf`
- BPF object: `/usr/lib/aegisbpf/aegis.bpf.o`
- Policy and keys:
  - `/etc/aegisbpf/policy.conf`
  - `/etc/aegisbpf/keys/` (trusted public keys)

### Service configuration
- Use `packaging/systemd/aegisbpf.service` and `packaging/systemd/aegisbpf.env`.
- Start in audit mode first, then move to enforce:
  - Audit: `--audit`
  - Enforce: `--enforce --lsm-hook=inode` (file enforce baseline)

### Capability bounds
- Minimal capabilities are documented in `SECURITY.md`.
- Remove unused caps if you do not enable network enforcement.

### Rollout sequence
1. Audit-only (observe logs, verify drops, confirm event schema).
2. Canary cgroups only (allowlist controlled workloads first).
3. Expand allowlist-based rollout to full fleet.

Dry-run traces:
- Run audit-only with JSON logs: `aegisbpf run --audit --log-format=json`.
- Use `aegisbpf explain` on captured events for best-effort decision traces.

Example decision trace:
```text
$ aegisbpf explain --event /var/log/aegisbpf/event.json --policy /etc/aegisbpf/policy.conf
decision=deny
reason=matched deny_inode rule
rule_id=deny_inode:/usr/bin/oldtool (dev=259, inode=123456)
mode=enforce
```

### Rollback
- `aegisbpf policy rollback` is the primary rollback lever.
- Emergency kill switch (preferred, immediate, auditable):
  - `aegisbpf emergency-disable --reason "TICKET=INC-1234 <short reason>"`
- Break-glass marker file (fallback if CLI path is unavailable):
  - create `/etc/aegisbpf/break_glass` to force audit-only.

## 2a) Configuration source precedence

AegisBPF reads configuration from several sources. When the same knob is set
in more than one place, the effective value is chosen in this order (highest
to lowest precedence):

1. **CLI flags** on `aegisbpf run` — authoritative for the running daemon
   (e.g. `--enforce`, `--log-format=json`, `--enforce-gate-mode=fail-closed`).
2. **Environment variables** (`AEGIS_*`) consumed at start-up. These exist for
   packaging and override use cases; they can be set via
   `packaging/systemd/aegisbpf.env` or a Helm values override. Notable vars:
   - `AEGIS_BPF_OBJ`, `AEGIS_SKIP_BPF_VERIFY`, `AEGIS_REQUIRE_BPF_HASH`
   - `AEGIS_ALLOW_UNSIGNED_BPF`
   - `AEGIS_POLICY_APPLIED_PATH`, `AEGIS_POLICY_APPLIED_HASH_PATH`
   - `AEGIS_POLICY_SHA256`, `AEGIS_POLICY_SHA256_FILE`
   - `AEGIS_ENFORCE_GATE_MODE`
   - `AEGIS_KEYS_DIR`, `AEGIS_VERSION_COUNTER_PATH`
   - `AEGIS_CONTROL_STATE_PATH`, `AEGIS_CONTROL_LOG_PATH`,
     `AEGIS_CONTROL_LOCK_PATH`, `AEGIS_NODE_NAME`
   - `AEGIS_CAPABILITIES_REPORT_PATH`
   - `AEGIS_OTEL_SPANS`
3. **Control-plane state files** — persistent operator intent that outlives a
   restart. Written by the CLI (`emergency-disable`, `policy apply`, etc.):
   - `/var/lib/aegisbpf/control_state.json` (emergency state, break-glass)
   - `/var/lib/aegisbpf/policy.applied` (+ `.sha256`, `.prev`)
   - `/var/lib/aegisbpf/version_counter`
4. **Break-glass marker files** — fail-safe fallback when the CLI is
   unavailable (e.g. operator SSH only). Presence forces audit-only:
   - `/etc/aegisbpf/break_glass`
   - `/var/lib/aegisbpf/break_glass`
   - `/etc/aegisbpf/break_glass.token` (optional auth token)
5. **Policy file content** (`/etc/aegisbpf/policy.conf` or
   `--policy <file>`) — all in-policy `deny_*`, `protect_*`, and `allow_*`
   rules. Content precedence between rules is described in
   `docs/POLICY_SEMANTICS.md`.
6. **Kernel feature detection** — runtime capability probe
   (`aegisbpf doctor`, `capabilities.json`) can silently downgrade hooks if
   `--enforce-gate-mode=audit-fallback`; set `fail-closed` to prevent this.
7. **Compile-time defaults** — baked into the binary (see
   `src/types.hpp` for `kEnforceSignal*`, `kSigkillEscalation*Default`,
   `AEGIS_VERSION_STRING`, etc.). These are the final fallback.

This ordering is security-sensitive: **break-glass and emergency-disable
can only relax enforcement, never tighten it.** If you change any of these
knobs out-of-band, re-run `aegisbpf health --require-enforce` to confirm
the effective posture before declaring the node ready.

## 3) Kubernetes deployment guidance (reference)

If deploying in Kubernetes, use a DaemonSet with host mounts for bpffs and
cgroup v2, and explicitly scoped capabilities. Ensure all required kernel
features are enabled on the host.

This repository includes a reference Helm chart at `helm/aegisbpf/`.

Recommended guidance:
- Verify kernel features on nodes with `aegisbpf doctor` and/or the daemon
  capability report (`/var/lib/aegisbpf/capabilities.json`).
- Mount:
  - `/sys/fs/bpf` (bpffs pins)
  - `/sys/fs/cgroup` (cgroup v2)
  - `/var/lib/aegisbpf` (policy snapshots, capability report, emergency control audit trail)
- Provide only the capabilities listed in `SECURITY.md` (drop network caps if
  network enforcement is not used).
- Start in audit-only mode and promote to enforce in stages.

Node capability fragmentation handling:
- Default recommendation: deploy `deployment.mode=both` and schedule enforce
  pods only on labeled nodes (`enforceNodeSelector`).
- For strict fleets, use `agent.enforceGateMode=fail-closed` to prevent silent
  enforcement downgrades.
- Enforce pods should use readiness fail-closed:
  - `aegisbpf health --require-enforce`
  - Helm default: `agent.requireEnforceReadiness=true` (enforce mode only).
- Generate machine-readable posture + recommended node labels from each node's
  capability report:

```bash
python3 scripts/evaluate_capability_posture.py \
  --input /var/lib/aegisbpf/capabilities.json \
  --strict \
  --out-json /var/lib/aegisbpf/capabilities.posture.json \
  --out-labels-json /var/lib/aegisbpf/capabilities.labels.json
```

- Use `aegisbpf.io/enforce-capable=true` for enforce DaemonSet placement.

Optional posture-label automation (Helm):
- Enable `postureAutomation.enabled=true` to run a node-local sidecar that:
  - reads `/var/lib/aegisbpf/capabilities.json`
  - writes `/var/lib/aegisbpf/capabilities.posture.json`
  - patches node labels (`aegisbpf.io/*`) for scheduler targeting
- This requires cluster-scoped RBAC (`nodes.get/patch`), installed by chart
  when `serviceAccount.create=true`.

Minimal RBAC for emergency control:
- See `docs/KUBERNETES_RBAC.md`.

## 4) Observability integration

- Metrics: run `aegisbpf metrics --out /var/lib/node_exporter/textfile_collector/aegisbpf.prom`
  on a timer if using Prometheus textfile collection.
- Logs: use `--log-format=json` for structured pipelines.
- Event schema validation: `scripts/validate_event_schema.py`.

## 5) Air-gapped or restricted environments

- Use signed policy bundles and verify hashes.
- Keep SBOM and release signatures alongside artifacts.
- Validate integrity with `aegisbpf policy apply --sha256 <hash>` or
  signed policy bundles.

## 6) Operational guardrails

- Keep SIGKILL enforcement disabled unless explicitly required and approved.
- Use audit-only or canary rollout for new policy changes.
- Track drop ratios and attach health during rollout.

## Evidence

- Systemd unit: `packaging/systemd/aegisbpf.service`
- Capability bounds: `SECURITY.md`
- Operational runbooks: `docs/runbooks/`
- Diagnostics: `aegisbpf doctor` and `docs/TROUBLESHOOTING.md`
