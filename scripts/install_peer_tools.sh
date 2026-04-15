#!/usr/bin/env bash
# install_peer_tools.sh — Install Falco and/or Tetragon for head-to-head comparison.
#
# This script installs peer eBPF security tools so that
# scripts/compare_runtime_security.sh can exercise them alongside AegisBPF.
#
# Usage:
#   sudo scripts/install_peer_tools.sh [falco|tetragon|all]
#
# The script is idempotent: re-running it skips already-installed tools.

set -euo pipefail

TETRAGON_VERSION="${TETRAGON_VERSION:-v1.6.0}"

log()  { echo "[install] $*"; }
warn() { echo "[install] WARN: $*" >&2; }
err()  { echo "[install] ERROR: $*" >&2; }

if [[ "${EUID}" -ne 0 ]]; then
    err "must run as root"
    exit 1
fi

install_falco() {
    if command -v falco >/dev/null 2>&1; then
        log "falco already installed: $(falco --version 2>/dev/null | head -1)"
        return 0
    fi

    log "installing Falco (modern eBPF mode)..."

    # Add Falco GPG key
    if [[ ! -f /usr/share/keyrings/falco-archive-keyring.gpg ]]; then
        curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
            gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    fi

    # Add Falco APT repo
    cat > /etc/apt/sources.list.d/falcosecurity.list <<EOF
deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main
EOF

    apt-get update -qq
    FALCO_FRONTEND=noninteractive apt-get install -y falco

    # Enable modern eBPF (not kmod)
    systemctl disable falco-kmod.service 2>/dev/null || true
    systemctl disable falco-bpf.service 2>/dev/null || true
    # Don't auto-start — comparison script manages lifecycle
    systemctl disable falco-modern-bpf.service 2>/dev/null || true
    systemctl stop falco-modern-bpf.service 2>/dev/null || true
    systemctl stop falco-kmod.service 2>/dev/null || true
    systemctl stop falco-bpf.service 2>/dev/null || true

    log "falco installed: $(falco --version 2>/dev/null | head -1)"
    log "  NOTE: services disabled — comparison script starts/stops Falco on demand"
}

install_tetragon() {
    if command -v tetragon >/dev/null 2>&1; then
        log "tetragon already installed: $(tetragon version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    log "installing Tetragon ${TETRAGON_VERSION} (standalone, no Cilium)..."

    local tmpdir
    tmpdir="$(mktemp -d)"
    local tarball="tetragon-${TETRAGON_VERSION}-amd64.tar.gz"

    curl -fsSL -o "${tmpdir}/${tarball}" \
        "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/${tarball}"

    tar -xf "${tmpdir}/${tarball}" -C "${tmpdir}"

    local extract_dir="${tmpdir}/tetragon-${TETRAGON_VERSION}-amd64"
    if [[ -d "${extract_dir}" ]]; then
        cd "${extract_dir}"
        ./install.sh
    else
        # Fallback: find install.sh in extracted content
        local install_sh
        install_sh="$(find "${tmpdir}" -name install.sh -maxdepth 2 | head -1)"
        if [[ -n "${install_sh}" ]]; then
            cd "$(dirname "${install_sh}")"
            ./install.sh
        else
            err "could not find install.sh in ${tarball}"
            rm -rf "${tmpdir}"
            return 1
        fi
    fi

    # Don't auto-start — comparison script manages lifecycle
    systemctl disable tetragon.service 2>/dev/null || true
    systemctl stop tetragon.service 2>/dev/null || true

    # Install tetra CLI
    curl -fsSL "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetra-linux-amd64.tar.gz" | \
        tar -xz -C /usr/local/bin/ tetra 2>/dev/null || true

    rm -rf "${tmpdir}"
    log "tetragon installed: $(tetragon version 2>/dev/null || echo '${TETRAGON_VERSION}')"
    log "  NOTE: service disabled — comparison script starts/stops Tetragon on demand"
}

usage() {
    cat <<EOF
Usage: $0 [falco|tetragon|all]

Install peer eBPF security tools for head-to-head comparison.

Options:
  falco      Install Falco with modern eBPF driver
  tetragon   Install Tetragon standalone (no Cilium)
  all        Install both (default)

Environment:
  TETRAGON_VERSION   Tetragon release tag (default: ${TETRAGON_VERSION})
EOF
}

TARGET="${1:-all}"

case "${TARGET}" in
    falco)
        install_falco
        ;;
    tetragon)
        install_tetragon
        ;;
    all)
        install_falco
        install_tetragon
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    *)
        err "unknown target: ${TARGET}"
        usage >&2
        exit 1
        ;;
esac

log "done. Run the comparison with:"
log "  sudo scripts/compare_runtime_security.sh --agents none,aegisbpf,falco,tetragon --out results/"
