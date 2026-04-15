# Runtime-security comparison results

- host: `ern42-RLEFG-XX-6.17.0-19-generic`
- timestamp: 2026-04-15T09:40:16Z
- workload: connect_close
- iterations: 200000

| agent | status | us/op | p50 (µs) | p95 (µs) | p99 (µs) | delta vs none | notes |
|---|---|---|---|---|---|---|---|
| none | ok | 3.62 | 2.66 | 5.5 | 7.38 | — |  |
| aegisbpf | ok | 3.87 | 2.67 | 5.34 | 8.18 | +6.91% |  |
| falco | ok | 4.44 | 3.47 | 6.13 | 8.56 | +22.65% |  |
| tetragon | ok | 3.74 | 2.89 | 5.46 | 7.18 | +3.31% |  |

> Numbers are only meaningful when all agents were measured on the same host
> in the same run of this script. Do not copy rows across runs.
