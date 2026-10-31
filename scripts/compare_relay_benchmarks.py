#!/usr/bin/env python3
"""Gate paired trials, reporting actual measurements and relative medians."""
import argparse
import json
from pathlib import Path
import statistics


def compare(root):
    trials = [json.loads(path.read_text()) for path in sorted(root.glob("**/comparison.json"))]
    if len(trials) != 3:
        raise ValueError(f"expected three paired trials, found {len(trials)}")
    throughput = []
    latency = []
    lines = ["# DERP performance comparison", "", "Same-host paired trials; server: 2 CPUs / 2 GiB; clients use separate CPUs.", "", "| Trial | Baseline Mbps | Candidate Mbps | Baseline P99 µs | Candidate P99 µs |", "|---|---:|---:|---:|---:|"]
    for i, trial in enumerate(trials, 1):
        before, after = trial["baseline"], trial["candidate"]
        if min(before["mbps"], after["mbps"], before["p99_us"], after["p99_us"]) <= 0:
            raise ValueError("missing traffic measurements")
        throughput.append(after["mbps"] / before["mbps"])
        latency.append(after["p99_us"] / before["p99_us"])
        lines.append(f'| {i} | {before["mbps"]:.2f} | {after["mbps"]:.2f} | {before["p99_us"]} | {after["p99_us"]} |')
    completion = list(root.glob("**/resilience.json"))
    required = {"idle", "slow", "reconnect", "admission", "memory", "profiles"}
    faults_passed = len(completion) == 1
    if faults_passed:
        evidence = json.loads(completion[0].read_text())
        faults_passed = evidence.get("passed") is True and set(evidence.get("scenarios", [])) == required
    rate, p99 = statistics.median(throughput), statistics.median(latency)
    passed = rate >= .95 and p99 <= 1.10 and faults_passed
    lines += ["", f"Median paired throughput ratio: {rate:.4f}; P99 ratio: {p99:.4f}.", "", "PASS" if passed else "FAIL: an acceptance check failed; inspect workload completion, profiles and paired ratios before delivery."]
    if not faults_passed:
        lines += ["", "Failure scenarios, memory budgets or profiling did not complete; delivery is blocked."]
    (root / "REPORT.md").write_text("\n".join(lines) + "\n")
    return passed


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    raise SystemExit(0 if compare(args.directory) else 1)
