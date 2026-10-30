#!/usr/bin/env python3
"""Run isolated, resource-limited DERP comparisons on a disposable CI host."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time
import urllib.request

CONTROL = "http://127.0.0.1:19090"


def run(*command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def get(path, timeout=5):
    with urllib.request.urlopen(CONTROL + path, timeout=timeout) as response:
        return response.read()


def ready(process):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("fixture exited before readiness")
        try:
            if json.loads(get("/metrics"))["status"]["ready"]:
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    raise RuntimeError("fixture did not become ready")


def measure(binary, label, scenario, args, *, budget="off", profiles=False):
    output = args.output / label
    output.mkdir(parents=True, exist_ok=True)
    log = (output / "server.log").open("w")
    env = dict(os.environ, DERPER_GO_LOAD_TEST="1", GOMAXPROCS="2", GOMEMLIMIT=budget)
    process = None
    container = "derper-go-load"
    try:
        if args.smoke:
            process = subprocess.Popen([str(binary), "-mode", "server"], env=env, stdout=log, stderr=log)
        else:
            with tempfile.TemporaryDirectory() as directory:
                build = Path(directory)
                shutil.copy2(binary, build / "relayload")
                (build / "Dockerfile").write_text('FROM scratch\nCOPY relayload /relayload\nENTRYPOINT ["/relayload"]\n')
                run("docker", "build", "-q", "-t", "derper-go-load", directory, stdout=log, stderr=log)
            run("docker", "run", "-d", "--name", container, "--network", "host", "--cpus", "2", "--cpuset-cpus", "0,1",
                "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "16384", "--ulimit", "nofile=65536:65536", "--tmpfs", "/tmp:mode=1777",
                "-e", "DERPER_GO_LOAD_TEST=1", "-e", "GOMAXPROCS=2", "-e", f"GOMEMLIMIT={budget}",
                "derper-go-load", "-mode", "server", f"-profiles={str(profiles).lower()}", stdout=log, stderr=log)
        ready(process)
        seconds = args.duration if scenario == "forward" else min(args.duration, 20)
        command = [str(args.candidate), "-mode", "client", "-scenario", scenario, "-connections", str(args.connections), "-duration", f"{seconds}s"]
        if not args.smoke:
            command = ["taskset", "-c", "2,3", *command]
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            profile = None
            if profiles:
                def collect_profile():
                    time.sleep(5)
                    (output / "cpu.pprof").write_bytes(get("/debug/pprof/profile?seconds=15", timeout=30))
                profile = pool.submit(collect_profile)
            with (output / "result.json").open("w") as stdout, (output / "client.log").open("w") as stderr:
                run(*command, env=env, stdout=stdout, stderr=stderr, timeout=seconds + 190)
            if profile is not None:
                profile.result()
                for name in ("heap", "allocs", "mutex", "block", "goroutine"):
                    (output / f"{name}.pprof").write_bytes(get(f"/debug/pprof/{name}"))
        result = json.loads((output / "result.json").read_text())
        if result["seconds"] < seconds * 0.95:
            raise RuntimeError("measurement ended before the requested duration")
        if scenario == "admission" and label.startswith("candidate") and result["after"]["peak_mock_checks"] > 32:
            raise RuntimeError("admission exceeded the default 32 concurrent checks")
        return result
    finally:
        if args.smoke:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        else:
            subprocess.run(["docker", "logs", container], stdout=log, stderr=log, check=False)
            subprocess.run(["docker", "rm", "-f", container], stdout=log, stderr=log, check=False)
        log.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=600)
    parser.add_argument("--connections", type=int, default=1000)
    parser.add_argument("--trial", type=int, default=1)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("run this fixture only on a disposable GitHub Actions host")
    if not 1 <= args.duration <= 1800 or not 2 <= args.connections <= 1000 or args.connections % 2:
        parser.error("invalid workload bounds")
    args.candidate = args.candidate.resolve()
    if args.baseline:
        args.baseline = args.baseline.resolve()
    if not args.smoke and len(os.sched_getaffinity(0)) < 4:
        parser.error("comparison requires four CPUs to isolate server and clients")
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "environment.json").write_text(json.dumps({"platform": platform.platform(), "cpu": Path("/proc/cpuinfo").read_text(), "connections": args.connections, "seconds": args.duration, "server_cpus": 2, "server_memory_bytes": None if args.smoke else 2 << 30, "trial": args.trial}, indent=2))
    if args.smoke:
        measure(args.candidate, "smoke", "forward", args)
        return
    if not args.baseline:
        parser.error("full comparison requires --baseline")
    # Alternate order between trials to reduce warm-host bias.
    versions = [("baseline", args.baseline), ("candidate", args.candidate)]
    if args.trial % 2 == 0:
        versions.reverse()
    results = {}
    for label, binary in versions:
        print(f"{label}: {args.connections} nodes, {args.duration}s", flush=True)
        results[label] = measure(binary, label + "-forward", "forward", args)
    (args.output / "comparison.json").write_text(json.dumps(results, indent=2))
    if args.trial == 1:
        for scenario in ("idle", "slow", "reconnect", "admission"):
            for label, binary in versions:
                print(f"{label}: {scenario}", flush=True)
                measure(binary, label + "-" + scenario, scenario, args)
        original = args.duration
        args.duration = 30
        for budget in ("96MiB", "256MiB"):
            measure(args.candidate, "candidate-memory-" + budget, "forward", args, budget=budget)
        measure(args.candidate, "candidate-profiles", "forward", args, profiles=True)
        args.duration = original


if __name__ == "__main__":
    main()
