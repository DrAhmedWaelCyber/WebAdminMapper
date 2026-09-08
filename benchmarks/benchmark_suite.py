"""
WebAdminMapper - Performance Benchmarking Suite
===============================================
Measures and documents real, reproducible throughput, thread concurrency
scaling, error rates, and response latencies against a controlled local server.

Developer & Author: Ahmed Wael
Email: ahmedwael6143@gmail.com
Copyright (c) 2026, Ahmed Wael. All rights reserved.
"""

import argparse
import http.server
import json
import os
import platform
import socket
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

# Ensure parent directory is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from web_mapper.config import ScanConfig
from web_mapper.engine import ExecutionEngine
from web_mapper.requester import HTTPRequester, ScanResult

__author__ = "Ahmed Wael"
__version__ = "1.1.0"


class BenchmarkServerHandler(http.server.BaseHTTPRequestHandler):
    """Ultra-fast, lightweight HTTP handler for benchmark measurements."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        body = b'{"status":"ok","message":"benchmark endpoint active"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Threaded HTTP server to handle high-concurrency benchmark load."""
    daemon_threads = True
    allow_reuse_address = True


def get_system_specifications() -> Dict[str, Any]:
    """Capture hardware and runtime specifications for reproducible benchmarking."""
    return {
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "processor": platform.processor() or "N/A",
        "cpu_cores": os.cpu_count() or 1,
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
    }


def run_benchmark_trial(
    base_url: str,
    threads: int,
    request_count: int,
) -> Dict[str, Any]:
    """Execute a single benchmark trial at a specific thread concurrency level."""
    # Build list of paths to test
    paths = [f"/bench_endpoint_{i:04d}" for i in range(request_count)]

    cfg = ScanConfig(
        target_url=base_url,
        threads=threads,
        timeout=5.0,
        delay=0.0,
        retries=0,
        wildcard_detection=False,
        security_audit=False,
        cert_inspect=False,
        network_diag=False,
        validate_vulns=False,
        compliance_check=False,
        show_tree=False,
        quiet=True,
    )

    requester = HTTPRequester(cfg)
    engine = ExecutionEngine(cfg, requester)

    # Patch generator to supply exactly the benchmark paths
    engine.generator.get_all_paths = lambda base_prefix="": paths

    latencies: List[float] = []
    def on_result(res: ScanResult):
        latencies.append(res.response_time_ms)

    start_time = time.perf_counter()
    results = engine.run(on_result=on_result)
    elapsed = max(0.001, time.perf_counter() - start_time)

    total_reqs = engine.total_requests
    success_count = len(results)
    total_errors = sum(engine.error_stats.values())
    error_rate = (total_errors / max(1, total_reqs)) * 100.0
    throughput = total_reqs / elapsed

    sorted_lat = sorted(latencies) if latencies else [0.0]
    n = len(sorted_lat)

    return {
        "threads": threads,
        "total_requests": total_reqs,
        "successful_responses": success_count,
        "error_count": total_errors,
        "error_rate_pct": round(error_rate, 2),
        "execution_time_sec": round(elapsed, 3),
        "throughput_req_sec": round(throughput, 1),
        "latency_stats_ms": {
            "min": round(sorted_lat[0], 2),
            "max": round(sorted_lat[-1], 2),
            "mean": round(sum(sorted_lat) / n, 2),
            "p50": round(sorted_lat[int(n * 0.50)], 2),
            "p90": round(sorted_lat[min(n - 1, int(n * 0.90))], 2),
            "p99": round(sorted_lat[min(n - 1, int(n * 0.99))], 2),
        },
    }


def run_benchmark_suite(
    thread_levels: List[int],
    requests_per_level: int = 500,
    output_json: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute complete benchmarking suite across multiple thread concurrency levels."""
    server = ThreadedHTTPServer(("127.0.0.1", 0), BenchmarkServerHandler)
    port = server.server_port
    base_url = f"http://127.0.0.1:{port}"

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    sys_specs = get_system_specifications()

    print("\n" + "=" * 78)
    print("  WebAdminMapper Performance Benchmarking Suite")
    print(f"  Author & Developer: Ahmed Wael | Version: {__version__}")
    print("=" * 78)
    print(f"  OS Platform       : {sys_specs['os']} ({sys_specs['architecture']})")
    print(f"  CPU Cores         : {sys_specs['cpu_cores']} logical cores ({sys_specs['processor']})")
    print(f"  Python Runtime    : {sys_specs['python_implementation']} {sys_specs['python_version']}")
    print(f"  Requests per Trial: {requests_per_level}")
    print("=" * 78)
    print(f"  {'THREADS':<8}  {'REQS':>6}  {'TIME (s)':>9}  {'SPEED (req/s)':>14}  {'ERR RATE':>9}  {'P50 (ms)':>9}  {'P99 (ms)':>9}")
    print("  " + "-" * 74)

    trials: List[Dict[str, Any]] = []

    try:
        for t in thread_levels:
            trial = run_benchmark_trial(base_url, threads=t, request_count=requests_per_level)
            trials.append(trial)
            lat = trial["latency_stats_ms"]
            print(
                f"  {trial['threads']:<8}  "
                f"{trial['total_requests']:>6}  "
                f"{trial['execution_time_sec']:>9.3f}  "
                f"{trial['throughput_req_sec']:>14.1f}  "
                f"{trial['error_rate_pct']:>8.1f}%  "
                f"{lat['p50']:>9.1f}  "
                f"{lat['p99']:>9.1f}"
            )
    finally:
        server.shutdown()
        server.server_close()

    print("=" * 78 + "\n")

    report = {
        "author": __author__,
        "version": __version__,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "system_specifications": sys_specs,
        "trials": trials,
    }

    if output_json:
        out_path = Path(output_json).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Benchmark results exported to: {out_path}\n")

    return report


def main():
    parser = argparse.ArgumentParser(description="WebAdminMapper Performance Benchmarking Suite")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run a quick benchmark trial (10, 25, 50 threads; 250 reqs)",
    )
    parser.add_argument(
        "--threads",
        type=str,
        default="5,10,25,50,100",
        help="Comma-separated thread levels to benchmark (default: 5,10,25,50,100)",
    )
    parser.add_argument(
        "-n", "--requests",
        type=int,
        default=500,
        help="Number of requests per concurrency level (default: 500)",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="benchmarks/benchmark_results.json",
        help="Output path for benchmark JSON report (default: benchmarks/benchmark_results.json)",
    )

    args = parser.parse_args()

    if args.quick:
        threads = [10, 25, 50]
        reqs = 250
    else:
        threads = [int(x.strip()) for x in args.threads.split(",") if x.strip().isdigit()]
        reqs = args.requests

    run_benchmark_suite(thread_levels=threads, requests_per_level=reqs, output_json=args.output)


if __name__ == "__main__":
    main()
