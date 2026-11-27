#!/usr/bin/env python3
"""Benchmark one CRS rule at a time on the existing 218 WAF compare ingress."""

import argparse
import concurrent.futures
import csv
import http.client
import json
from pathlib import Path
import statistics
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "ui/system-rules.json"
PLUGINS = {
    "go": ("w7panel-pluginwaf", 1, "wafgo218.fan.b2.sz.w7.com"),
    "rust": ("w7panel-wafrust", 0, "wafrust218.fan.b2.sz.w7.com"),
}


def kubectl(config, *args):
    attempts = 90 if args[0] == "get" else 1
    for attempt in range(attempts):
        result = subprocess.run(["kubectl", "--kubeconfig", config, *args], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        if not any(term in result.stderr for term in ("ServiceUnavailable", "connection refused", "was refused", "TLS handshake timeout", "i/o timeout")) or attempt == attempts - 1:
            raise RuntimeError(result.stderr.strip())
        time.sleep(1)


def replace_config(kubeconfig, name, path, expected, desired):
    for attempt in range(10):
        live = json.loads(kubectl(kubeconfig, "get", "wasmplugin", name, "-n", "higress-system", "-o", "json"))
        index = int(path.split("/")[3])
        actual = live["spec"]["matchRules"][index]["config"]
        if actual == desired:
            return
        if actual != expected:
            raise RuntimeError(f"{name} test config changed externally; inspect before restoring")
        operations = [{"op": "test", "path": path, "value": expected}, {"op": "replace", "path": path, "value": desired}]
        try:
            kubectl(kubeconfig, "patch", "wasmplugin", name, "-n", "higress-system", "--type=json", "-p", json.dumps(operations, separators=(",", ":")))
            return
        except RuntimeError:
            if attempt == 9:
                raise
            time.sleep(0.5)


def request(port, host, method, path, body=b"", extra=None, timeout=30):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"Host": host, **(extra or {})}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


def bench(port, host, method, path, body, requests, concurrency, extra):
    def worker(count):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        times, statuses = [], []
        try:
            for _ in range(count):
                started = time.perf_counter()
                try:
                    connection.request(method, path, body=body, headers={"Host": host, **extra})
                    response = connection.getresponse()
                    response.read()
                    statuses.append(response.status)
                except Exception:
                    statuses.append(0)
                    connection.close()
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                times.append((time.perf_counter() - started) * 1000)
        finally:
            connection.close()
        return times, statuses

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(worker, [requests // concurrency + (i < requests % concurrency) for i in range(concurrency)]))
    times = sorted(t for row, _ in results for t in row)
    statuses = [status for _, row in results for status in row]
    return (round(requests / (time.perf_counter() - started), 1),
            round(statistics.median(times), 2),
            round(times[int((len(times) - 1) * 0.95)], 2),
            ";".join(f"{status}:{statuses.count(status)}" for status in sorted(set(statuses))))


def main(args):
    name, match_index, host = PLUGINS[args.plugin]
    catalog = json.loads(CATALOG.read_text())
    rules = list(enumerate((row for row in catalog["rules"] if not row["internal"]), 1))
    rules = ([item for item in rules if item[1]["id"] in args.ids] if args.ids
             else rules[args.start - 1:args.start - 1 + args.limit if args.limit else None])
    if args.ids and len(rules) != len(args.ids):
        raise ValueError("unknown or internal CRS rule ID in --ids")
    categories = {row["name"].removesuffix(".conf"): False for row in catalog["files"]}
    resource = json.loads(kubectl(args.kubeconfig, "get", "wasmplugin", name, "-n", "higress-system", "-o", "json"))
    original = resource["spec"]["matchRules"][match_index]["config"]
    ingress = resource["spec"]["matchRules"][match_index]["ingress"]
    if ingress != [f"default/waf-{args.plugin}-218-compare"]:
        raise RuntimeError(f"unexpected test ingress: {ingress}")
    path = f"/spec/matchRules/{match_index}/config"
    current = original
    forward = subprocess.Popen(["kubectl", "--kubeconfig", args.kubeconfig, "port-forward", "-n", "higress-system", "pod/" + args.pod, f"{args.port}:80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if request(args.port, host, "GET", "/") == 200:
                    break
            except OSError:
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError("port-forward or test ingress is not ready")
        with open(args.output, "w", newline="") as output:
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["plugin", "index", "id", "file", "mode", "requests", "concurrency", "load_seconds", "rps", "p50_ms", "p95_ms", "statuses"])
            for index, row in rules:
                rule_file = row["file"].removesuffix(".conf")
                marker = f"/waf-218-bench-ready-{args.plugin}-{index}"
                updated = {**original,
                    "useCRS": True, "requestBodyAccess": True, "engineMode": "On",
                    "paranoiaLevel": row["paranoiaLevel"] or 1,
                    "categories": {**categories, rule_file: True},
                    "ruleStates": {str(other["id"]): False for other in catalog["rules"] if not other["internal"] and other["file"] == row["file"] and other["id"] != row["id"]},
                    "customRules": [{"id": 1000000, "enabled": True, "rule": f'SecRule REQUEST_URI "@streq {marker}" "id:1000000,phase:1,deny,status:403"'}],
                }
                started = time.monotonic()
                replace_config(args.kubeconfig, name, path, current, updated)
                current = updated
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    if request(args.port, host, "GET", marker) == 403:
                        break
                    time.sleep(0.2)
                else:
                    raise RuntimeError(f"rule {row['id']} did not load")
                load_seconds = round(time.monotonic() - started, 2)
                cases = [
                    ("nonbody", "GET", "/bench?data=" + "a" * 1024, b"", {"X-Bench": "a" * 1024}),
                    ("body", "POST", "/bench", b"data=" + b"a" * (args.body_size - 5), {"Content-Type": "application/x-www-form-urlencoded"}),
                ]
                for mode, method, url, body, headers in cases:
                    for _ in range(3):
                        request(args.port, host, method, url, body, headers)
                    result = bench(args.port, host, method, url, body, args.requests, args.concurrency, headers)
                    writer.writerow([args.plugin, index, row["id"], row["file"], mode, args.requests, args.concurrency, load_seconds, *result])
                    output.flush()
                print(f"{args.plugin} {index}/{515} {row['id']} loaded in {load_seconds}s", flush=True)
    finally:
        try:
            if current != original:
                replace_config(args.kubeconfig, name, path, current, original)
        finally:
            forward.terminate()
            forward.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("plugin", choices=PLUGINS)
    parser.add_argument("--kubeconfig", default=str(Path.home() / ".kube/218.config"))
    parser.add_argument("--pod", default="higress-gateway-5c444bbdcf-tjbq6")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--output", required=True)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--ids", type=lambda value: {int(item) for item in value.split(",")})
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--body-size", type=int, default=16384)
    options = parser.parse_args()
    if options.start < 1 or options.limit < 0 or options.requests < 1 or options.concurrency < 1 or options.body_size < 5:
        parser.error("invalid benchmark size or count")
    main(options)
