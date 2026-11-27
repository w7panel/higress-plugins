#!/usr/bin/env python3
"""Benchmark request bodies or one enabled CRS detection rule at a time in local Envoy."""

import argparse
import concurrent.futures
import csv
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import random
import re
import statistics
import string
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "skills/waf-envoy-test/assets/envoy.yaml"
CATALOG = ROOT / "ui/system-rules.json"
GATEWAY = "higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/gateway:2.2.3"
LEAK_BODY = b"<title>Index of /</title><h1>Index of /</h1>"


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        try:
            self.wfile.write(b"ok")
        except BrokenPipeError:
            pass

    def do_GET(self):
        body = (LEAK_BODY if self.path.startswith("/leak")
                else b"<html>" + b"a" * 16384 + b"</html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, *_args):
        pass


class QuietServer(ThreadingHTTPServer):
    def handle_error(self, _request, _client_address):
        pass


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def stat(name, key):
    output = docker("exec", name, "curl", "-fsS", "http://127.0.0.1:9901/stats?filter=listener_manager.lds.update_success")
    match = re.search(rf"^{re.escape(key)}: (\d+)$", output, re.MULTILINE)
    return int(match.group(1)) if match else 0


def fetch(port, body, method="POST", path="/bench", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body, headers or {"Content-Type": "application/x-www-form-urlencoded"})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def probe(port, body, method="POST", path="/bench", headers=None):
    return fetch(port, body, method, path, headers)[0]


def load(path, listener, name, port, version, config):
    before = stat(name, "listener_manager.lds.update_success")
    value = json.dumps(config, separators=(",", ":"))
    if "'" in value:
        raise ValueError("single quote in config is not supported by the Envoy template")
    content = re.sub(r"(?m)^(\s*value: )'.*'$", lambda m: m.group(1) + "'" + value + "'", listener, count=1)
    if content == listener:
        raise ValueError("plugin configuration was not found in the Envoy template")
    content = f"version_info: '{version}'\nresources:\n  - '@type': type.googleapis.com/envoy.config.listener.v3.Listener\n    name: local\n" + content
    temporary = path.with_suffix(".next")
    temporary.write_text(content)
    os.replace(temporary, path)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if stat(name, "listener_manager.lds.update_success") > before:
            status = probe(port, b"data=ok")
            if status == 200:
                return
            raise RuntimeError(f"loaded config {version} returned HTTP {status}")
        time.sleep(0.1)
    raise TimeoutError(f"LDS update {version} did not succeed")


def bench(port, body, requests, concurrency, method="POST", path="/bench", headers=None):
    def worker(count):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        times = []
        errors = 0
        try:
            for _ in range(count):
                start = time.perf_counter()
                try:
                    conn.request(method, path, body, headers or {"Content-Type": "application/x-www-form-urlencoded"})
                    response = conn.getresponse()
                    response.read()
                    errors += response.status != 200
                except Exception:
                    errors += 1
                    conn.close()
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
                times.append((time.perf_counter() - start) * 1000)
        finally:
            conn.close()
        return times, errors

    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(worker, [requests // concurrency + (i < requests % concurrency) for i in range(concurrency)]))
    elapsed = time.perf_counter() - started
    times = sorted(t for row, _ in results for t in row)
    return round(requests / elapsed, 1), round(statistics.median(times), 2), round(times[int((len(times) - 1) * 0.95)], 2), sum(error for _, error in results)


def payload(size, pattern):
    length = max(size - 5, 0)
    value = ("".join(random.Random(0).choices(string.ascii_letters + string.digits, k=length)) if pattern == "alnum" else "a" * length)
    return (b"data=" + value.encode())[:size]


def attack(size, at_end):
    injection = b"id=1%27+OR+%271%27%3D%271"
    padding = b"a" * max(size - len(injection) - 6, 0)
    return (b"data=" + padding + b"&" + injection) if at_end else (injection + b"&data=" + padding)


def main(args):
    catalog = json.loads(CATALOG.read_text())
    rules = [row for row in catalog["rules"] if not row["internal"]]
    categories = {row["name"].removesuffix(".conf"): False for row in catalog["files"]}
    template = TEMPLATE.read_text()
    admin, listener = template.split("static_resources:\n  listeners:\n  - name: local\n", 1)
    listener = listener.replace("/etc/envoy/plugin.wasm", "/etc/envoy/dynamic/plugin.wasm")
    listener = listener.replace('direct_response: {status: 200, body: {inline_string: "upstream-ok"}}', 'route: {cluster: benchmark_upstream}')
    gateway_ip = docker("network", "inspect", "bridge", "--format", "{{(index .IPAM.Config 0).Gateway}}")
    upstream = QuietServer((gateway_ip, 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="waf-rule-bench-") as temp:
        directory = Path(temp)
        if Path(args.image).is_file() and args.image.endswith(".wasm"):
            (directory / "plugin.wasm").write_bytes(Path(args.image).read_bytes())
        else:
            image = docker("create", args.image, "/plugin.wasm")
            try:
                docker("cp", f"{image}:/plugin.wasm", str(directory / "plugin.wasm"))
            finally:
                docker("rm", "-f", image)
        (directory / "bootstrap.yaml").write_text(admin + f"node:\n  id: waf-rule-bench\n  cluster: local\ndynamic_resources:\n  lds_config:\n    path: /etc/envoy/dynamic/lds.yaml\nstatic_resources:\n  clusters:\n  - name: benchmark_upstream\n    type: STATIC\n    connect_timeout: 1s\n    load_assignment:\n      cluster_name: benchmark_upstream\n      endpoints:\n      - lb_endpoints:\n        - endpoint:\n            address:\n              socket_address: {{address: {gateway_ip}, port_value: {upstream.server_port}}}\n")
        lds = directory / "lds.yaml"
        lds.write_text("version_info: '0'\nresources:\n  - '@type': type.googleapis.com/envoy.config.listener.v3.Listener\n    name: local\n" + listener)
        name = f"waf-rule-bench-{os.getpid()}-{random.getrandbits(32):08x}"
        docker("run", "-d", "--name", name, "--cpus", "2", "--memory", "8g",
               "-p", "127.0.0.1::10000", "-v", f"{directory}:/etc/envoy/dynamic",
               "--entrypoint", "envoy", GATEWAY, "-c", "/etc/envoy/dynamic/bootstrap.yaml",
               "--concurrency", "2", "--log-level", "error")
        try:
            port = int(docker("port", name, "10000/tcp").rsplit(":", 1)[1])
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                try:
                    if probe(port, b"data=ok") == 200:
                        break
                except (OSError, http.client.HTTPException):
                    pass
                time.sleep(0.2)
            else:
                raise TimeoutError("initial WAF listener did not become ready")
            if args.mode == "smoke":
                load(lds, listener, name, port, 1, {"useCRS": True, "paranoiaLevel": 1})
                checks = [
                    ("normal", "/normal", {}, 200),
                    ("url-sqli", "/?id=1%27+OR+%271%27%3D%271", {}, 403),
                    ("url-xss", "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", {}, 403),
                    ("header-scanner", "/normal", {"User-Agent": "sqlmap/1.0"}, 403),
                ]
                for label, path, headers, expected in checks:
                    status = probe(port, b"", "GET", path, headers)
                    print(f"{label}: {status} (expected {expected})", file=sys.stderr)
                    if status != expected:
                        raise AssertionError(label)
                status, response = fetch(port, b"", "GET", "/leak")
                print(f"response-leak: {status}, bytes={len(response)}, leaked={b'Index of /' in response}", file=sys.stderr)
                if status != 200 or len(response) != len(LEAK_BODY) or any(response):
                    raise AssertionError("response-leak")
                return
            writer = csv.writer(sys.stdout, lineterminator="\n")
            writer.writerow(["mode", "id", "file", "payload", "body_bytes", "requests", "concurrency", "load_seconds", "rps", "p50_ms", "p95_ms", "errors", "attack_simple_status", "attack_head_status", "attack_tail_status"])
            cases = []
            if args.mode == "body":
                sizes = [int(value) for value in args.sizes.split(",")] if args.sizes else (0, 1024, 16384, 262144, 1048576)
                for label, config in [
                    ("body-off", {"useCRS": False, "requestBodyAccess": False}),
                    ("no-crs", {"useCRS": False, "requestBodyAccess": True}),
                    ("full-crs", {"useCRS": True, "requestBodyAccess": True, "paranoiaLevel": 1}),
                ]:
                    for size in sizes:
                        cases.append((label, "", size, config))
            else:
                selected = [row for row in rules if row["id"] in args.ids] if args.ids else rules[:args.limit or None]
                if args.ids and len(selected) != len(args.ids):
                    raise ValueError("unknown or internal CRS rule ID in --ids")
                for row in selected:
                    file = row["file"].removesuffix(".conf")
                    states = {str(other["id"]): False for other in rules if other["file"] == row["file"] and other["id"] != row["id"]}
                    config = {"useCRS": True, "requestBodyAccess": True,
                              "paranoiaLevel": row["paranoiaLevel"] or 1,
                              "categories": {**categories, file: True}, "ruleStates": states}
                    cases.append((str(row["id"]), row["file"], args.body_size if args.mode == "rules" else 0, config))
            for index, (label, file, size, config) in enumerate(cases, 1):
                try:
                    started = time.monotonic()
                    load(lds, listener, name, port, index, config)
                    load_seconds = round(time.monotonic() - started, 2)
                    body = payload(size, args.payload)
                    method = "GET" if args.mode == "nonbody" else "POST"
                    request_path = "/bench?data=" + "a" * 1024 if args.mode == "nonbody" else "/bench"
                    headers = {"X-Bench": "a" * 1024} if args.mode == "nonbody" else None
                    for _ in range(3):
                        probe(port, body, method, request_path, headers)
                    rps, p50, p95, errors = bench(port, body, args.requests, args.concurrency, method, request_path, headers)
                    simple = probe(port, b"id=1%27+OR+%271%27%3D%271") if args.mode == "body" else ""
                    head = probe(port, attack(size, False)) if args.mode == "body" and size >= 100 else ""
                    tail = probe(port, attack(size, True)) if args.mode == "body" and size >= 100 else ""
                    writer.writerow([args.mode, label, file, args.payload, size, args.requests, args.concurrency, load_seconds, rps, p50, p95, errors, simple, head, tail])
                    sys.stdout.flush()
                    if errors or any(isinstance(status, int) and status >= 500 for status in (simple, head, tail)):
                        print(docker("logs", name)[-2000:], file=sys.stderr)
                except Exception as error:
                    writer.writerow([args.mode, label, file, args.payload, size, args.requests, args.concurrency, "", "", "", "", str(error), "", "", ""])
                    sys.stdout.flush()
                print(f"{index}/{len(cases)} {label}", file=sys.stderr, flush=True)
        finally:
            docker("rm", "-f", name)
            upstream.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("body", "rules", "nonbody", "smoke"))
    parser.add_argument("image")
    parser.add_argument("--body-size", type=int, default=16384)
    parser.add_argument("--requests", type=int, default=40)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--ids", type=lambda value: {int(item) for item in value.split(",")}, help="comma-separated detection rule IDs for rules mode")
    parser.add_argument("--sizes", help="comma-separated body sizes for body mode")
    parser.add_argument("--payload", choices=("repeat", "alnum"), default="repeat")
    options = parser.parse_args()
    if options.body_size < 0 or options.requests < 1 or options.concurrency < 1 or options.limit < 0:
        parser.error("body-size, requests, concurrency, and limit must be nonnegative; requests and concurrency must be positive")
    if options.sizes:
        try:
            if options.mode != "body" or any(int(value) < 0 for value in options.sizes.split(",")):
                parser.error("sizes must be nonnegative integers in body mode")
        except ValueError:
            parser.error("sizes must be comma-separated integers")
    if options.ids and options.mode not in ("rules", "nonbody"):
        parser.error("ids is only valid in rules and nonbody modes")
    main(options)
