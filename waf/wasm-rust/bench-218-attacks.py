#!/usr/bin/env python3
"""Run official CRS request attack cases against one 218 WAF rule at a time."""

import argparse
import csv
from datetime import datetime, timezone
import http.client
import importlib.util
import json
from pathlib import Path
import subprocess
import time

import yaml

BENCH = Path(__file__).resolve().parent / "bench-218.py"
spec = importlib.util.spec_from_file_location("bench218", BENCH)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def load_cases(tests_dir):
    matches = {}
    for path in tests_dir.rglob("*.yaml"):
        data = yaml.safe_load(path.read_text())
        if not isinstance(data, dict):
            continue
        for test in data.get("tests", []):
            for stage in test.get("stages", []):
                ids = ((stage.get("output") or {}).get("log") or {}).get("expect_ids", [])
                if not ids:
                    continue
                inp = stage.get("input") or {}
                if "encoded_request" in inp or "autocomplete_headers" in inp:
                    continue
                if not isinstance(inp.get("uri"), str) or not inp["uri"].startswith("/"):
                    continue
                try:
                    inp["uri"].encode("ascii")
                except UnicodeEncodeError:
                    continue
                if inp.get("version", "HTTP/1.1") != "HTTP/1.1":
                    continue
                headers = inp.get("headers") or {}
                if not isinstance(headers, dict):
                    continue
                headers = {str(k): str(v) for k, v in headers.items() if k.lower() != "host"}
                try:
                    for key, value in headers.items():
                        key.encode("ascii")
                        value.encode("latin-1")
                except UnicodeEncodeError:
                    continue
                body = inp.get("data", "")
                if not isinstance(body, str) or "{{" in body or "{%" in body or len(body.encode()) > 131072:
                    continue
                if any(k.lower() == "content-length" for k in headers):
                    continue
                if body and not any(k.lower() == "content-type" for k in headers):
                    headers["Content-Type"] = "application/x-www-form-urlencoded"
                for rule_id in ids:
                    matches.setdefault(rule_id, []).append((path.name, test.get("test_id"), inp.get("method", "GET"), inp["uri"], body.encode(), headers))
    return matches


def logs_since(kubeconfig, pod, since):
    return bench.kubectl(kubeconfig, "logs", "-n", "higress-system", "pod/" + pod, "--since-time=" + since, "--tail=1000")


def main(args):
    name, match_index, host = bench.PLUGINS[args.plugin]
    catalog = json.loads(bench.CATALOG.read_text())
    rules = [row for row in catalog["rules"] if not row["internal"] and row["file"].startswith("REQUEST-")]
    selected = [row for row in rules if row["id"] in args.ids] if args.ids else rules[args.start - 1:args.start - 1 + args.limit if args.limit else None]
    if args.ids and len(selected) != len(args.ids):
        raise ValueError("unknown or non-request CRS rule ID in --ids")
    samples_by_id = load_cases(args.tests_dir)
    categories = {row["name"].removesuffix(".conf"): False for row in catalog["files"]}
    resource = json.loads(bench.kubectl(args.kubeconfig, "get", "wasmplugin", name, "-n", "higress-system", "-o", "json"))
    original = resource["spec"]["matchRules"][match_index]["config"]
    ingress = resource["spec"]["matchRules"][match_index]["ingress"]
    if ingress != [f"default/waf-{args.plugin}-218-compare"]:
        raise RuntimeError(f"unexpected test ingress: {ingress}")
    path = f"/spec/matchRules/{match_index}/config"
    current = original
    forward = subprocess.Popen(["kubectl", "--kubeconfig", args.kubeconfig, "port-forward", "-n", "higress-system", "pod/" + args.pod, f"{args.port}:80"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                if bench.request(args.port, host, "GET", "/") == 200:
                    break
            except OSError:
                pass
            time.sleep(.2)
        else:
            raise RuntimeError("port-forward or test ingress is not ready")
        with open(args.output, "w", newline="") as output:
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["plugin", "id", "file", "test_file", "test_id", "method", "uri", "body_bytes", "load_seconds", "status", "log_hit", "control_status", "target_dependent", "rps", "p50_ms", "p95_ms", "statuses", "error"])
            for index, row in enumerate(selected, args.start):
                samples = samples_by_id.get(row["id"], [])
                if not samples:
                    writer.writerow([args.plugin, row["id"], row["file"]] + [""] * 14 + ["no usable official request case"])
                    output.flush()
                    continue
                rule_file = row["file"].removesuffix(".conf")
                marker = f"/waf-218-attack-ready-{args.plugin}-{row['id']}"
                updated = {**original, "useCRS": True, "requestBodyAccess": True, "engineMode": "On",
                           "paranoiaLevel": row["paranoiaLevel"] or 1,
                           "categories": {**categories, rule_file: True},
                           "ruleStates": {str(other["id"]): False for other in catalog["rules"] if not other["internal"] and other["file"] == row["file"] and other["id"] != row["id"]},
                           "customRules": [{"id": 1000000, "enabled": True, "rule": f'SecRule REQUEST_URI "@streq {marker}" "id:1000000,phase:1,deny,status:403"'}]}
                started = time.monotonic()
                bench.replace_config(args.kubeconfig, name, path, current, updated)
                current = updated
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    if bench.request(args.port, host, "GET", marker) == 403:
                        break
                    time.sleep(.2)
                else:
                    raise RuntimeError(f"rule {row['id']} did not load")
                load_seconds = round(time.monotonic() - started, 2)
                error = ""
                hit = False
                control_status = ""
                dependent = 0
                for test_file, test_id, method, uri, body, headers in samples[:args.attempts]:
                    since = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
                    try:
                        status = bench.request(args.port, host, method, uri, body, headers)
                        logs = logs_since(args.kubeconfig, args.pod, since)
                        hit = any(f"wasm log higress-system.{name}:" in line and f'[id "{row["id"]}"]' in line for line in logs.splitlines())
                        if hit or (args.plugin == "rust" and status != 200):
                            rps, p50, p95, statuses = bench.bench(args.port, host, method, uri, body, args.requests, args.concurrency, headers)
                            if args.plugin == "rust":
                                control_marker = f"/waf-218-control-ready-{row['id']}"
                                control = {**updated,
                                           "ruleStates": {**updated["ruleStates"], str(row["id"]): False},
                                           "customRules": [{"id": 1000000, "enabled": True, "rule": f'SecRule REQUEST_URI "@streq {control_marker}" "id:1000000,phase:1,deny,status:403"'}]}
                                bench.replace_config(args.kubeconfig, name, path, current, control)
                                current = control
                                deadline = time.monotonic() + 90
                                while time.monotonic() < deadline:
                                    if bench.request(args.port, host, "GET", control_marker) == 403:
                                        break
                                    time.sleep(.2)
                                else:
                                    raise RuntimeError(f"rule {row['id']} control did not load")
                                control_status = bench.request(args.port, host, method, uri, body, headers)
                                dependent = int(control_status == 200)
                            result_error = "" if hit or dependent else f"target-independent HTTP {status}"
                            writer.writerow([args.plugin, row["id"], row["file"], test_file, test_id, method, uri, len(body), load_seconds, status, int(hit), control_status, dependent, rps, p50, p95, statuses, result_error])
                            break
                        error = "target rule not proven"
                    except (OSError, ValueError, http.client.HTTPException) as exc:
                        status = 0
                        error = str(exc)
                else:
                    writer.writerow([args.plugin, row["id"], row["file"], test_file, test_id, method, uri, len(body), load_seconds, status, 0, "", 0, "", "", "", "", error])
                output.flush()
                print(f"{args.plugin} {index}/{len(rules)} {row['id']}: {'hit' if hit or dependent else error or 'ambiguous'}", flush=True)
    finally:
        try:
            if current != original:
                bench.replace_config(args.kubeconfig, name, path, current, original)
        finally:
            forward.terminate()
            forward.wait(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("plugin", choices=bench.PLUGINS)
    parser.add_argument("--tests-dir", type=Path, default=Path("/tmp/crs-v4.30.0/tests/regression/tests"))
    parser.add_argument("--kubeconfig", default=str(Path.home() / ".kube/218.config"))
    parser.add_argument("--pod", default="higress-gateway-5c444bbdcf-tjbq6")
    parser.add_argument("--port", type=int, default=18081)
    parser.add_argument("--output", required=True)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--ids", type=lambda value: {int(item) for item in value.split(",")})
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--concurrency", type=int, default=4)
    options = parser.parse_args()
    if options.start < 1 or options.limit < 0 or options.attempts < 1 or options.requests < 1 or options.concurrency < 1 or not options.tests_dir.is_dir():
        parser.error("invalid count or tests directory")
    main(options)
