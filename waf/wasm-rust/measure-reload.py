#!/usr/bin/env python3
"""Reload the same WAF listener in one Envoy process and sample cgroup memory."""

import os
import http.client
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


GATEWAY = "higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/gateway:2.2.3"
TEMPLATE = Path(__file__).resolve().parents[1] / "skills/waf-envoy-test/assets/envoy.yaml"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


def status(port):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/waf-local-probe", timeout=2) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code
    except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException):
        return 0


def wait_for(port, expected, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if status(port) == expected:
            return
        time.sleep(0.2)
    raise RuntimeError(f"probe did not become HTTP {expected}; got {status(port)}")


def write_listener(path, listener, version, enabled):
    value = listener.replace('"enabled":true', '"enabled":true' if enabled else '"enabled":false')
    assert value != listener or enabled
    content = f"version_info: '{version}'\nresources:\n  - '@type': type.googleapis.com/envoy.config.listener.v3.Listener\n    name: local\n" + value
    temporary = path.with_suffix(".next")
    temporary.write_text(content)
    os.replace(temporary, path)


def main(source, rounds=20):
    template = TEMPLATE.read_text()
    admin, listener = template.split("static_resources:\n  listeners:\n  - name: local\n", 1)
    listener = listener.replace("/etc/envoy/plugin.wasm", "/etc/envoy/dynamic/plugin.wasm")
    with tempfile.TemporaryDirectory(prefix="waf-reload-") as temp:
        directory = Path(temp)
        wasm = directory / "plugin.wasm"
        if source.suffix == ".wasm" and source.is_file():
            shutil.copyfile(source, wasm)
        else:
            extracted = docker("create", str(source), "/plugin.wasm")
            try:
                docker("cp", f"{extracted}:/plugin.wasm", str(wasm))
            finally:
                docker("rm", "-f", extracted)
        (directory / "bootstrap.yaml").write_text(admin + "node:\n  id: waf-reload\n  cluster: local\ndynamic_resources:\n  lds_config:\n    path: /etc/envoy/dynamic/lds.yaml\n")
        lds = directory / "lds.yaml"
        write_listener(lds, listener, 0, True)
        name = f"waf-reload-{os.getpid()}"
        docker("run", "-d", "--name", name, "--cpus", "2", "--memory", "8g",
               "-p", "127.0.0.1::10000", "-v", f"{directory}:/etc/envoy/dynamic",
               "--entrypoint", "envoy", GATEWAY, "-c", "/etc/envoy/dynamic/bootstrap.yaml",
               "--concurrency", "2", "--log-level", "info")
        try:
            port = int(docker("port", name, "10000/tcp").rsplit(":", 1)[1])
            wait_for(port, 403, 180)
            print("round,status,memory_current_mib,memory_anon_mib,memory_peak_mib,wasm_memory_mib,wasm_active,wasm_created", flush=True)
            for round_number in range(rounds + 1):
                if round_number:
                    enabled = round_number % 2 == 0
                    write_listener(lds, listener, round_number, enabled)
                    wait_for(port, 403 if enabled else 200)
                    time.sleep(1)
                current = int(docker("exec", name, "cat", "/sys/fs/cgroup/memory.current")) / 1048576
                memory_stat = docker("exec", name, "cat", "/sys/fs/cgroup/memory.stat")
                anon = int(next(line.split()[1] for line in memory_stat.splitlines() if line.startswith("anon "))) / 1048576
                peak = int(docker("exec", name, "cat", "/sys/fs/cgroup/memory.peak")) / 1048576
                stats = docker("exec", name, "curl", "-fsS", "http://127.0.0.1:9901/stats?filter=wasm")
                values = dict(line.rsplit(": ", 1) for line in stats.splitlines() if ": " in line)
                memory_values = [int(value) for key, value in values.items() if key.startswith("wasm.envoy.wasm.runtime.v8.plugin.wasmtest.") and key.endswith(".memory_size")]
                wasm = f"{sum(memory_values) / 1048576:.1f}" if any(memory_values) else ""
                active = values["wasm.envoy.wasm.runtime.v8.active"]
                created = values["wasm.envoy.wasm.runtime.v8.created"]
                print(f"{round_number},{403 if round_number % 2 == 0 else 200},{current:.1f},{anon:.1f},{peak:.1f},{wasm},{active},{created}", flush=True)
        except Exception:
            print(docker("logs", name)[-6000:], file=sys.stderr)
            raise
        finally:
            docker("rm", "-f", name)


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(f"usage: {sys.argv[0]} <wasm file or image> [rounds]")
    main(Path(sys.argv[1]).resolve() if Path(sys.argv[1]).is_file() else Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) == 3 else 20)
