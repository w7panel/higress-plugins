#!/usr/bin/env python3
"""Measure cold Go or Rust WASM build process-tree RSS on this host."""

import os
import pathlib
import subprocess
import sys
import tempfile
import time


def group_rss(pgid):
    pages = 0
    for process in pathlib.Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = process.read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid:
                pages += int(fields[21])
        except (OSError, IndexError, ValueError):
            continue
    return pages * os.sysconf("SC_PAGE_SIZE")


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"go", "rust"}:
        raise SystemExit("usage: measure-build.py go|rust")
    kind = sys.argv[1]
    directory = pathlib.Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix=f"waf-{kind}-build-") as temporary:
        env = os.environ.copy()
        if kind == "go":
            env.update(GOOS="wasip1", GOARCH="wasm", GOCACHE=f"{temporary}/cache")
            cmd = ["go", "build", "-tags=no_fs_access", "-buildmode=c-shared", "-buildvcs=false", "-o", f"{temporary}/plugin.wasm", "."]
            cwd = directory.parent / "wasm"
        else:
            env["CARGO_TARGET_DIR"] = f"{temporary}/target"
            cmd = ["mise", "exec", "rust@1.99.1", "--", "cargo", "build", "--locked", "--release", "--target", "wasm32-wasip1"]
            cwd = directory
        started = time.monotonic()
        process = subprocess.Popen(cmd, cwd=cwd, env=env, start_new_session=True)
        peak = 0
        while process.poll() is None:
            peak = max(peak, group_rss(process.pid))
            time.sleep(0.05)
        peak = max(peak, group_rss(process.pid))
        print(f"{kind}: exit={process.returncode}, elapsed={time.monotonic() - started:.2f}s, peak_process_group_rss={peak / 1048576:.1f} MiB")
        return process.returncode


if __name__ == "__main__":
    raise SystemExit(main())
