#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "用法: $0 <WAF 镜像标签或本地 .wasm 文件>" >&2
  exit 2
fi
for tool in docker curl; do
  command -v "$tool" >/dev/null || { echo "缺少 $tool" >&2; exit 2; }
done

source_path=$1
skill_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
temp_dir=$(mktemp -d)
container="waf-envoy-test-$$"
extract_container=
cleanup() {
  docker stop "$container" >/dev/null 2>&1 || true
  if [[ -n "$extract_container" ]]; then docker rm -f "$extract_container" >/dev/null 2>&1 || true; fi
  rm -rf "$temp_dir"
}
trap cleanup EXIT

if [[ -f "$source_path" && "$source_path" == *.wasm ]]; then
  cp "$source_path" "$temp_dir/plugin.wasm"
else
  extract_container=$(docker create "$source_path" /plugin.wasm)
  docker cp "$extract_container:/plugin.wasm" "$temp_dir/plugin.wasm"
  docker rm "$extract_container" >/dev/null
  extract_container=
fi

gateway_image=higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/gateway:2.2.3
started=$(date +%s)
docker run -d --rm --name "$container" --cpus 2 --memory 8g \
  -p 127.0.0.1::10000 -p 127.0.0.1::9901 \
  --entrypoint envoy \
  -v "$skill_dir/assets/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  -v "$temp_dir/plugin.wasm:/etc/envoy/plugin.wasm:ro" \
  "$gateway_image" -c /etc/envoy/envoy.yaml --concurrency 2 --log-level info >/dev/null

admin_port=$(docker port "$container" 9901/tcp | sed -n '1s/.*://p')
http_port=$(docker port "$container" 10000/tcp | sed -n '1s/.*://p')
deadline=$((SECONDS + 180))
until curl -fsS --max-time 1 "http://127.0.0.1:$admin_port/ready" 2>/dev/null | grep -q LIVE; do
  if (( SECONDS >= deadline )) || [[ $(docker inspect -f '{{.State.Running}}' "$container") != true ]]; then
    docker logs --timestamps "$container" >&2
    echo "Envoy 未在 180 秒内就绪" >&2
    exit 1
  fi
  sleep 1
done
echo "Envoy 就绪: $(( $(date +%s) - started )) 秒（从容器启动算起）"
docker logs --timestamps "$container" 2>&1 | grep 'plugin start successfully' || true

check() {
  local label=$1 expected=$2 actual=$3
  echo "$label: HTTP $actual"
  [[ "$actual" == "$expected" ]] || { echo "$label 预期 HTTP $expected" >&2; exit 1; }
}
base="http://127.0.0.1:$http_port"
check custom 403 "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$base/waf-local-probe")"
check sqli 403 "$(curl -sS -G -o /dev/null -w '%{http_code}' --max-time 10 --data-urlencode "id=1' OR '1'='1" "$base/")"
check xss 403 "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$base/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")"
check normal 200 "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$base/normal")"
docker stats --no-stream --format '内存: {{.MemUsage}}' "$container"
