#!/usr/bin/env python3
"""Generate the UI catalog from the exact CRS files embedded in the Wasm."""
import argparse
from collections import Counter, defaultdict
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / 'wasm/wasmplugin/rules/crs'
NAMES = ROOT / 'ui/rule-names.zh.json'
OUTPUT = ROOT / 'ui/system-rules.json'
VERSION = 'v4.30.0'
GROUPS = {
    911: '请求方法', 913: '扫描器识别', 920: '协议与请求格式', 921: '协议攻击',
    922: 'Multipart 攻击', 930: '本地文件包含', 931: '远程文件包含',
    932: '远程命令执行', 933: 'PHP 注入', 934: '通用应用攻击',
    941: '跨站脚本', 942: 'SQL 注入', 943: '会话固定', 944: 'Java 攻击',
    950: '响应数据泄露', 951: 'SQL 信息泄露', 952: 'Java 信息泄露',
    953: 'PHP 信息泄露', 954: 'IIS 信息泄露', 955: 'Web Shell',
    956: 'Ruby 信息泄露',
}
CORE = {901, 905, 949, 999, 959, 980}
ID = re.compile(r'(?i)\bid\s*:\s*(\d+)')
MSG = re.compile(r'(?i)\bmsg\s*:\s*[\'\"]([^\'\"]+)[\'\"]')
PL = re.compile(r'paranoia-level/([1-4])')


def directives(path):
    pending = ''
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        pending += ' ' + stripped.rstrip('\\').strip()
        if stripped.endswith('\\'):
            continue
        yield pending.strip()
        pending = ''
    if pending:
        raise ValueError(f'unfinished continuation in {path}')


def catalog():
    result = []
    seen = set()
    for path in sorted(RULES.glob('*.conf')):
        number = int(path.name.split('-', 2)[1])
        if number not in GROUPS and number not in CORE:
            raise ValueError(f'unclassified CRS file: {path.name}')
        for directive in directives(path):
            if not directive.startswith(('SecRule ', 'SecAction ')):
                continue
            match = ID.search(directive)
            if not match:
                continue
            rule_id = int(match.group(1))
            if rule_id in seen:
                raise ValueError(f'duplicate CRS rule ID: {rule_id}')
            seen.add(rule_id)
            msg = MSG.search(directive)
            pl = PL.search(directive)
            result.append({'id': rule_id, 'file': path.name, 'category': number,
                           'message': msg.group(1) if msg else '',
                           'paranoiaLevel': int(pl.group(1)) if pl else None,
                           'internal': number in CORE,
                           '_target': directive.split()[1] if directive.startswith('SecRule ') else ''})
    if not result:
        raise ValueError('no CRS rules found')
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    rules = catalog()
    names = json.loads(NAMES.read_text())
    ids = {str(row['id']) for row in rules}
    if set(names) != ids or any(not isinstance(names[id], str) or not re.search(r'[\u4e00-\u9fff]', names[id]) for id in ids):
        raise ValueError(f'Chinese names do not match CRS IDs; missing={sorted(ids-set(names))}, stale={sorted(set(names)-ids)}')
    duplicates = Counter(names[str(row['id'])] for row in rules if row['message'] and not row['internal'])
    targets = defaultdict(Counter)
    for row in rules:
        targets[names[str(row['id'])]][row['_target']] += 1
    for row in rules:
        name = names[str(row['id'])]
        target = row.pop('_target')
        if duplicates[name] > 1:
            if not target or targets[name][target] != 1:
                raise ValueError(f'rule {row["id"]} needs a distinct semantic Chinese name: {name}')
            name += f'（{target}）'
        row['nameZh'] = name
    files = [{'name': name, 'titleZh': GROUPS[int(name.split('-', 2)[1])]}
             for name in sorted({row['file'] for row in rules if not row['internal']})]
    output = json.dumps({'crsVersion': VERSION, 'files': files, 'rules': rules}, ensure_ascii=False, indent=2) + '\n'
    if args.check:
        if OUTPUT.read_text() != output:
            raise ValueError('generated catalog is stale')
    else:
        OUTPUT.write_text(output)


if __name__ == '__main__':
    main()
