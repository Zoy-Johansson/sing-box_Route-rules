#!/usr/bin/env python3
"""
convert_and_emit_v3.py
（相对于上一版，本文件在开始时会清空 --json-out 和 --srs-out 指定的目录，
以确保每次生成前旧文件被移除。其他逻辑保持：读取 source.txt，生成 v3 JSON，并用 sing-box 编译 .srs）
"""
import argparse
import os
import sys
import json
import csv
import requests
import yaml
import ipaddress
import subprocess
from glob import glob
from shutil import rmtree

#（为了简洁，这里保留之前的 normalize/parse/build 函数；按需直接复用上次给你的实现）
# 为避免重复，这里直接粘贴上次版本的关键函数（normalize_entry、parse_csv_like、try_parse_yaml、build_rules_from_rows 等）。
# —— 下面是上次完整实现（已过简化注释），请直接替换为你现有脚本中的实现体（或如果你没有，完整实现也在下面）

def is_ip_network(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except Exception:
        return False

def fetch_text(url_or_path):
    if os.path.exists(url_or_path):
        with open(url_or_path, 'r', encoding='utf-8') as f:
            return f.read()
    try:
        r = requests.get(url_or_path, timeout=30)
        r.raise_for_status()
        return r.text
    except Exception as e:
        print(f"[WARN] 无法读取 {url_or_path}: {e}")
        return ""

def parse_csv_like(text):
    rows = []
    reader = csv.reader(text.splitlines())
    for row in reader:
        if not row:
            continue
        if len(row) == 1:
            rows.append({"pattern": None, "address": row[0].strip(), "other": None})
        elif len(row) == 2:
            rows.append({"pattern": row[0].strip(), "address": row[1].strip(), "other": None})
        else:
            rows.append({"pattern": row[0].strip(), "address": row[1].strip(), "other": ",".join(col.strip() for col in row[2:])})
    return rows

def try_parse_yaml(text):
    try:
        data = yaml.safe_load(text)
        return data
    except Exception:
        return None

def normalize_entry(raw):
    entry = {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            entry[k] = v
        return entry
    s = str(raw).strip()
    if not s:
        return {}
    if "," in s and not s.startswith("http") and not s.startswith("https"):
        parts = [p.strip() for p in s.split(",")]
        key = parts[0].upper()
        val = parts[1] if len(parts) > 1 else ""
        other = parts[2] if len(parts) > 2 else None
        mapping = {
            'DOMAIN-SUFFIX':'domain_suffix', 'HOST-SUFFIX':'domain_suffix',
            'DOMAIN':'domain','HOST':'domain',
            'DOMAIN-KEYWORD':'domain_keyword','HOST-KEYWORD':'domain_keyword',
            'IP-CIDR':'ip_cidr','IP-CIDR6':'ip_cidr','IP6-CIDR':'ip_cidr',
            'SRC-IP-CIDR':'source_ip_cidr','GEOIP':'geoip','DST-PORT':'port',
            'SRC-PORT':'source_port','URL-REGEX':'domain_regex'
        }
        mapped = mapping.get(key, None)
        if mapped:
            entry[mapped] = val
            if other:
                entry.setdefault("meta", {})["other"] = other
            return entry
    prefixes = {
        "geosite:":"geosite:",
        "geoip:":"geoip:",
        "set:":"rule_set:",
        "rule-set:":"rule_set:",
        "proc_name:":"process_name:",
        "proc:":"process_name:",
        "process_name:":"process_name:",
        "proc_path:":"process_path:",
        "path:":"process_path:",
        "proc_path_regexp:":"process_path_regexp:",
        "proc_re:":"process_path_regexp:",
        "group:":"process_group:",
        "package:":"package_name:",
        "user:":"user:",
        "uid:":"user_id:",
        "mac:":"source_mac_address:",
        "hostname:":"source_hostname:",
        "ip:":"ip_cidr:",
        "port:":"port:",
        "ports:":"port_range:"
    }
    lower = s.lower()
    for p in prefixes:
        if lower.startswith(p):
            key = prefixes[p].rstrip(':')
            val = s[len(p):].strip()
            entry[key] = val
            return entry
    if is_ip_network(s):
        entry['ip_cidr'] = s
        return entry
    try:
        n = int(s)
        if 0 <= n <= 65535:
            entry['port'] = s
            return entry
    except Exception:
        pass
    if s.startswith('.') or s.startswith('+'):
        entry['domain_suffix'] = s.lstrip('+').lstrip('.')
        return entry
    if any(ch in s for ch in ['*', '^', '$', '\\', '.+']) and ('/' in s or 'regexp' in s.lower()):
        entry['domain_regex'] = s
        return entry
    if ' ' in s or s.count('.') == 0:
        entry['domain_keyword'] = s
    else:
        entry['domain'] = s
    return entry

def build_rules_from_rows(rows):
    result = {"version": 3, "rules": []}
    domain_list = []
    proc_names = []
    proc_paths = []
    proc_re = []
    process_groups = []
    package_names = []
    users = []
    user_ids = []
    rule_entries = []
    for r in rows:
        if isinstance(r, dict) and ('pattern' in r and 'address' in r):
            raw = r['address']
            other = r.get('other', None)
            parsed = normalize_entry(raw)
            if other:
                for tag in str(other).split(','):
                    p = tag.strip()
                    if not p:
                        continue
                    p_parsed = normalize_entry(p)
                    parsed.update(p_parsed)
        else:
            parsed = normalize_entry(r)
        if 'domain' in parsed:
            domain_list.append(parsed['domain'])
        if 'domain_suffix' in parsed:
            domain_list.append(parsed['domain_suffix'])
        if 'process_name' in parsed:
            if isinstance(parsed['process_name'], list):
                proc_names.extend(parsed['process_name'])
            else:
                proc_names.append(parsed['process_name'])
        if 'process_path' in parsed:
            proc_paths.append(parsed['process_path'])
        if 'process_path_regexp' in parsed:
            proc_re.append(parsed.get('process_path_regexp'))
        if 'process_group' in parsed:
            process_groups.append(parsed['process_group'])
        if 'package_name' in parsed:
            package_names.append(parsed['package_name'])
        if 'user' in parsed:
            users.append(parsed['user'])
        if 'user_id' in parsed:
            user_ids.append(parsed['user_id'])
        generic = {}
        for k,v in parsed.items():
            if k in {'domain','domain_suffix','process_name','process_path','process_path_regexp','process_group','package_name','user','user_id'}:
                continue
            generic[k] = v
        if generic:
            rule_entries.append(generic)
    def uniq_sorted(lst):
        return sorted(list({s for s in lst if s}))
    domain_list = uniq_sorted(domain_list)
    proc_names = uniq_sorted(proc_names)
    proc_paths = uniq_sorted(proc_paths)
    proc_re = uniq_sorted([x for x in proc_re if x])
    process_groups = uniq_sorted(process_groups)
    package_names = uniq_sorted(package_names)
    users = uniq_sorted(users)
    user_ids = uniq_sorted(user_ids)
    if domain_list:
        result['rules'].append({'domain': domain_list})
    if proc_names or proc_paths or proc_re or process_groups or package_names or users or user_ids:
        proc_rule = {}
        if proc_names:
            proc_rule['process_name'] = proc_names
        if proc_paths:
            proc_rule['process_path'] = proc_paths
        if proc_re:
            proc_rule['process_path_regexp'] = proc_re
        if process_groups:
            proc_rule['process_group'] = process_groups
        if package_names:
            proc_rule['package_name'] = package_names
        if users:
            proc_rule['user'] = users
        if user_ids:
            proc_rule['user_id'] = user_ids
        result['rules'].append(proc_rule)
    merged = []
    for g in rule_entries:
        found = False
        for m in merged:
            if set(m.keys()) == set(g.keys()):
                for k,v in g.items():
                    if k in m:
                        if isinstance(m[k], list):
                            if isinstance(v, list):
                                m[k].extend(v)
                            else:
                                m[k].append(v)
                        else:
                            m[k] = [m[k]] + ([v] if not isinstance(v, list) else v)
                    else:
                        m[k] = v
                found = True
                break
        if not found:
            merged.append(dict(g))
    for m in merged:
        for k,v in list(m.items()):
            if isinstance(v, list):
                m[k] = uniq_sorted(v)
    for m in merged:
        result['rules'].append(m)
    return result

def parse_source_entry_to_rows(entry_text):
    yaml_data = try_parse_yaml(entry_text)
    if isinstance(yaml_data, dict):
        items = yaml_data.get('payload') or yaml_data.get('data') or yaml_data.get('items') or []
        rows = []
        for it in items:
            rows.append({"pattern": None, "address": it, "other": None})
        return rows
    if isinstance(yaml_data, list):
        return [{"pattern": None, "address": it, "other": None} for it in yaml_data]
    if entry_text.startswith('http://') or entry_text.startswith('https://') or os.path.exists(entry_text):
        content = fetch_text(entry_text)
        first_line = content.splitlines()[0] if content.splitlines() else ""
        if ',' in first_line:
            return parse_csv_like(content)
        else:
            return [{"pattern": None, "address": ln, "other": None} for ln in content.splitlines() if ln.strip() and not ln.strip().startswith('#')]
    return parse_csv_like(entry_text)

def clean_directory(path):
    """
    删除目录下的所有内容，但保留目录本身。
    """
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
        return
    for entry in os.listdir(path):
        entry_path = os.path.join(path, entry)
        try:
            if os.path.isdir(entry_path):
                rmtree(entry_path)
            else:
                os.remove(entry_path)
        except Exception as e:
            print(f"[WARN] 无法删除 {entry_path}: {e}")

def main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--source', required=True, help='path to source.txt')
    p.add_argument('--json-out', default='./json', help='directory to write json files')
    p.add_argument('--srs-out', default='./srs', help='directory to write srs files')
    args = p.parse_args()

    # 在开始时清空旧文件（按你的新要求）
    try:
        clean_directory(args.json_out)
        clean_directory(args.srs_out)
        print(f"[INFO] cleaned output dirs: {args.json_out} , {args.srs_out}")
    except Exception as e:
        print(f"[WARN] cleaning output dirs failed: {e}")

    # 读取 source.txt
    try:
        with open(args.source, 'r', encoding='utf-8') as f:
            lines = [ln.strip() for ln in f.readlines() if ln.strip() and not ln.strip().startswith('#')]
    except Exception as e:
        print(f"[ERROR] 无法读取 source 文件 {args.source}: {e}")
        return 2

    for src in lines:
        try:
            rows = parse_source_entry_to_rows(src)
            v3_rules = build_rules_from_rows(rows)
            base = os.path.basename(src).split('?')[0].split('#')[0]
            if not base:
                base = "source"
            name = base.split('.')[0]
            json_path = os.path.join(args.json_out, f"{name}.json")
            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(v3_rules, jf, ensure_ascii=False, indent=2)
            print(f"[OK] 写入 JSON: {json_path}")
            srs_path = os.path.join(args.srs_out, f"{name}.srs")
            try:
                subprocess.run(["sing-box", "rule-set", "compile", "--output", srs_path, json_path], check=True)
                print(f"[OK] 编译 SRS: {srs_path}")
            except subprocess.CalledProcessError as e:
                print(f"[WARN] sing-box 编译失败: {e}. 跳过 srs 生成。")
        except Exception as e:
            print(f"[WARN] 处理 {src} 发生错误: {e}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
