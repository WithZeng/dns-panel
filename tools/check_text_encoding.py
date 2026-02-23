#!/usr/bin/env python3
import argparse
import pathlib
import re
import sys

SUSPECT_PATTERNS = [
    re.compile(r"鈹"),
    re.compile(r"锛"),
    re.compile(r"鎿"),
    re.compile(r"鍙"),
    re.compile(r"\uFFFD"),
    re.compile(r"\?\?\?+"),
]

DEFAULT_EXTS = {".py", ".html", ".md", ".sh", ".ps1", ".toml", ".yml", ".yaml", ".txt"}
IGNORE_DIRS = {".git", ".venv", "__pycache__", "komari-1.1.7"}


def should_scan(path: pathlib.Path) -> bool:
    if path.suffix.lower() not in DEFAULT_EXTS:
        return False
    for p in path.parts:
        if p in IGNORE_DIRS:
            return False
    return True


def scan_file(path: pathlib.Path):
    issues = []
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{path}: 非 UTF-8 编码"]

    for idx, line in enumerate(text.splitlines(), start=1):
        for pat in SUSPECT_PATTERNS:
            if pat.search(line):
                issues.append(f"{path}:{idx}: 疑似乱码 -> {line[:120]}")
                break
    return issues


def main():
    parser = argparse.ArgumentParser(description="检查项目中文乱码")
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()

    root = pathlib.Path(args.root).resolve()
    all_issues = []
    for path in root.rglob("*"):
        if path.is_file() and should_scan(path):
            all_issues.extend(scan_file(path))

    if all_issues:
        print("发现疑似乱码：")
        for item in all_issues:
            safe = item.encode('utf-8', 'backslashreplace').decode('utf-8', 'replace')
            sys.stdout.buffer.write((safe + "\n").encode('utf-8', 'replace'))
        sys.exit(1)

    print("检查完成：未发现疑似乱码。")


if __name__ == "__main__":
    main()
