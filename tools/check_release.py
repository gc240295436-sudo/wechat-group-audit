"""Check the files about to be published, without reading user data directories."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def files():
    # A skill installed under a user's dotfiles checkout is not itself that
    # repository. In that case inspect its own files instead of an empty index.
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, capture_output=True, text=True)
        if top.returncode == 0 and Path(top.stdout.strip()).resolve() == ROOT.resolve():
            process = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
            return [ROOT / p.decode("utf-8") for p in process.stdout.split(b"\0") if p]
    except OSError:
        pass
    ignored = {".git", ".venv", "__pycache__", "build", "dist"}
    return [p for p in ROOT.rglob("*") if p.is_file() and not any(part in ignored or part.endswith(".egg-info") for part in p.relative_to(ROOT).parts)]


def main():
    issues = []
    forbidden_modules = {"snapshot_reader", "windows_native", "windows_live", "windows_keyscan", "vault_cli", "contact_source", "group_audit"}
    secret_patterns = [re.compile(r"github_pat_[A-Za-z0-9_]{30,}"), re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
                       re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
                       re.compile(r"wxid_[a-z0-9]{10,}_[a-f0-9]{4}")]
    checked = files()
    for path in checked:
        relative = path.relative_to(ROOT).as_posix()
        lower = path.name.casefold()
        if path.is_symlink() or path.suffix in (".db", ".sqlite", ".sqlite3", ".pyc") or ".db-" in lower or lower.startswith(".env"):
            issues.append(relative + ": private/binary artifact")
            continue
        if path.stat().st_size > 1_000_000:
            issues.append(relative + ": unexpected large file")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            issues.append(relative + ": unexpected non-UTF-8 content")
            continue
        if any(pattern.search(content) for pattern in secret_patterns):
            issues.append(relative + ": possible credential or personal account directory")
        if path.suffix == ".py":
            tree = ast.parse(content, filename=relative)
            for node in ast.walk(tree):
                names = [n.name.split(".")[0] for n in node.names] if isinstance(node, ast.Import) else [node.module.split(".")[0]] if isinstance(node, ast.ImportFrom) and node.module else []
                if forbidden_modules.intersection(names):
                    issues.append(relative + ": dependency on a restricted implementation")
        if path.suffix == ".json":
            data = json.loads(content)
            if isinstance(data, dict) and data.get("schema") == "wga-report/1":
                issues.append(relative + ": personal report must not be published")
            if isinstance(data, dict) and data.get("schema") == "wga-directory/1":
                if relative != "examples/directory.json" or not all(row["id"].startswith("demo-") for row in data["contacts"] + data["groups"]):
                    issues.append(relative + ": only the checked synthetic directory may be published")
    lock = json.loads((ROOT / "LICENSES/wcdb-source.json").read_text(encoding="utf-8"))
    for relative, expected in lock["published_files"].items():
        digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        if digest != expected:
            issues.append(relative + ": vendor/license content differs from its pinned digest")
    if not (ROOT / "LICENSE").read_text(encoding="utf-8").startswith("MIT License"):
        issues.append("LICENSE: missing project license")
    if issues:
        print("\n".join(issues), file=sys.stderr)
        return 1
    print(f"Publication checks passed: {len(checked)} files; no reports, credentials, or restricted imports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
