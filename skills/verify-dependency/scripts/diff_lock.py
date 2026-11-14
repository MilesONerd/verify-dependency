#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""
Compares two lockfiles and lists ADDED, REMOVED and CHANGED dependencies,
including transitive ones (the ones you did not ask for but that come along).

Usage:
  diff_lock.py <old_lock> <new_lock> [--verify] [--max N]
  diff_lock.py --git <lockfile> [--base REF] [--verify] [--max N]
      compares the file on disk with its version at REF (default: HEAD); if the file
      does not exist at REF, everything is treated as "added".

  --verify   runs the registry check (check_dep.py, without the repository check)
             on every ADDED dependency and highlights the ones with alerts.
  --max N    limit on the number of dependencies checked (default 150).

Supported lockfiles (detected by file name):
  package-lock.json, npm-shrinkwrap.json, yarn.lock (v1 and berry), pnpm-lock.yaml (best effort),
  Cargo.lock, poetry.lock, uv.lock, requirements*.txt / pip freeze (only lines with ==),
  go.sum, composer.lock, Gemfile.lock
  *.json = pip report (`pip install --dry-run --report FILE ...`); compare it with `pip freeze > old.txt`

Python standard library only. Output: JSON on stdout.
The diff shows WHAT changed. It does not say whether it is safe: that takes human review.
"""
import sys, os, re, json, subprocess, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

NPM_REGISTRIES = ("https://registry.npmjs.org/", "https://registry.yarnpkg.com/")


def norm_py(n):
    return re.sub(r"[-_.]+", "-", n.lower())


class Lock:
    def __init__(self, eco, structured=False):
        self.eco = eco
        self.structured = structured  # True when the format is JSON: a successful parse with zero packages is a real result
        self.pkgs = {}   # name -> set(versions)
        self.notes = {}  # name -> [notes]

    def add(self, name, version, note=None):
        if not name or not version:
            return
        self.pkgs.setdefault(name, set()).add(str(version))
        if note:
            self.notes.setdefault(name, [])
            if note not in self.notes[name]:
                self.notes[name].append(note)


# ---------- parsers ----------
def p_npm_lock(text):
    L = Lock("npm", structured=True)
    d = json.loads(text)
    if d.get("packages"):
        for path, v in d["packages"].items():
            if not path or v.get("link"):
                continue
            name = v.get("name") or path.rsplit("node_modules/", 1)[-1]
            note = None
            if v.get("hasInstallScript"):
                note = "runs a script at install time (hasInstallScript)"
            res = v.get("resolved")
            if res and not res.startswith(NPM_REGISTRIES):
                note = (note + "; " if note else "") + f"source outside the npm registry: {res}"
            L.add(name, v.get("version"), note)
    else:
        def walk(deps):
            for n, v in (deps or {}).items():
                L.add(n, v.get("version"))
                walk(v.get("dependencies"))
        walk(d.get("dependencies"))
    return L


def p_yarn(text):
    L = Lock("npm")
    berry = "__metadata:" in text
    for block in re.split(r"\n\s*\n", text):
        lines = [l for l in block.splitlines() if l.strip() and not l.lstrip().startswith("#")]
        if not lines or lines[0].startswith(("__metadata", " ")):
            continue
        spec = lines[0].rstrip(":").split(",")[0].strip().strip('"')
        at = spec.find("@", 1)  # first '@' after the optional scope marker
        if at < 0 or re.search(r"@(workspace|link|portal):", spec):
            continue  # not a registry package (berry workspaces and local links)
        name = spec[:at]
        m = re.search(r'^\s+version:? "?([^"\s]+)"?', block, re.M)
        if m and name and not m.group(1).startswith("0.0.0-use.local"):
            L.add(name, m.group(1))
    return L


def p_pnpm(text):
    """pnpm-lock.yaml. v5 keys look like '/name/1.0.0_peer@1', v6 like '/name@1.0.0(peer@1)', v9 like 'name@1.0.0'."""
    L = Lock("npm")
    m = re.search(r"^lockfileVersion:\s*['\"]?(\d+)", text, re.M)
    major = int(m.group(1)) if m else 9
    in_pk = False
    for line in text.splitlines():
        if re.match(r"^packages:\s*$", line):
            in_pk = True
            continue
        if in_pk and re.match(r"^\S", line):
            in_pk = False
        if not in_pk:
            continue
        if major <= 5:
            mm = re.match(r"^  /(@[^/\s:]+/[^/\s:]+|[^/\s:@]+)/(\d[^:\s_(]*)", line)
        else:
            mm = re.match(r"^  '?/?(@[^@\s'/]+/[^@\s'/]+|[^@\s'/]+)@(\d[^:\s'()]*)", line)
        if mm:
            L.add(mm.group(1), mm.group(2))
    return L


def _toml_blocks(text, eco, keep):
    L = Lock(eco)
    for block in text.split("[[package]]")[1:]:
        n = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
        v = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
        src = re.search(r"^source\s*=\s*(.+)$", block, re.M)
        if not (n and v) or not keep(src.group(1) if src else None):
            continue
        note = None
        if src and "git" in src.group(1) and eco == "crates":
            note = f"git source: {src.group(1).strip()}"
        L.add(norm_py(n.group(1)) if eco == "pypi" else n.group(1), v.group(1), note)
    return L


def p_cargo(text):
    return _toml_blocks(text, "crates", lambda src: src is not None)  # no 'source' = workspace member


def p_pylock(text):
    return _toml_blocks(text, "pypi", lambda src: not (src and re.search(r"editable|virtual", src)))


def p_requirements(text):
    L = Lock("pypi")
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;\\]+)", line)
        if m:
            L.add(norm_py(m.group(1)), m.group(2))
    return L


def p_gosum(text):
    L = Lock("go")
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            L.add(parts[0], parts[1])
    return L


def p_composer(text):
    L = Lock("packagist", structured=True)
    d = json.loads(text)
    for key in ("packages", "packages-dev"):
        for p in d.get(key) or []:
            L.add(p.get("name"), p.get("version"))
    return L


def p_gemfile(text):
    L = Lock("gem")
    for line in text.splitlines():
        m = re.match(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)$", line)
        if m:
            L.add(m.group(1), m.group(2))
    return L


def p_pip_report(text):
    """Report from `pip install --dry-run --report FILE ...` (JSON with an "install" key)."""
    L = Lock("pypi", structured=True)
    d = json.loads(text)
    if "install" not in d:
        raise ValueError("JSON without an 'install' key (not a pip report)")
    for item in d["install"]:
        m = item.get("metadata") or {}
        L.add(norm_py(m.get("name", "")), m.get("version"))
    return L


def parser_for(path):
    b = os.path.basename(path).lower()
    if b in ("package-lock.json", "npm-shrinkwrap.json"):
        return p_npm_lock
    if b == "yarn.lock":
        return p_yarn
    if b == "pnpm-lock.yaml":
        return p_pnpm
    if b == "cargo.lock":
        return p_cargo
    if b in ("poetry.lock", "uv.lock"):
        return p_pylock
    if b.endswith(".txt"):  # requirements*.txt or `pip freeze` output
        return p_requirements
    if b == "go.sum":
        return p_gosum
    if b.endswith(".json") and b not in ("composer.lock",):
        return p_pip_report
    if b == "composer.lock":
        return p_composer
    if b == "gemfile.lock":
        return p_gemfile
    return None


# ---------- diff ----------
def diff(old, new):
    added, removed, changed = [], [], []
    for name in sorted(new.pkgs):
        if name not in old.pkgs:
            added.append({"name": name, "versions": sorted(new.pkgs[name]), "notes": new.notes.get(name, [])})
        elif new.pkgs[name] != old.pkgs[name]:
            changed.append({"name": name, "from": sorted(old.pkgs[name]), "to": sorted(new.pkgs[name]),
                            "notes": new.notes.get(name, [])})
    for name in sorted(old.pkgs):
        if name not in new.pkgs:
            removed.append({"name": name, "versions": sorted(old.pkgs[name])})
    return added, removed, changed


def _git(args, cwd):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=30)


def git_show(path, ref):
    """Returns (text, error). text is None with no error when the file does not exist at ref."""
    d, b = os.path.dirname(os.path.abspath(path)), os.path.basename(path)
    try:
        inside = _git(["rev-parse", "--is-inside-work-tree"], d)
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return None, "not inside a git repository"
        if _git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], d).returncode != 0:
            return None, f"unknown git ref: {ref}"
        r = _git(["show", f"{ref}:./{b}"], d)
    except (OSError, subprocess.SubprocessError) as e:
        return None, f"git is not available: {e}"
    return (r.stdout if r.returncode == 0 else None), None


def fail(msg):
    print(json.dumps({"status": "error", "error": msg}, ensure_ascii=False))
    sys.exit(2)


def read_text(path):
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as e:
        fail(f"cannot read {path}: {e}")


def parse_old(text, parse, alt_parse, eco):
    """Reads the old lockfile with the new file's parser; if that fails or finds nothing in an unstructured
    format, tries the parser matching the old file's name. An empty JSON lockfile is a valid result."""
    if not text.strip():
        return Lock(eco)
    first = None
    try:
        first = parse(text)
        if first.pkgs or first.structured:
            return first
    except ValueError:
        pass
    if alt_parse and alt_parse is not parse:
        try:
            return alt_parse(text)
        except ValueError:
            if first is not None:
                return first
            raise
    return first or Lock(eco)


def verify(eco, added, limit):
    import check_dep
    checked = 0
    for a in added:
        if checked >= limit:
            a["verification"] = {"status": "skipped", "reason": f"--max limit of {limit} reached"}
            continue
        checked += 1
        res, _ = check_dep.check(eco, a["name"], repo=False)
        v = {"status": res["status"], "signals": res.get("signals")}
        if res["status"] == "found":
            r = res["registry"]
            v.update(version=r.get("version"), created=r.get("created"), maintainers=r.get("maintainers"),
                     flags=[f["code"] for f in res["flags"] if f["level"] in ("high", "medium")],
                     maintenance=[f["code"] for f in res["flags"] if f["level"] == "maintenance"])
        elif res["status"] == "not_found":
            v["flags"] = ["NOT_FOUND"]
        else:
            v["error"] = res.get("error")
        a["verification"] = v
        time.sleep(0.05)


def main():
    argv = sys.argv[1:]
    if not argv or "-h" in argv or "--help" in argv:
        print(__doc__)
        sys.exit(2)
    do_verify = "--verify" in argv
    limit = 150
    base = "HEAD"
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--max":
            limit = int(argv[i + 1]); i += 2; continue
        if a == "--base":
            base = argv[i + 1]; i += 2; continue
        if not a.startswith("--"):
            pos.append(a)
        i += 1

    old_parse = None
    if "--git" in argv:
        if len(pos) != 1:
            print(__doc__); sys.exit(2)
        new_path = pos[0]
        new_text = read_text(new_path)
        old_text, err = git_show(new_path, base)
        if err:
            fail(err)
        old_missing = old_text is None
        old_text = old_text or ""
    else:
        if len(pos) != 2:
            print(__doc__); sys.exit(2)
        old_path, new_path = pos
        old_text, new_text, old_missing = read_text(old_path), read_text(new_path), False
        old_parse = parser_for(old_path)  # only used as a fallback (see parse_old)

    parse = parser_for(new_path)
    if not parse:
        print(json.dumps({"status": "error", "error": f"unsupported lockfile: {os.path.basename(new_path)}"}, ensure_ascii=False))
        sys.exit(2)
    try:
        new = parse(new_text)
        old = parse_old(old_text, parse, old_parse, new.eco)
    except ValueError as e:
        print(json.dumps({"status": "error", "error": f"failed to read lockfile: {e}"}, ensure_ascii=False))
        sys.exit(2)

    if old.pkgs and old.eco != new.eco:
        print(json.dumps({"status": "error", "error": f"different ecosystems: {old.eco} vs {new.eco}"}, ensure_ascii=False))
        sys.exit(2)
    added, removed, changed = diff(old, new)
    res = {"status": "ok", "ecosystem": new.eco, "lockfile": os.path.basename(new_path),
           "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)}}
    warnings = []
    if new_text.strip() and not new.pkgs and not new.structured:
        warnings.append("parsed 0 packages from a non-empty new lockfile: it may have no dependencies, or this format version is unsupported")
    if old_text.strip() and not old.pkgs and not old.structured:
        warnings.append("parsed 0 packages from a non-empty old lockfile: the comparison may be incomplete")
    if warnings:
        res["parse_warning"] = warnings
    if old_missing:
        res["note"] = f"lockfile not found at {base}: all dependencies appear as added."
    if os.path.basename(new_path).lower() == "pnpm-lock.yaml":
        res["parse_quality"] = "best_effort"
    if do_verify:
        verify(new.eco, added, limit)
        res["needs_attention"] = [a["name"] for a in added
                                  if (a.get("verification") or {}).get("signals") in ("attention", "strong_alerts")]
        res["not_found"] = [a["name"] for a in added if (a.get("verification") or {}).get("status") == "not_found"]
        res["verification_errors"] = [a["name"] for a in added if (a.get("verification") or {}).get("status") == "error"]
        res["verification_note"] = ("Registry-only check (no repository check). Signals are indicators, not proof of security. "
                                    "Manually review the ones that need attention and the ones that carry 'notes'.")
    res.update(added=added, changed=changed, removed=removed)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    sys.exit(0)


if __name__ == "__main__":
    main()
