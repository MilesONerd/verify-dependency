#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Enzo (MilesONerd)
"""
Checks a dependency against public registries and cross-checks it with its repository.

Usage:   python3 check_dep.py <ecosystem> <name> [--no-repo] [--version X]
Examples:
  python3 check_dep.py npm express
  python3 check_dep.py pypi requests
  python3 check_dep.py crates serde
  python3 check_dep.py maven org.apache.commons:commons-lang3

Ecosystems: npm, pypi, crates, gem, nuget, go, packagist, aur, hex, pub, maven
Options: --no-repo     skip the repository check (useful when checking many dependencies at once).
         --version X   evaluate release timing for version X instead of the latest one.
Output: JSON on stdout. Exit code: 0 = found, 1 = does not exist, 2 = network error / inconclusive.
The "signals" field summarizes automatic signals (no_alerts / attention / strong_alerts).
It is NOT a security certification.
Flag levels: high and medium (supply-chain signals, they change "signals"), maintenance (stale,
archived, deprecated: informational, they do NOT change "signals") and info (limits of the check).
Optional: GITHUB_TOKEN in the environment raises the GitHub API rate limit.
Python standard library only.
"""
import sys, json, re, os, signal, base64
import urllib.request, urllib.error, urllib.parse
from datetime import datetime, timezone

if hasattr(signal, "SIGPIPE"):
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

UA = "verify-dependency-skill/1.0"
TIMEOUT = 15
q = urllib.parse.quote


class NetErr(Exception):
    pass


# The only hosts this script ever fetches from. Anything else is refused BEFORE a request is made, and a redirect to
# any other host (or to plain http) is refused too: package metadata is attacker-influenced, so a URL taken from it
# must never decide where we connect.
FETCH_HOSTS = frozenset({
    "registry.npmjs.org", "api.npmjs.org", "pypi.org", "pypistats.org", "crates.io", "rubygems.org",
    "azuresearch-usnc.nuget.org", "proxy.golang.org", "packagist.org", "aur.archlinux.org", "hex.pm", "pub.dev",
    "search.maven.org", "api.github.com", "raw.githubusercontent.com", "github.com",
})
ALLOWED_SCHEMES = ("https",)
ALLOWED_PORTS = (None, 443)


def _allowed(url):
    p = urllib.parse.urlparse(url)
    try:
        port = p.port
    except ValueError:
        return False
    return p.scheme in ALLOWED_SCHEMES and (p.hostname or "").lower() in FETCH_HOSTS and port in ALLOWED_PORTS and not p.username


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _allowed(newurl):
            raise urllib.error.URLError(f"redirect to a URL that is not allowed: {newurl[:80]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirect())


def get(url, as_json=True, headers=None):
    """Returns (status, body). 404/410 -> (404, None). Network failure or HTTP error other than 404 -> NetErr."""
    h = {"User-Agent": UA, "Accept": "application/json" if as_json else "*/*"}
    if headers:
        h.update(headers)
    if not _allowed(url):
        raise NetErr(f"refusing to fetch {url[:80]}: not an https URL on an allowed registry or forge host")
    try:
        with _OPENER.open(urllib.request.Request(url, headers=h), timeout=TIMEOUT) as r:
            body = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return 404, None
        why = e.headers.get("x-deny-reason") if e.headers else None
        raise NetErr(f"HTTP {e.code} for {url}" + (f" (x-deny-reason: {why})" if why else ""))
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NetErr(f"{url}: {e}")
    if as_json:
        try:
            return 200, json.loads(body)
        except ValueError:
            raise NetErr(f"non-JSON response from {url}")
    return 200, body


# ---------- utilities ----------
def to_dt(ts):
    if ts is None:
        return None
    try:
        if isinstance(ts, (int, float)):
            ts = ts / 1000 if ts > 1e11 else ts
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        return datetime.strptime(str(ts)[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def iso(dt):
    return dt.strftime("%Y-%m-%d") if dt else None


def age_days(dt):
    return (datetime.now(timezone.utc) - dt).days if dt else None


def norm(n):
    return re.sub(r"[-_.]+", "-", str(n).lower())


def lev(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# Registries that treat case and the separators - _ . as the same name (so "Flask" and "flask" are one package).
NORMALIZING = ("pypi", "crates")
_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def skeleton(n):
    """Collapses separators and common look-alike characters so that 'body_parser', 'vvs' and 'rnoment' compare equal to 'body-parser', 'ws' and 'moment'."""
    n = n.lower()
    for a, b in _CONFUSABLES:
        n = n.replace(a, b)
    return re.sub(r"[-_.]", "", n.translate(str.maketrans("01", "ol")))


def earliest(pairs):
    """{version: earliest timestamp} from (version, timestamp) pairs, ignoring empty values."""
    out = {}
    for v, ts in pairs:
        if v and ts and (v not in out or str(ts) < str(out[v])):
            out[v] = ts
    return out


def release_dates(info, version):
    """(published, previous_release) as datetimes for `version`, or (None, None) when the registry gave no dates."""
    rt = info.get("release_times") or {}
    cur = to_dt(rt.get(version))
    if not cur:
        return None, None
    prev = max((d for d in (to_dt(t) for v, t in rt.items() if v != version) if d and d < cur), default=None)
    return cur, prev


HOSTS = r"github\.com|gitlab\.com|codeberg\.org|bitbucket\.org|sr\.ht|sourcehut"


def pick_repo(*urls):
    for u in urls:
        if u and re.search(HOSTS, str(u)):
            return str(u)
    return None


def mk(**kw):
    base = dict(version=None, created=None, modified=None, n_versions=None, repo=None, repo_dir=None,
                homepage=None, license=None, description=None, maintainers=None, deprecated=None,
                install_scripts=None, adoption=None, release_times=None, publishers=None, attestation_urls=None, integrity=None, notes=[])
    base.update(kw)
    return base


# ---------- registries ----------
def r_npm(name):
    path = q(name, safe="@")
    s, d = get(f"https://registry.npmjs.org/{path}")
    if s == 404:
        return None
    latest = (d.get("dist-tags") or {}).get("latest")
    v = (d.get("versions") or {}).get(latest, {})
    t = d.get("time") or {}
    repo = d.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else repo
    repo_dir = repo.get("directory") if isinstance(repo, dict) else None
    scripts = v.get("scripts") or {}
    inst = [k for k in ("preinstall", "install", "postinstall") if k in scripts]
    adoption = None
    try:
        s2, d2 = get(f"https://api.npmjs.org/downloads/point/last-week/{path}")
        if d2 and "downloads" in d2:
            adoption = ("weekly downloads (npm)", d2["downloads"], 1000)
    except NetErr:
        pass
    vers = d.get("versions") or {}
    return mk(release_times=earliest((v, t.get(v)) for v in vers),
              publishers={v: (m.get("_npmUser") or {}).get("name") for v, m in vers.items()},
              attestation_urls={v: ((m.get("dist") or {}).get("attestations") or {}).get("url") for v, m in vers.items()},
              integrity={v: (m.get("dist") or {}).get("integrity") for v, m in vers.items()},
              version=latest, created=t.get("created"), modified=t.get("modified"),
              n_versions=len(d.get("versions") or {}), repo=repo_url, repo_dir=repo_dir,
              homepage=d.get("homepage"), license=v.get("license") or d.get("license"),
              description=d.get("description"),
              maintainers=[m.get("name") for m in d.get("maintainers", [])],
              deprecated=v.get("deprecated"), install_scripts=inst or None, adoption=adoption,
              url=f"https://www.npmjs.com/package/{name}")


def r_pypi(name):
    n = norm(name)
    s, d = get(f"https://pypi.org/pypi/{q(n)}/json")
    if s == 404:
        return None
    info, rel = d["info"], d.get("releases") or {}
    times = [f["upload_time"] for fl in rel.values() for f in fl if f.get("upload_time")]
    urls = info.get("project_urls") or {}
    adoption = None
    try:
        s2, d2 = get(f"https://pypistats.org/api/packages/{q(n)}/recent")
        if d2:
            adoption = ("weekly downloads (PyPI)", d2["data"]["last_week"], 1000)
    except (NetErr, KeyError):
        pass
    lic = info.get("license") or ""
    return mk(release_times=earliest((v, min((f["upload_time"] for f in fl if f.get("upload_time")), default=None)) for v, fl in rel.items()),
              version=info.get("version"), created=min(times) if times else None,
              modified=max(times) if times else None, n_versions=len(rel),
              repo=pick_repo(*urls.values(), info.get("home_page")),
              homepage=info.get("home_page") or urls.get("Homepage"),
              license=(lic[:80] or None), description=info.get("summary"),
              maintainers=[x for x in (info.get("author"), info.get("maintainer")) if x],
              deprecated="release is marked as yanked" if info.get("yanked") else None,
              adoption=adoption, url=f"https://pypi.org/project/{n}/",
              notes=["The install name (pip) may differ from the import name."])


def r_crates(name):
    s, d = get(f"https://crates.io/api/v1/crates/{q(name)}")
    if s == 404:
        return None
    c, vs = d["crate"], d.get("versions") or []
    return mk(release_times=earliest((v.get("num"), v.get("created_at")) for v in vs),
              publishers={v.get("num"): (v.get("published_by") or {}).get("login") for v in vs},
              version=c.get("max_stable_version") or c.get("max_version"), created=c.get("created_at"),
              modified=c.get("updated_at"), n_versions=len(vs), repo=c.get("repository"),
              homepage=c.get("homepage"), license=vs[0].get("license") if vs else None,
              description=c.get("description"),
              deprecated="latest version is yanked" if vs and vs[0].get("yanked") else None,
              adoption=("total downloads (crates.io)", c.get("downloads"), 5000),
              url=f"https://crates.io/crates/{name}")


def r_gem(name):
    s, d = get(f"https://rubygems.org/api/v1/gems/{q(name)}.json")
    if s == 404:
        return None
    s2, vs = get(f"https://rubygems.org/api/v1/versions/{q(name)}.json")
    vs = vs or []
    times = [v["created_at"] for v in vs if v.get("created_at")]
    return mk(release_times=earliest((v.get("number"), v.get("created_at")) for v in vs),
              version=d.get("version"), created=min(times) if times else None,
              modified=max(times) if times else None, n_versions=len(vs),
              repo=pick_repo(d.get("source_code_uri"), d.get("homepage_uri")),
              homepage=d.get("homepage_uri"), license=",".join(d.get("licenses") or []) or None,
              description=d.get("info"), maintainers=[d.get("authors")] if d.get("authors") else None,
              adoption=("total downloads (RubyGems)", d.get("downloads"), 10000),
              url=f"https://rubygems.org/gems/{name}")


def r_nuget(name):
    s, d = get(f"https://azuresearch-usnc.nuget.org/query?q={q('packageid:' + name)}&prerelease=true&take=5")
    m = next((x for x in d.get("data", []) if x["id"].lower() == name.lower()), None)
    if not m:
        return None
    notes = ["The NuGet search API does not return a publication date; check the package page."]
    if m.get("verified"):
        notes.append("Prefixo de ID reservado/verificado no NuGet (sinal positivo).")
    return mk(version=m.get("version"), n_versions=len(m.get("versions") or []),
              repo=pick_repo(m.get("projectUrl")), homepage=m.get("projectUrl"),
              description=m.get("description"), maintainers=m.get("owners") or m.get("authors"),
              adoption=("total downloads (NuGet)", m.get("totalDownloads"), 10000),
              url=f"https://www.nuget.org/packages/{m['id']}", notes=notes)


def r_go(name):
    esc = re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)
    s, d = get(f"https://proxy.golang.org/{esc}/@latest")
    if s == 404:
        return None
    s2, lst = get(f"https://proxy.golang.org/{esc}/@v/list", as_json=False)
    mm = re.match(r"(github\.com|gitlab\.com|codeberg\.org)/([^/]+)/([^/]+)", name)
    return mk(version=d.get("Version"), modified=d.get("Time"),
              n_versions=len((lst or "").split()) if lst is not None else None,
              repo=f"https://{mm.group(1)}/{mm.group(2)}/{mm.group(3)}" if mm else None,
              url=f"https://pkg.go.dev/{name}",
              notes=["If a subpackage path comes back as not found, try the root module (the repo's go.mod)."])


def r_packagist(name):
    s, d = get(f"https://packagist.org/packages/{q(name, safe='/')}.json")
    if s == 404:
        return None
    p = d["package"]
    vs = p.get("versions") or {}
    k = next((x for x in vs if not x.startswith("dev-") and not x.endswith("-dev")), None)
    return mk(release_times=earliest((ver, (meta or {}).get("time")) for ver, meta in vs.items()
                                     if not ver.startswith("dev-") and not ver.endswith("-dev")),
              version=k, created=p.get("time"), n_versions=len(vs), repo=p.get("repository"),
              license=",".join(vs.get(k, {}).get("license") or []) or None, description=p.get("description"),
              maintainers=[m.get("name") for m in p.get("maintainers", [])],
              deprecated=f"abandoned: {p['abandoned']}" if p.get("abandoned") else None,
              adoption=("total downloads (Packagist)", (p.get("downloads") or {}).get("total"), 5000),
              url=f"https://packagist.org/packages/{name}")


def r_aur(name):
    s, d = get(f"https://aur.archlinux.org/rpc/v5/info?arg%5B%5D={q(name)}")
    if not d or not d.get("results"):
        return None
    r = d["results"][0]
    notes = ["The AUR is unreviewed user-submitted content: read the PKGBUILD (and .install) before installing.",
             "Also check whether the package exists in the official repositories (extra/core) before using the AUR."]
    if r.get("Maintainer") is None:
        notes.append("Orphaned package (no maintainer).")
    return mk(version=r.get("Version"), created=r.get("FirstSubmitted"), modified=r.get("LastModified"),
              repo=pick_repo(r.get("URL")), homepage=r.get("URL"), license=",".join(r.get("License") or []) or None,
              description=r.get("Description"), maintainers=[r["Maintainer"]] if r.get("Maintainer") else [],
              deprecated="flagged out of date (OutOfDate)" if r.get("OutOfDate") else None,
              adoption=("votes (AUR)", r.get("NumVotes"), 10), url=f"https://aur.archlinux.org/packages/{name}",
              notes=notes)


def r_hex(name):
    s, d = get(f"https://hex.pm/api/packages/{q(name)}")
    if s == 404:
        return None
    meta = d.get("meta") or {}
    return mk(release_times=earliest((r.get("version"), r.get("inserted_at")) for r in (d.get("releases") or [])),
              version=d.get("latest_stable_version") or d.get("latest_version"), created=d.get("inserted_at"),
              modified=d.get("updated_at"), n_versions=len(d.get("releases") or []),
              repo=pick_repo(*(meta.get("links") or {}).values()), license=",".join(meta.get("licenses") or []) or None,
              description=meta.get("description"),
              maintainers=[o.get("username") for o in d.get("owners", [])] or None,
              adoption=("total downloads (Hex)", (d.get("downloads") or {}).get("all"), 5000),
              url=f"https://hex.pm/packages/{name}")


def r_pub(name):
    s, d = get(f"https://pub.dev/api/packages/{q(name)}")
    if s == 404:
        return None
    lat, vs = d["latest"], d.get("versions") or []
    ps = lat.get("pubspec") or {}
    pubs = [v["published"] for v in vs if v.get("published")]
    return mk(release_times=earliest((v.get("version"), v.get("published")) for v in vs),
              version=lat.get("version"), created=min(pubs) if pubs else None, modified=lat.get("published"),
              n_versions=len(vs), repo=pick_repo(ps.get("repository"), ps.get("homepage")),
              homepage=ps.get("homepage"), description=ps.get("description"),
              deprecated="discontinued" if d.get("isDiscontinued") else None,
              url=f"https://pub.dev/packages/{name}")


def r_maven(name):
    if ":" not in name:
        raise NetErr("Maven requires 'groupId:artifactId'")
    g, a = name.split(":", 1)
    s, d = get("https://search.maven.org/solrsearch/select?wt=json&rows=1&q=" + q(f'g:"{g}" AND a:"{a}"'))
    resp = (d or {}).get("response") or {}
    if not resp.get("numFound"):
        return None
    doc = resp["docs"][0]
    return mk(version=doc.get("latestVersion"), modified=doc.get("timestamp"), n_versions=doc.get("versionCount"),
              url=f"https://central.sonatype.com/artifact/{g}/{a}",
              notes=["Maven Central does not expose the repository or license in this API: open the POM and check <scm>."])


REGISTRIES = {"npm": r_npm, "pypi": r_pypi, "crates": r_crates, "gem": r_gem, "nuget": r_nuget, "go": r_go,
              "packagist": r_packagist, "aur": r_aur, "hex": r_hex, "pub": r_pub, "maven": r_maven}
ALIASES = {"node": "npm", "yarn": "npm", "pnpm": "npm", "pip": "pypi", "python": "pypi", "cargo": "crates",
           "rust": "crates", "rubygems": "gem", "ruby": "gem", "dotnet": "nuget", "golang": "go",
           "composer": "packagist", "php": "packagist", "mix": "hex", "elixir": "hex", "dart": "pub",
           "flutter": "pub", "gradle": "maven", "java": "maven"}

POPULAR = {
    "npm": "react react-dom express lodash axios moment chalk commander debug typescript webpack eslint prettier jest vue next tailwindcss dotenv uuid request async underscore jquery mongoose cors body-parser socket.io zod vite rxjs yargs minimist glob rimraf mkdirp semver colors inquirer ws node-fetch nodemon passport jsonwebtoken bcrypt redux".split(),
    "pypi": "requests numpy pandas flask django pytest scipy boto3 urllib3 setuptools pip pillow matplotlib sqlalchemy pydantic fastapi httpx aiohttp beautifulsoup4 lxml pyyaml cryptography click jinja2 tensorflow torch scikit-learn openai anthropic transformers selenium colorama python-dotenv uvicorn celery redis psycopg2 black tqdm rich".split(),
    "crates": "serde serde_json tokio rand clap regex anyhow thiserror reqwest hyper axum tracing log env_logger syn quote itertools once_cell lazy_static futures chrono uuid bytes rayon libc tempfile bitflags async-trait diesel sqlx ratatui crossterm nix".split(),
    "gem": "rails rack rspec nokogiri devise sidekiq puma bundler rake".split(),
}


# Built-in module names: installing a third-party package with the same name is almost never what you want.
NODE_BUILTINS = set("""assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns
domain events fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl
stream string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib""".split())


def stdlib_names(eco):
    if eco == "npm":
        return NODE_BUILTINS
    if eco == "pypi":
        return set(getattr(sys, "stdlib_module_names", ())) or set(
            "os sys json re math time datetime random string typing pathlib subprocess logging asyncio collections itertools functools "
            "sqlite3 http urllib socket threading multiprocessing argparse csv hashlib base64 uuid decimal enum dataclasses abc io shutil "
            "tempfile glob copy pickle zipfile tarfile gzip email html xml unittest".split())
    return set()


# ---------- repository ----------
def parse_repo(url):
    u = str(url).strip()
    u = re.sub(r"^git\+", "", u)
    u = re.sub(r"^github:", "https://github.com/", u)
    u = re.sub(r"^(git|ssh)://(git@)?", "https://", u)
    u = re.sub(r"^git@([^:]+):", r"https://\1/", u)
    if re.match(r"^[\w.-]+/[\w.-]+$", u):
        u = "https://github.com/" + u
    m = re.match(r"https?://(?:www\.)?([^/]+)/([^/]+)/([^/#?]+)", u)
    if not m:
        return None
    return m.group(1).lower(), m.group(2), re.sub(r"\.git$", "", m.group(3))


def manifest_matches(eco, owner, repo, directory, pkg):
    fname = {"npm": "package.json", "crates": "Cargo.toml", "pypi": "pyproject.toml"}.get(eco)
    if not fname:
        return None
    path = f"{directory.strip('/')}/{fname}" if directory else fname
    try:
        s, t = get(f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}", as_json=False)
    except NetErr:
        return None
    if s == 404:
        return None
    found = None
    if eco == "npm":
        try:
            found = json.loads(t).get("name")
        except ValueError:
            return None
    else:
        m = re.search(r"^\s*name\s*=\s*[\"']([^\"']+)[\"']", t, re.M)
        found = m.group(1) if m else None
    return None if not found else (norm(found) == norm(pkg))


MANIFEST_ECOSYSTEMS = ("npm", "crates", "pypi")


def manifest_fields(eco, owner, repo, directory, pkg):
    """Tri-state manifest cross-check: match / mismatch / inconclusive / not_supported (never an ambiguous None alone)."""
    if eco not in MANIFEST_ECOSYSTEMS:
        return {"manifest_name_matches": None, "manifest_check": "not_supported"}
    m = manifest_matches(eco, owner, repo, directory, pkg)
    return {"manifest_name_matches": m,
            "manifest_check": "inconclusive" if m is None else ("match" if m else "mismatch")}


def gh_check(info, eco, pkg):
    url = info.get("repo")
    if not url:
        return {"status": "no_repo"}
    p = parse_repo(url)
    if not p:
        return {"status": "unverified_host", "url": url, "note": "Unrecognized repository URL"}
    host, owner, repo = p
    out = {"url": f"https://{host}/{owner}/{repo}", "host": host}
    if host != "github.com":
        out["status"] = "unverified_host"
        out["note"] = "Non-GitHub host: open the repository and verify it manually."
        return out
    hdr = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        hdr["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    try:
        s, d = get(f"https://api.github.com/repos/{owner}/{repo}", headers=hdr)
    except NetErr as e:
        out.update(status="error", error=str(e))
        # Fallback without the API (the anonymous 60/h limit is easy to exhaust): check existence via the HTML page
        try:
            s2, _ = get(f"https://github.com/{owner}/{repo}", as_json=False)
        except NetErr:
            return out
        if s2 == 404:
            out["status"] = "not_found"
            return out
        out["status"] = "limited"
        out.update(manifest_fields(eco, owner, repo, info.get("repo_dir"), pkg))
        out["note"] = ("GitHub API unavailable or rate-limited (set GITHUB_TOKEN). The repository EXISTS (checked via the HTML page), "
                       "but stars, activity and fork/archived status were NOT verified: open the repository to complete the check.")
        return out
    if s == 404:
        out["status"] = "not_found"
        return out
    lic = d.get("license") or {}
    out.update(status="ok", full_name=d.get("full_name"), stars=d.get("stargazers_count"),
               archived=d.get("archived"), is_fork=d.get("fork"), pushed_at=iso(to_dt(d.get("pushed_at"))),
               repo_created=iso(to_dt(d.get("created_at"))), description=d.get("description"),
               license=lic.get("spdx_id"))
    out.update(manifest_fields(eco, owner, repo, info.get("repo_dir"), pkg))
    return out


# ---------- evaluation ----------
ATTESTATION_PREFIX = "https://registry.npmjs.org/-/npm/v1/attestations/"


def provenance_check(info, version):
    """npm build attestations, in three separate levels that must never be confused:
    attestation_present: the registry says an attestation exists for this version (a claim, not a proof);
    provenance_consistent: what we CAN check without cryptography agrees (digest of the tarball, source repository);
    provenance_verified: the signature chain (Sigstore: Fulcio certificate, Rekor log) was verified. This tool cannot do
    that with the standard library, so it is always False. `npm audit signatures` does it, after installation."""
    out = {"attestation_present": False, "provenance_consistent": None, "provenance_verified": False,
           "digest_matches": None, "repository_matches": None, "workflow_repository": None, "workflow_ref": None, "issue": None}
    url = (info.get("attestation_urls") or {}).get(version)
    if not url:
        return out
    out["attestation_present"] = True
    if not url.startswith(ATTESTATION_PREFIX):
        out.update(provenance_consistent=False, issue="the registry metadata points to an unexpected attestation URL")
        return out
    try:
        status, doc = get(url)
    except NetErr as e:
        out["issue"] = f"the attestation could not be fetched: {e}"[:200]
        return out
    if not doc:
        out["issue"] = "the attestation document was not found"
        return out
    statement = None
    try:
        for a in doc.get("attestations") or []:
            if "slsa.dev/provenance" in str(a.get("predicateType")):
                statement = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
                break
        if statement is None:
            out.update(provenance_consistent=False, issue="no SLSA provenance statement in the attestation bundle")
            return out
        integrity = (info.get("integrity") or {}).get(version) or ""
        want = base64.b64decode(integrity.split("-", 1)[1]).hex() if integrity.startswith("sha512-") else None
        subjects = statement.get("subject") or []
        out["digest_matches"] = (want is not None and any((x.get("digest") or {}).get("sha512") == want
                                                         and str(x.get("name", "")).endswith("@" + version) for x in subjects)) if want else None
        wf = ((statement.get("predicate") or {}).get("buildDefinition") or {}).get("externalParameters", {}).get("workflow") or {}
        out["workflow_repository"], out["workflow_ref"] = wf.get("repository"), wf.get("ref")
        declared, built = parse_repo(info.get("repo") or ""), parse_repo(wf.get("repository") or "")
        if declared and built:
            out["repository_matches"] = (declared[0], declared[1].lower(), declared[2].lower()) == (built[0], built[1].lower(), built[2].lower())
    except (ValueError, KeyError, TypeError, AttributeError, IndexError) as e:
        out.update(provenance_consistent=False, issue=f"the attestation is malformed: {type(e).__name__}")
        return out
    problems = []
    if out["digest_matches"] is False:
        problems.append("its digest does not match the published tarball")
    if out["repository_matches"] is False:
        problems.append("its source repository differs from the one the package declares")
    if problems:
        out.update(provenance_consistent=False, issue="; ".join(problems))
    elif out["digest_matches"] is True:
        out["provenance_consistent"] = True
    else:
        out["issue"] = "the tarball digest could not be compared"
    return out


def _prov_phrase(pc):
    if not (pc or {}).get("attestation_present"):
        return "no build attestation"
    if pc.get("provenance_consistent") is True:
        return "a build attestation consistent with the tarball and repository (signature not verified by this tool)"
    return "a build attestation that could not be confirmed as consistent"


def evaluate(eco, name, info, gh, target_version=None):
    flags = []

    def add(level, code, msg):
        flags.append({"level": level, "code": code, "msg": msg})

    ca, ma = age_days(to_dt(info.get("created"))), age_days(to_dt(info.get("modified")))
    if ca is not None and ca < 90:
        add("medium", "NEW_PACKAGE", f"first published {ca} days ago")
    if ma is not None and ma > 730:
        add("maintenance", "STALE", f"last release {ma} days ago")
    if info.get("n_versions") is not None and info["n_versions"] <= 2:
        add("maintenance", "FEW_VERSIONS", f"only {info['n_versions']} version(s) published")
    if info.get("deprecated"):
        add("maintenance", "DEPRECATED", str(info["deprecated"]))
    if info.get("install_scripts"):
        add("medium", "INSTALL_SCRIPTS", "runs code at install time: " + ", ".join(info["install_scripts"]))
    if eco == "npm" and ((info.get("version") or "").endswith("-security") or "security-holder" in str(info.get("repo"))):
        add("high", "SECURITY_HOLDING", "package replaced by npm with a security placeholder (it was previously malicious or removed)")
    if info.get("adoption") is None and eco in ("npm", "pypi"):
        add("info", "ADOPTION_UNAVAILABLE", "could not retrieve download counts (API unreachable): check the registry page")
    if info.get("adoption"):
        label, val, thr = info["adoption"]
        if val is not None and val < thr:
            add("medium", "LOW_ADOPTION", f"{val} {label} (attention threshold: {thr})")
    if eco == "aur" and not info.get("maintainers"):
        add("medium", "ORPHAN", "AUR package without a maintainer")
    if not info.get("repo"):
        add("medium", "NO_REPO", "no source repository declared in the registry")
    st = gh.get("status")
    if st == "not_found":
        add("high", "REPO_NOT_FOUND", f"the registry points to {gh.get('url')}, but that repository does not exist")
    elif st == "ok":
        if gh.get("archived"):
            add("maintenance", "REPO_ARCHIVED", "repository is archived (read-only)")
        if gh.get("is_fork"):
            add("medium", "REPO_IS_FORK", "the declared repository is a fork: confirm it is the original project")
        pa = age_days(to_dt(gh.get("pushed_at")))
        if pa is not None and pa > 730:
            add("maintenance", "REPO_INACTIVE", f"last push to the repository {pa} days ago")
        if gh.get("stars") is not None and gh["stars"] < 10:
            add("info", "FEW_STARS", f"{gh['stars']} estrela(s) no GitHub")
        if gh.get("manifest_name_matches") is False:
            add("medium", "REPO_MANIFEST_MISMATCH", "the manifest at the repository root declares a different name (could be a monorepo; check)")
    elif st in ("unverified_host", "error", "limited", "skipped"):
        if st == "limited" and gh.get("manifest_name_matches") is False:
            add("medium", "REPO_MANIFEST_MISMATCH", "the manifest at the repository root declares a different name (could be a monorepo; check)")
        add("info", "REPO_UNVERIFIED", gh.get("note") or gh.get("error") or "repository not verified automatically")
    if st in ("ok", "limited") and gh.get("manifest_check") == "not_supported":
        add("info", "MANIFEST_NOT_CHECKED", "the repository manifest cross-check is only automated for npm, crates.io and PyPI: the package name was NOT compared with the repository")
    elif st in ("ok", "limited") and gh.get("manifest_check") == "inconclusive":
        add("info", "MANIFEST_NOT_CHECKED", "the repository manifest could not be read or has no package name (monorepo, setup.py, workspace root): the package name was NOT compared with the repository")
    if name.lower() in stdlib_names(eco) or norm(name) in stdlib_names(eco):
        add("medium", "STDLIB_NAME_COLLISION",
            f"the name matches a built-in {'Node' if eco == 'npm' else 'Python'} module: you probably need to install nothing, and the third-party package with this name is NOT the built-in module")
    tv = target_version or info.get("version")
    if info.get("release_times") is None:
        add("info", "RELEASE_HISTORY_UNAVAILABLE", "this registry API does not expose per-version publication dates: the dormant-package-revival check was NOT performed")
    else:
        cur, prev = release_dates(info, tv)
        if not cur:
            add("info", "RELEASE_HISTORY_UNAVAILABLE", f"the publication date of version {tv} was not found: the dormant-package-revival check was NOT performed")
        else:
            pubs = info.get("publishers") or {}
            who = pubs.get(tv)
            earlier = {pubs[v] for v, t in (info.get("release_times") or {}).items()
                       if v != tv and pubs.get(v) and to_dt(t) and to_dt(t) < cur}
            pc = info.get("provenance_check") or {}
            if prev and age_days(cur) <= 30 and (cur - prev).days > 730:
                ctx = ""
                if who:
                    ctx = (f" It was published by '{who}'" + (" (who also published earlier releases)" if who in earlier else " (who published none of the earlier releases)")
                           + f" with {_prov_phrase(pc)}.")
                add("medium", "RECENT_RELEASE_ON_MATURE_PKG",
                    f"version {tv} was published {age_days(cur)} days ago, after {(cur - prev).days} days without a release: a dormant package suddenly publishing is a classic account-takeover pattern, but it can also be a returning maintainer.{ctx}")
            if who and earlier and who not in earlier and pc.get("provenance_consistent") is not True and age_days(cur) <= 90:
                add("medium", "NEW_PUBLISHER",
                    f"version {tv} was published by '{who}', who published none of the earlier releases (earlier publishers: {', '.join(sorted(earlier))}), and it has {_prov_phrase(pc)}: a maintainer handover or a stolen token looks like this")
    pc = info.get("provenance_check") or {}
    if pc.get("attestation_present"):
        if pc.get("digest_matches") is False:
            add("high", "PROVENANCE_DIGEST_MISMATCH", "the build attestation does not describe the published tarball (its digest differs from the registry's)")
        if pc.get("repository_matches") is False:
            add("medium", "PROVENANCE_REPO_MISMATCH", f"the build attestation names a different source repository ({pc.get('workflow_repository')}) than the one the package declares")
        if pc.get("provenance_consistent") is True:
            add("info", "PROVENANCE_NOT_SIGNATURE_VERIFIED", "a build attestation is present and consistent with the tarball and repository, but its signature chain was NOT verified by this tool (run `npm audit signatures` after installing)")
        elif pc.get("provenance_consistent") is None:
            add("info", "PROVENANCE_UNCHECKED", f"a build attestation is present but could not be checked: {pc.get('issue')}")
    if not name.isascii():
        add("medium", "NON_ASCII_NAME", "the name contains non-ASCII characters (possible homoglyph attack)")
    raw = name.lower().split("/")[-1]
    n = norm(name).split("/")[-1]
    for pop in POPULAR.get(eco, []):
        p = norm(pop)
        if (norm(raw) == p) if eco in NORMALIZING else (raw == pop.lower()):
            continue  # it IS the popular package
        if skeleton(raw) == skeleton(pop):
            add("medium", "LOOKALIKE_OF_POPULAR", f"the name differs from the popular package '{pop}' only by separators (- _ .) or look-alike characters (rn/m, vv/w, 0/o, 1/l)")
            break
        if min(len(n), len(p)) >= 4 and lev(n, p) <= (1 if min(len(n), len(p)) <= 5 else 2):
            add("medium", "SIMILAR_TO_POPULAR", f"name is very close to the popular package '{pop}' (typosquatting risk)")
            break
    return flags


def suggestions(eco, name):
    try:
        if eco == "npm":
            s, d = get("https://registry.npmjs.org/-/v1/search?size=5&text=" + q(name))
            return [o["package"]["name"] for o in (d or {}).get("objects", [])]
        if eco == "crates":
            s, d = get("https://crates.io/api/v1/crates?per_page=5&q=" + q(name))
            return [c["name"] for c in (d or {}).get("crates", [])]
    except NetErr:
        pass
    return []


def check(eco, name, repo=True, version=None):
    """Checks a dependency. Returns (result, exit_code). Prints nothing."""
    res = {"ecosystem": eco, "name": name}
    try:
        info = REGISTRIES[eco](name)
    except NetErr as e:
        res.update(status="error", error=str(e),
                   note="A network failure does NOT prove the package does not exist, nor that it is safe. Verify by another means (open the registry and repository pages) or report that it could not be verified.")
        return res, 2
    if info is None:
        res.update(status="not_found", signals="strong_alerts",
                   flags=[{"level": "high", "code": "NOT_FOUND", "msg": "the name does not exist in this registry (likely a hallucination or a typo)"}],
                   registry_search_hits=suggestions(eco, name),
                   note="Never suggest registering the name. Registry search results are NOT verified: run each one through the same process.")
        return res, 1
    gh = gh_check(info, eco, name) if repo else {"status": "skipped", "note": "repository check disabled (--no-repo)"}
    if eco == "npm":
        info["provenance_check"] = provenance_check(info, version or info.get("version"))
    flags = evaluate(eco, name, info, gh, target_version=version)
    signals = ("strong_alerts" if any(f["level"] == "high" for f in flags)
               else "attention" if any(f["level"] == "medium" for f in flags) else "no_alerts")
    ad = info.pop("adoption", None)
    tv = version or info.get("version")
    cur, prev = release_dates(info, tv)
    info["target_version"], info["target_published"] = tv, iso(cur)
    info["previous_release"] = iso(prev)
    info["target_publisher"] = (info.get("publishers") or {}).get(tv)
    info["target_provenance"] = info.get("provenance_check")
    for k in ("release_times", "publishers", "attestation_urls", "integrity", "provenance_check"):
        info.pop(k, None)
    info["created"], info["modified"] = iso(to_dt(info.get("created"))), iso(to_dt(info.get("modified")))
    info.pop("repo_dir", None)
    res.update(status="found", signals=signals, registry=info,
               adoption={"metric": ad[0], "value": ad[1]} if ad else None, repository=gh, flags=flags,
               note="'no_alerts' = no automatic alerts; it is NOT a security certification. Stars, downloads, activity and reputation are indicators, not proof. Complete the check manually (README/docs, the API you will use).")
    return res, 0


def main():
    argv = sys.argv[1:]
    version = None
    if "--version" in argv:
        i = argv.index("--version")
        version = argv[i + 1] if i + 1 < len(argv) else None
        if not version:
            print(json.dumps({"status": "error", "error": "--version needs a value"}))
            sys.exit(2)
        del argv[i:i + 2]
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        sys.exit(2)
    eco = ALIASES.get(args[0].lower(), args[0].lower())
    if eco not in REGISTRIES:
        print(json.dumps({"status": "error", "error": f"unknown ecosystem: {args[0]}",
                          "supported": sorted(REGISTRIES)}, ensure_ascii=False))
        sys.exit(2)
    res, code = check(eco, args[1], repo="--no-repo" not in argv, version=version)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    sys.exit(code)


if __name__ == "__main__":
    main()
