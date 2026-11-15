---
name: verify-dependency
description: Verifies that a dependency (package, library, crate, module, gem, image, action) exists and shows no warning signs, and requires explicit user approval before it is used, including the transitive dependencies that come along. Use ALWAYS when suggesting, adding, installing, importing or updating third-party dependencies in any ecosystem (npm, PyPI, crates.io, Go, RubyGems, NuGet, Packagist, Maven, Hex, pub.dev, AUR, Homebrew, apt/pacman, Docker, GitHub Actions), in code, manifests, lockfiles, Dockerfiles or commands such as npm install, pip install, cargo add, go get, yay -S, npm update. Applies even when the user says "install package X". Also use when reviewing code with unfamiliar imports and when asked which library to use. Protects against slopsquatting (hallucinated package names that attackers register), typosquatting and unexpected transitive dependencies. Matches requests in any language.
license: Apache-2.0 OR MIT
compatibility: Requires Python 3 (tested on 3.12) and outbound network access to public package registries. git is optional (used by diff_lock.py --git).
metadata:
  author: Enzo (MilesONerd)
  version: "1.2.0"
  repository: https://github.com/MilesONerd/verify-dependency
---

# Dependency verification (anti-slopsquatting)

## Why this exists

Language models sometimes "remember" packages that do not exist, and the hallucination is **repeatable**: the same question tends to produce the same invented name. Attackers exploit this: they collect those names, register them on npm/PyPI/crates.io with malicious code, and wait for someone to run `install`. The command succeeds and no error appears.

Two consequences:

- A package name that came from a model's memory is **not trustworthy until verified**.
- "It exists in the registry" proves nothing on its own (the attacker may have registered the name), and even a legitimate package brings dozens of **transitive dependencies** that nobody asked for. Verification must cross-check several sources and look at the whole set, not only the name that was requested.

## Core rule

Every **new** dependency goes through three steps, in this order, **regardless of who suggested it**, including when the user says "install package X":

1. **Verify** (does it exist? are there warning signs? what else comes along?)
2. **Present** the findings to the user, including the repository link
3. **Wait for explicit approval**

Before approval, do **not** install anything, do not run `npm install X` / `pip install X` / `cargo add X`, do not write the dependency into the real manifest or lockfile, and do not write code that uses it as if it were approved. Work that does not depend on it may continue. The preview described in "Transitive dependencies" (resolving in a temporary copy, without installing and without running scripts) is part of the verification and may be done before asking.

For huge, unambiguous packages (react, serde, requests) the report can be compact, but the question is still mandatory.

### Outside the workflow

- A dependency that is **already present and unchanged** in the project's manifest/lockfile (it was accepted before). If the project is unfamiliar, read its manifest before proposing anything.
- The language's standard library (`os`, `std::fs`, `node:fs`). Still confirm that the module and function really exist in the version in use, because hallucination also happens with the stdlib.

## Step by step

### 1. Is a dependency really needed?

Before proposing one, check whether the stdlib or something the project already uses solves the problem. Fewer dependencies means a smaller attack surface. Beware of built-in module names (`path`, `fs`, `os`, `json`): `npm install path`, or `pip install` with such a name, brings in an unrelated third-party package, not the language's module.

### 2. Find the correct **install** name

The `import` name often differs from the install name (`import bs4` → `beautifulsoup4`; `import PIL` → `pillow`; `import yaml` → `pyyaml`; `import dotenv` → `python-dotenv`). Always verify the install name.

### 3. Run the verifier

```bash
python3 <skill-dir>/scripts/check_dep.py <ecosystem> <name>
```

`<skill-dir>` is the directory that contains this `SKILL.md`. Every `scripts/...` path in this skill is relative to it, so resolve it first (or `cd` there). Running `python3 scripts/check_dep.py` from the project root fails because the scripts are not in the project.

Ecosystems: `npm`, `pypi`, `crates`, `gem`, `nuget`, `go`, `packagist`, `aur`, `hex`, `pub`, `maven` (format `group:artifact`). Aliases such as `pip`, `cargo`, `composer`, `dotnet` work. One candidate per run. Uses only the Python standard library (tested on 3.12). `GITHUB_TOKEN` in the environment raises the GitHub API rate limit (anonymous: 60/hour, easy to exhaust). `--no-repo` skips the repository check (useful in bulk). `--version X` judges the release timing of version X instead of the latest one.

The script queries the registry, then the declared repository (existence, fork, archived, activity, and whether the repository's manifest carries the same name as the package), and returns JSON with `status`, `signals`, registry and repository data, and `flags`. Exit code: `0` found, `1` does not exist, `2` error/inconclusive.

### 4. Interpret the result

- **`not_found`**: the name does not exist. Say so plainly ("this package does not exist, it was probably a hallucination"). Do not try name variations blindly and **never** suggest registering the name. Look for real alternatives (web search, official documentation, `registry_search_hits`) and run **each** candidate through the same process, since search results are not verified.
- **`error`**: a network failure does **not** mean "does not exist" and does **not** mean "ok". Try another route (open the registry page and the repository page). If that also fails, report that verification was not possible and do not proceed as if it had been verified.
- **`found`**: the registry confirms existence, which is only the beginning. Continue to step 5.
- **`repository.manifest_check`**: `match` or `mismatch` is a real comparison; `inconclusive` (manifest unreadable, monorepo, `setup.py` project) and `not_supported` (every ecosystem except npm, crates.io and PyPI) mean the package name was **not** compared with the repository. Report that as "not checked", never as "matches".
- **Repository `limited`**: the GitHub API was unavailable. The script only confirmed that the repository exists (and, when possible, the name in its manifest); stars, activity, fork and archived status were **not** verified. Open the repository to complete the check, or declare the gap in the report.

### 5. Manual verification (what the script does not do)

- Open the repository: is it the project you think it is? Does the README describe what you need? Is there recent activity and more than one contributor?
- **Check the API you will use.** Hallucination also invents functions, classes and flags. Confirm in the official documentation that they exist in the current version before writing code.
- If there is a `high` or `medium` flag, search the web for the package name together with "malware", "vulnerability" or "advisory".
- **Ecosystems the script does not fully cover** (apt, the official pacman repositories, Homebrew, Docker images, GitHub Actions): consult the official pages (for example archlinux.org/packages, formulae.brew.sh, Docker Hub with the verified-publisher badge, the Action's page). For Actions and images, recommend pinning by SHA/digest.
- **AUR**: unreviewed user-submitted content. Check whether the package exists in the official repositories and **read the PKGBUILD** (and the `.install` file) before recommending it.

### 6. Transitive dependencies

Adding or updating a package changes the whole lockfile. Asking for 1 dependency can bring dozens (in testing, `npm install express` brought 65 packages). Whenever an addition **or update** (`npm update`, `cargo update`, `pip install -U`, a version change in a manifest) may introduce new packages, flag them and present the changes for review.

**a) Generate the preview without installing and without running scripts, in a temporary copy of the project** (copy the manifest and lockfile; do not touch the real ones):

| Ecosystem | Command (in the copy) | Status |
|---|---|---|
| npm | `npm install <pkg> --package-lock-only --ignore-scripts` | tested |
| PyPI | `pip freeze > old.txt` and `pip install --dry-run --ignore-installed --only-binary=:all: --report new.json <pkg>` | tested |
| Cargo | `cargo add <crate>` (resolves, edits `Cargo.toml` and updates `Cargo.lock`; does not compile or run build scripts, and no `cargo fetch` is needed; needs cargo 1.62 or later) | tested (cargo 1.75) |
| Go | `go list -m all > go-list-old.txt`, then `go get <module>@<version>`, then `go list -m all > go-list-new.txt` (downloads modules, does not compile). Compare the two files, not `go.sum`: `go.sum` records only what the build needed and can omit transitive modules | tested (Go 1.22, `GOPROXY=direct`) |
| pnpm | `pnpm add <pkg> --lockfile-only --ignore-scripts` (creates no `node_modules`) | tested (pnpm 12, lockfile v9) |
| uv | `uv add <pkg> --no-sync` (edits `pyproject.toml` and `uv.lock`; creates no `.venv`) | tested (uv 0.11) |
| Poetry | `poetry add <pkg> --lock` (updates `poetry.lock`; may create an empty virtualenv, installs no packages) | tested (Poetry 2.5) |
| yarn (classic and berry), composer, bundler | use the package manager's "lockfile only, no scripts" option (confirm in its documentation). Yarn classic has no lockfile-only mode | not tested |

Note on PyPI: `--only-binary=:all:` prevents resolving source distributions (sdists), whose resolution can execute build code. If resolution fails for lack of a wheel, treat that as a finding to report, not as an obstacle to work around.

**b) Compare and verify what came in:**

```bash
python3 <skill-dir>/scripts/diff_lock.py --git <lockfile> --verify        # against HEAD (lockfile path relative to where you run it)
python3 <skill-dir>/scripts/diff_lock.py old.lock new.lock --verify       # two files
python3 <skill-dir>/scripts/diff_lock.py old.txt new.json --verify        # pip freeze vs pip report
python3 <skill-dir>/scripts/diff_lock.py go-list-old.txt go-list-new.txt  # go list -m all, before and after
```

In `--git` mode the lockfile may live in any subdirectory; use `--base <ref>` to compare against something other than `HEAD`. An unknown ref, a directory outside a git repository, or an unreadable file is reported as an error, never as "everything added". A `parse_warning` in the output means a non-empty lockfile produced zero packages (possibly an unsupported format version): say so instead of reporting "nothing changed".

Reads `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` (best effort), `Cargo.lock`, `poetry.lock`, `uv.lock`, `requirements*.txt`/`pip freeze`, `go.sum`, `go list -m all` output (file name starting with `go-list`), `composer.lock`, `Gemfile.lock` and pip reports. Lists **added**, **changed** and **removed** packages, annotates sources outside the registry and install scripts, and with `--verify` queries the registry for every added package (without the repository check, so it fits in bulk). If the parser does not recognize the lockfile, or the output is empty for no apparent reason, say so instead of assuming "nothing changed".

**c) Report on the transitive set:** counts (added/changed/removed); the list of added packages (compact if there are many); individual detail **only** for those in `needs_attention`, `not_found`, carrying `notes` (source outside the registry, install scripts) or with a verification error. State explicitly that transitive packages were checked **in the registry only**, not in their repositories, and offer to go deeper on the flagged ones. **Changed** versions are checked too: `--verify` looks at the publication date and publisher of every NEW version of a package that was already in the lockfile. `changed_needs_attention` lists the packages whose new version looks like a dormant package that suddenly published, or like a publisher never seen before; `changed_not_date_checked` lists the ones whose registry API gives no per-version dates (NuGet, Go, Maven, AUR), which were therefore **not** checked and must be reported as such. A flag here is a reason to look at who published and why, not proof of a compromise: real maintainers do revive old packages, and a move to trusted publishing (publisher `GitHub Actions` with build provenance) is normal.

### 7. Report to the user

Write it in the user's language, concise, in this format:

```
**Proposed dependency:** `name` (ecosystem), for [what it does in this case]

| | |
|---|---|
| Registry | [link] · version X · first published YYYY-MM-DD · last release YYYY-MM-DD |
| Adoption | N downloads/votes (an indicator, not proof) |
| License / maintainers | ... |
| Repository | [link] · ⭐ N · last push YYYY-MM-DD · [archived/fork if applicable] |
| Cross-check | does the repository manifest match the package name (automated only for npm, crates.io and PyPI; otherwise write "not checked")? install scripts? |
| Transitive | N new (summary; details of the flagged ones) |
| Not verified | what was left out and why |

**Signals found:** [relevant flags, or "no automatic alerts"]
**Reading of the signals:** no alerts / attention / strong alerts, in 1-2 sentences with the reasoning.
**Alternatives:** stdlib or another library, if it makes sense.

This is a summary of signals, not a security certification. The decision is yours.
May I use it?
```

Always end with the question and stop there.

### 8. After approval

Use the verified version, recommend pinning the version (lockfile; hash where the ecosystem supports it), and only now actually install. If the user declines or asks for another option, return to step 1 with the alternative.

## What the signals mean (and do not mean)

Stars, downloads, activity, age and maintainer reputation are **indicators**. Legitimate packages can have few downloads and malicious ones can have many (compromised accounts, bought stars, hijacked old projects). A compromised maintainer account that publishes a new version of an **actively maintained** package is not detectable by these signals: the dormant-revival and new-publisher checks catch only two patterns of it. **Never** present the result as a certification, "safe package" or "approved". What may be said is "I found no automatic alerts" and "I found these signals".

`signals` in the JSON: `no_alerts` (no automatic alerts), `attention` (there is a `medium` flag), `strong_alerts` (there is a `high` flag). Maintenance flags and verification-limit flags do not change `signals`, but they must appear in the report.

| Flag | Level | What it suggests |
|---|---|---|
| `NOT_FOUND` | high | Invented name or typo. Do not use. |
| `SECURITY_HOLDING` | high | The registry already removed a malicious package with this name. Do not use. |
| `REPO_NOT_FOUND` | high | The registry points to a repository that does not exist. Very suspicious. |
| `NEW_PACKAGE`, `NO_REPO`, `LOW_ADOPTION` | medium | Classic profile of a package registered to catch hallucinations when they appear together. Do not use without strong confirmation. |
| `STDLIB_NAME_COLLISION` | medium | The name is that of a built-in language module (`path`, `fs`, `os`). You probably need to install nothing, and the third-party package with the same name is not the built-in module. Use the stdlib. |
| `LOOKALIKE_OF_POPULAR` | medium | Differs from a popular package only by separators (`-`, `_`, `.`) or look-alike characters (`rn`/`m`, `vv`/`w`, `0`/`o`, `1`/`l`). On npm `body_parser` and `body-parser` are different packages. Typosquatting until proven otherwise. |
| `SIMILAR_TO_POPULAR` | medium | Possible typosquatting by edit distance. Confirm the name is exactly the official project's. The check uses a small built-in list of popular names, so the absence of this flag and of `LOOKALIKE_OF_POPULAR` does **not** mean the name is not a typosquat. |
| `NON_ASCII_NAME` | medium | The name has non-ASCII characters (homoglyph attack). |
| `RECENT_RELEASE_ON_MATURE_PKG` | medium | The version was published in the last 30 days after more than 2 years without any release. A classic account-takeover pattern, but also what a returning maintainer looks like. Read the publisher and provenance in the message, then the changelog. |
| `NEW_PUBLISHER` | medium | The version was published (last 90 days) by someone who published none of the earlier releases, with no build provenance. A maintainer handover or a stolen token looks like this. Only available where the registry reports the publisher (npm, crates.io). |
| `INSTALL_SCRIPTS` | medium | Runs code at install time (npm). Read the script first. |
| `REPO_MANIFEST_MISMATCH` | medium | The declared repository carries a different name in its manifest. Could be a monorepo, could be a front. |
| `REPO_IS_FORK` | medium | Confirm it is the original project and not a tampered copy. |
| `ORPHAN` (AUR) | medium | No maintainer; anyone can adopt it. Read the PKGBUILD with extra care. |
| `STALE`, `FEW_VERSIONS`, `REPO_INACTIVE`, `REPO_ARCHIVED`, `DEPRECATED` | maintenance | Maintenance risk, not necessarily malware (old, stable packages are common). Report it and, where relevant, suggest a maintained alternative. Abandoned projects can also be hijacked: read it together with the other signals. |
| `REPO_UNVERIFIED`, `MANIFEST_NOT_CHECKED`, `RELEASE_HISTORY_UNAVAILABLE`, `ADOPTION_UNAVAILABLE`, `FEW_STARS` | info | Limits of the check or weak data. State them in the report. |

## Required operations (tool-independent)

This skill describes **what to do**, not which tool to use. Any agent that can perform the operations below will work:

| Operation | Used for | If unavailable |
|---|---|---|
| Run local commands (Python 3 and a shell) | run `check_dep.py` and `diff_lock.py`, generate the lockfile preview | ask the user to run the command and paste the JSON output; without that, state that nothing was verified |
| Read the content of a URL | open the registry page, repository, README, documentation, PKGBUILD | use only what the script returned and state what was left unverified |
| Search the web | find real alternatives, security advisories | ask the user for alternatives or candidate names and verify them with the script |
| Read and write local files | manifests, lockfiles, the temporary copy of the project | ask the user for the manifest/lockfile contents |

The scripts depend only on Python 3 (standard library) and outbound network access to the public registries (and to `api.github.com` / `raw.githubusercontent.com` for the repository). In restricted-network environments some registries may be blocked: that shows up as `error`, never as "does not exist".

## What not to do

- Do not "fix" a nonexistent name by guessing a similar one.
- Do not treat "it appears on npm/PyPI" as proof of legitimacy.
- Do not skip verification because the dependency seems obvious, because the user named it, or because of time pressure.
- Do not ignore transitive dependencies: the package you were asked for is the smallest part of what will be installed.
- Do not hide what was not verified. Saying so explicitly is part of the report.
- Do not run an install "just to test whether it exists": installation can execute code.
- Do not call the result "safe", "approved" or "certified".
