# verify-dependency

Repository: <https://github.com/MilesONerd/verify-dependency>

An [Agent Skill](https://agentskills.io) that stops AI agents from using **hallucinated or malicious dependencies**
(*slopsquatting*), in any ecosystem, and makes them ask for your approval first.

## Why

Language models sometimes invent package names, and the invention is repeatable: the same question tends to
produce the same fake name. Attackers collect those names, register them on npm, PyPI or crates.io with
malicious code, and wait. When the invented install suddenly *works*, nothing looks wrong.

This skill changes the default behavior of an agent that is about to add a dependency:

1. **Verify** that it exists, check for warning signs, find the repository, and look at what else comes along
   (transitive dependencies).
2. **Present** the findings to you, with links.
3. **Wait for your explicit approval**, even when you were the one who named the package.

Nothing is installed, and nothing is written to your real manifest or lockfile, before you say yes.

## What is in the box

| Part | What it does |
|---|---|
| `skills/verify-dependency/SKILL.md` | The instructions the agent follows: the approval rule, the verification steps, how to read the signals, the report format. |
| `skills/verify-dependency/scripts/check_dep.py` | Deterministic verifier (Python standard library only). Queries the registry, cross-checks the repository, returns JSON with `signals` and `flags`. |
| `skills/verify-dependency/scripts/diff_lock.py` | Compares lockfiles and lists added, changed and removed dependencies, including transitive ones, and can verify the added ones in bulk. |

Supported ecosystems: npm, PyPI, crates.io, RubyGems, NuGet, Go, Packagist, Maven, Hex, pub.dev, AUR.
Lockfiles read by `diff_lock.py`: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` (best effort), `Cargo.lock`,
`poetry.lock`, `uv.lock`, `requirements*.txt` / `pip freeze`, `go.sum`, `go list -m all` output, `composer.lock`, `Gemfile.lock`, and pip
reports (`pip install --dry-run --report`).

### What it detects

Non-existent names, packages replaced by registry security placeholders, repositories that do not exist, names
that collide with built-in modules (`npm install path`), names close to popular packages or differing only by separators and look-alike characters (`body_parser`), non-ASCII names, dormant packages that suddenly publish and publishers never seen before (the account-takeover patterns, also checked on the new versions of packages already in your lockfile), new packages with little
adoption, install scripts, forks, manifest/repository name mismatches (automated for npm, crates.io and PyPI only; the report says "not checked" for the rest), orphaned AUR packages, and, as
informational flags, stale, archived or deprecated projects.

### What it does **not** promise

The name-similarity check uses a small built-in list of popular packages, so a missing `SIMILAR_TO_POPULAR` flag does not clear a name.

Signals are **indicators, not proof**. Stars, downloads, activity and reputation can be faked, and a legitimate
package can be compromised later. The result `no_alerts` means "no automatic alerts", never "safe". The skill tells
the agent to say so, and never to call a dependency safe, approved or certified.

## Install

**Claude (claude.ai, Claude Code):** upload or install `verify-dependency.skill` (build it with
`python3 tools/package.py`, output in `dist/`), or copy `skills/verify-dependency/` into your skills folder
(for example `.claude/skills/`).

**Other agents that support the Agent Skills format:** copy `skills/verify-dependency/` into the folder your agent
reads skills from (`.agents/skills/` is the cross-client convention described by the specification).

**No agent at all:** the scripts work on their own.

```bash
git clone https://github.com/MilesONerd/verify-dependency.git
```

## Auditing this skill before you install it

A skill is part of your supply chain: `SKILL.md` is a prompt that stays in your agent's context, and the scripts run on your
machine. Treat this one like any other dependency, which is the whole point of it.

- **Read it.** `SKILL.md` is about 185 lines and the two scripts use only the Python standard library.
- **Pin it.** Install from a tagged release or a commit hash, not from a moving branch. `python3 tools/package.py` prints the SHA-256 of
  `verify-dependency.skill` and writes it next to the file; compare it with the one published with the release.
- **The network is guarded at runtime, not only by tests.** Every request goes through one opener that refuses any host outside a fixed
  allowlist, anything that is not https, and any redirect to another host (a package's own metadata can point anywhere, so a URL taken from it
  never decides where the script connects). `tests/test_network_guard.py` checks this with real sockets and with a recording opener across all
  eleven ecosystems.
- **Let the tests check the surface.** `tests/test_audit_surface.py` fails if the scripts start to import anything unexpected, use dynamic code or
  reflection, write, rename or delete files by any route (`open`, `os.*`, `urlretrieve`, `pathlib`-style writers), modify the environment,
  run anything other than read-only `git` commands, or use an unguarded opener. It resolves import aliases, so `import os as x` does not hide a
  call. It also fails if `SKILL.md` gains phrases that tell an agent to hide output or skip the approval. Static analysis cannot prove a
  script safe; it makes the usual ways of going wrong fail loudly. The hosts contacted are the package registries (npm, PyPI, crates.io, RubyGems,
  NuGet, Go proxy, Packagist, Hex, pub.dev, Maven Central, AUR) plus `api.github.com`, `raw.githubusercontent.com` and `github.com`.
- **Review every change or fork.** Look for instructions that weaken the approval rule or the report, new hosts, new imports, obfuscated or
  encoded strings, and anything that executes what it downloads. The tests catch some of this; they do not replace reading the diff.

## Use the scripts directly

```bash
# One dependency
python3 skills/verify-dependency/scripts/check_dep.py npm express
python3 skills/verify-dependency/scripts/check_dep.py pypi requests --no-repo

# What would an update bring in? (compare the lockfile on disk with HEAD, verify what was added)
python3 skills/verify-dependency/scripts/diff_lock.py --git package-lock.json --verify
```

`check_dep.py` exit codes: `0` found, `1` does not exist, `2` error or inconclusive. A network failure is always
reported as `error`, never as "does not exist" and never as "no alerts". Set `GITHUB_TOKEN` to raise the GitHub API
rate limit (60 requests per hour when anonymous).

### Verification status per ecosystem

| Ecosystem | Status |
|---|---|
| npm, PyPI, crates.io | Tested against the live registries. |
| RubyGems, NuGet, Go, Packagist, Maven, Hex, pub.dev, AUR | Parsers tested against mocked responses only. Run the live test in your own environment before relying on them. |

## Limitations and design choices

- **Approval is always required, and there is no allowlist.** Approval fatigue is real, and a compact report for well-known packages is the
  mitigation. Dependencies already in your lockfile are outside the workflow, and updates are summarized as one diff rather than asked
  about one by one. A bypass list is a prime prompt-injection target (the agent could be talked into adding to it), so none is shipped.
  If you want one, it should be a file you own, keyed by exact ecosystem, name and version, that the agent cannot write to.
- **The list of popular packages is small and static.** `LOOKALIKE_OF_POPULAR` and `SIMILAR_TO_POPULAR` only compare against it, so a typosquat
  of a niche package passes. A dynamic top-N from the registries was not adopted: there is no uniform official source (crates.io has one, npm does
  not), it adds network dependence, it makes results vary over time in a verifier meant to be deterministic, and the list itself becomes a trust
  anchor. A better path is a committed snapshot, refreshed by a maintainer script and reviewed as a diff.
- **Account compromise is only partly covered.** The dormant-package and new-publisher checks catch two patterns. A hijacked maintainer account
  publishing a new version of an actively maintained package looks normal to every signal here. Pin versions, prefer packages with build
  provenance, and delay adopting brand-new versions when you can.
- **Build provenance is checked for consistency, not verified.** For npm the script compares the attestation's digest with the published tarball
  and its source repository with the declared one. It does not verify the Sigstore signature chain (the standard library cannot), so the result
  is "present and consistent", never "verified". `npm audit signatures` verifies signatures after installation. Even verified provenance only
  says where a build ran, not that the code is benign.
- **Repository cross-checks cover GitHub only.** Repositories on GitLab, Codeberg, SourceHut and self-hosted forges get an informational
  `REPO_UNVERIFIED`. Fetching them would need per-forge APIs and a strict host allowlist, because the URL comes from the package's own metadata.
- **GitHub rate limits.** `diff_lock.py --verify` makes no GitHub requests (measured: 0 for a 65-package tree); it queries registries only.
  A single `check_dep.py` run makes one to three.

## Using AI agents on this repository

`AGENTS.md` is the single source of truth for agents working on this repository. The other files only point to it.

| Tool | How it gets the instructions | File here |
|---|---|---|
| OpenAI Codex, Cursor, Windsurf, Kiro, Cline, Amp, Warp, Roo Code, Kilo Code, Jules, Factory, goose, opencode, Devin, JetBrains Junie, Augment Code and others | Read `AGENTS.md` natively | none needed |
| Claude Code | Reads `AGENTS.md` itself (v2.1.277 and later) **only when no `CLAUDE.md` exists**, so a `CLAUDE.md` must import it | `CLAUDE.md` (`@AGENTS.md`) |
| Gemini CLI | Reads `GEMINI.md`, which supports `@file` imports (alternatively, set `context.fileName` in `.gemini/settings.json`) | `GEMINI.md` (`@./AGENTS.md`) |
| Antigravity | Reads both `AGENTS.md` and `GEMINI.md` | none beyond the two above |
| Aider | Does not discover instruction files by name; needs `read:` | `.aider.conf.yml` |
| GitHub Copilot | Cloud agent and CLI read `AGENTS.md`; VS Code reads it when `chat.useAgentsMdFile` is on; the IDE code review reads only `copilot-instructions.md` | `.github/copilot-instructions.md` (pointer) |
| Zed | Loads the **first** match of `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `AGENT.md`, `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` | see note below |

Notes:

- Not created on purpose: `.cursorrules` and `.windsurfrules` (legacy formats), `.rules`, `.clinerules/`,
  `.cursor/rules/`, `.windsurf/rules/`, `.kiro/steering/`. The tools behind them read `AGENTS.md` natively, and in Zed
  every one of the single-file names sits *before* `AGENTS.md` in the list above and would hide it.
- Because of that same list, Zed picks up `.github/copilot-instructions.md` before `AGENTS.md`. That file is a
  one-paragraph pointer telling the agent to read `AGENTS.md`; delete it if you do not use Copilot and want Zed to
  load `AGENTS.md` directly.
- With a `CLAUDE.md` that imports `AGENTS.md`, tools that read both files (for example Cursor and the Copilot CLI) may
  see the shared instructions twice. This costs a few tokens and changes nothing else. Claude Code itself never reads
  the content twice.
- Checked against vendor documentation in November 2026. This is documentation-based; each tool was not run to
  confirm. This area changes quickly, so re-check before relying on a detail.

The lockfile preview commands in `SKILL.md` were run for real for npm, pip, Cargo (1.75), Go (1.22, with `GOPROXY=direct`), pnpm 12, uv 0.11 and
Poetry 2.5, and `diff_lock.py` was run on the lockfiles they produced. They are not tested for yarn (classic or berry), composer and bundler.

## Development

```bash
python3 -m unittest discover -s tests -v                         # offline suite
VERIFY_DEP_LIVE=1 python3 -m unittest discover -s tests -v       # also hits live registries
python3 tools/package.py                                         # validate and build dist/verify-dependency.skill
```

`evals/scenarios.md` lists eight behavior scenarios (known library, invented package, suspicious package,
explicitly requested package, standard library, dependency update, unavailable registry, no reply from the user) to
run with a fresh agent. The scripts are covered by tests; the agent's behavior can only be confirmed by running
those prompts.

Requirements: Python 3 (tested on 3.12). `git` is optional (used by `diff_lock.py --git`). There are no third-party
dependencies, and there must never be any.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option. SPDX identifier: `Apache-2.0 OR MIT`.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Author

Enzo ([@MilesONerd](https://github.com/MilesONerd)), project home: <https://github.com/MilesONerd/verify-dependency>
