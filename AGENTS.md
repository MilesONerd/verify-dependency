# AGENTS.md

Source of truth for AI coding agents working on this repository. The tool-specific files
(`CLAUDE.md`, `GEMINI.md`, `.aider.conf.yml`, `.github/copilot-instructions.md`) only point here.
Edit this file, never those.

## Project overview

`verify-dependency` is an agent skill (Agent Skills format, `SKILL.md`) that stops AI agents from using
hallucinated or malicious dependencies (slopsquatting). It has two parts:

- Instructions: `skills/verify-dependency/SKILL.md`.
- A deterministic verifier in Python, standard library only: `skills/verify-dependency/scripts/check_dep.py`
  (one dependency) and `skills/verify-dependency/scripts/diff_lock.py` (lockfile diff, including transitive
  dependencies).

## Repository layout

Upstream: https://github.com/MilesONerd/verify-dependency

```
skills/verify-dependency/   the skill itself (this folder is what gets packaged and installed)
  SKILL.md                  instructions and frontmatter (license, author, version)
  scripts/                  check_dep.py, diff_lock.py
  LICENSE-APACHE, LICENSE-MIT   copies of the root licenses (must stay byte-identical)
tests/                      unittest suite (offline by default)
tools/package.py            validates and builds dist/verify-dependency.skill
evals/scenarios.md          behavior scenarios to run with a fresh agent
```

## Commands

- Run all tests (offline): `python3 -m unittest discover -s tests -v`
- Run live registry tests (needs network, opt-in): `VERIFY_DEP_LIVE=1 python3 -m unittest discover -s tests -v`
- Validate and build the package: `python3 tools/package.py` (writes `dist/verify-dependency.skill`)
- Smoke test the verifier: `python3 skills/verify-dependency/scripts/check_dep.py npm express --no-repo`

Run the offline tests and `tools/package.py` before every commit.

## Code conventions

- Python 3, **standard library only**. This repository must never depend on third-party packages.
- All text is English: code, comments, messages, docs.
- Every source file starts with `# SPDX-License-Identifier: Apache-2.0 OR MIT` and the copyright line.
- Scripts print JSON on stdout. Keep the exit codes: `check_dep.py` 0 found, 1 not found, 2 error;
  `diff_lock.py` 0 ok, 2 error.
- A network failure must surface as `error`, never as `not_found` and never as `no_alerts`.
- Every command shown in `AGENTS.md` and `README.md` must run from the repository root, with full paths.
  Inside `SKILL.md`, script paths are written as `<skill-dir>/scripts/...`. `tests/test_docs.py` enforces both.
- Do not remove existing checks. Adding a flag means adding a test and a row in the flag table in `SKILL.md`.
- Flag levels: `high` and `medium` change `signals`; `maintenance` and `info` do not.

## Invariants of the skill (do not weaken)

1. Explicit user approval before using any new dependency, regardless of who suggested it.
2. Transitive dependencies are flagged and presented for review.
3. Signals are indicators, not proof. Never call a result "safe", "approved" or "certified".
4. Instructions describe operations, not one vendor's tools (no tool names such as web fetchers).
5. Multi-ecosystem. Do not narrow the skill to npm.
6. The skill text is English; the report it asks for is written in the user's language.

## SKILL.md authoring rules

- `name` equals the folder name. `description` is at most 1024 characters and contains no `: ` sequence.
- Keep `license: Apache-2.0 OR MIT` and `metadata.author`. Bump `metadata.version` on every release.
- Keep `SKILL.md` under 500 lines.

## Agent instruction files

- `AGENTS.md` is the only file with real content.
- `CLAUDE.md` imports it with `@AGENTS.md` (Claude Code ignores `AGENTS.md` when a `CLAUDE.md` exists).
- `GEMINI.md` imports it with `@./AGENTS.md`.
- `.aider.conf.yml` loads it with `read: AGENTS.md` (Aider does not discover instruction files by name).
- `.github/copilot-instructions.md` is a one-paragraph pointer.
- Do **not** add `.rules`, `.cursorrules`, `.windsurfrules` or `.clinerules`. Zed loads only the first match of
  `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `AGENT.md`,
  `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, so each of those would hide this file from Zed. Cursor, Windsurf, Cline and
  most other tools read `AGENTS.md` natively.
- Never duplicate these instructions into another file.

## Boundaries

- Ask first: adding any dependency (even a development one), changing the license, changing the invariants above.
- Never: edit the license texts, commit secrets, add credentials to fixtures.

## Commits and pull requests

- Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`), one logical change per commit.
- By contributing you agree your work is dual-licensed as described in `README.md`.
