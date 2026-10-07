# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

Centralized, reusable security tooling consumed by **other** Centreon repositories. There is no application code, build, or test suite here — the deliverables are:

- **Reusable GitHub Actions workflows** (`workflow_call`) that downstream repos invoke.
- **A pre-commit hook** (`.githooks/pre-commit`) that runs gitleaks secret scanning.
- **A blocklist of compromised packages** (`blacklist/compromised-packages.txt`) served raw over HTTP and fetched at scan time.

Because consumers pin to `@main`, changes to workflows and the blocklist take effect immediately across all Centreon repositories that reference them. Treat `main` as production.

## Architecture

### Reusable workflows (`.github/workflows/`)

- `security-checks.yml` — the **orchestrator**. Runs on PR/push to `main`, on a weekday cron, and on demand. It calls the two `workflow_call` workflows below. This is also the pattern downstream repos copy: `uses: centreon/security-tools/.github/workflows/<file>.yml@main`.
- `dependency-analysis.yml` — `workflow_call` + runs on PR. Two responsibilities:
  1. **Lockfile compliance** — enforces PNPM only (rejects `yarn.lock` / `package-lock.json`), requires a lockfile, and enforces a minimum `lockfileVersion` (`8.9.9`).
  2. **Blocklist scan** — downloads `compromised-packages.txt` from `main` and greps every `pnpm-lock.yaml` for `name@version` matches.
- `gitleaks-analysis.yml` — `workflow_call` (org repos call it on `pull_request` and `workflow_dispatch`; this repo also on push to `main` and on a schedule). Installs the gitleaks release pinned by `GITLEAKS_VERSION` + `GITLEAKS_SHA256` (bump both together; Dependabot/Renovate don't) and scans every non-merge commit of the analyzed branch, excluding only the commits already on the destination branch (whatever it is called, and whether or not they are on other branches): `base..head` for a PR, `before..after` for a push to an existing branch, and the ref's whole history when there is no destination nor `before` (new branch, `before` gone, `workflow_dispatch`, `schedule`). A PR never fails on secrets already on its base; it fails on a secret in one of its commits. Pull requests are checked out shallow (`fetch-depth` = PR commits + 2): the scan deepens the base side until the range holds no parentless commit (a shallow boundary would be read as a root and its whole tree scanned). Event SHAs missing from the clone are re-fetched with the job token. Fails closed: leaks, gitleaks errors, unresolvable ranges and unsupported events all fail the job. `pull_request_target` always fails (not compliant with the security posture), from a first step that runs before checkout.

**Warn-then-enforce gating** (in `dependency-analysis.yml`): findings are reported as `[WARNING]` until a deadline, after which they become `[ERROR]` and fail the build. Controlled by two repository-level GitHub variables:
- `OVERRIDE_DEPENDENCY_ENFORCEMENT_DATE` — the date enforcement begins.
- `OVERRIDE_DEPENDENCY_SCAN` — set to `"true"` to bypass the scan entirely.

Findings accumulate in `error_log.txt`, which is posted back to the PR as a sticky comment via `marocchino/sticky-pull-request-comment`. The job only fails if `fail_the_build=true` (set when enforcement is active and findings exist).

**Self-hosted runner selection**: jobs use a conditional `runs-on` that picks a per-org self-hosted runner only for **private** repos — `centreon-security` for the `centreon` org, `quanta-security` for the `quanta-computing` org — and falls back to `ubuntu-24.04` for public repos or any other owner. The same expression is used in both `dependency-analysis.yml` and `gitleaks-analysis.yml`; keep them in sync when editing.

### The blocklist (`blacklist/compromised-packages.txt`)

- Format: one `package_name:version` per line; `#` lines are comments.
- Consumed by URL: `https://raw.githubusercontent.com/centreon/security-tools/main/blacklist/compromised-packages.txt`. Adding a line here arms it everywhere on the next scan — keep the `name:version` format exact.
- The file header documents the advisory sources to check when updating.

## Conventions

- **GitHub Actions are pinned by full commit SHA** with a trailing `# vX.Y.Z` comment, not by tag. Keep this when bumping (Dependabot/Renovate do this automatically). Never replace a SHA pin with a floating tag.
- **Commit messages** follow Conventional Commits with project scopes seen in history: `ci(secu):`, `pipeline(secu):`, `chore(SECU):`, `fix(dependency-analysis):`, `build(deps):`.
- **CODEOWNERS** splits ownership: `@centreon/owners-pipelines` owns `.github/**`; `@centreon/owners-security` owns `.gitleaks*`, the pre-commit hook, and any `**/secu-*.yml`. Security-owned files need security-team review.

## Local secret scanning

The pre-commit hook requires `gitleaks` on PATH and runs `gitleaks detect --no-git`. Enable it with:

```sh
git config core.hooksPath .githooks
```

(Per the user's global rules: never bypass this hook with `--no-verify`.)
