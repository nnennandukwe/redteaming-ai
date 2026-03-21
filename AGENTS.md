# AGENTS.md

## Issue Workflow
- Before starting work on a new issue, always sync with the latest remote main:
  - `git fetch origin --prune`
  - `git checkout main`
  - `git pull --ff-only origin main`
- Start each issue on a fresh branch created from the updated `main`.
- Branch names must be issue-specific and descriptive, for example:
  - `feat/issue-5-target-adapters`
  - `fix/issue-12-devx`

## Implementation Discipline
- Keep changes scoped to the active issue.
- Make organized, meaningful commits instead of leaving issue work uncommitted.
- Run the relevant test and lint commands before opening a pull request.

## Pull Request Workflow
- After implementation and verification, push the issue branch and open a pull request unless explicitly told not to.
- The pull request body must link the issue being solved with a closing keyword:
  - `Closes #<issue>`
- If the work belongs to a parent issue or epic, also include a reference line:
  - `Refs #<epic>`
- Summarize the verification steps that were actually run.

## For This Repo
- Treat the packaged API and CLI flows in `src/redteaming_ai/` as the primary maintained product surface.
- Legacy demo/UI entrypoints may remain intentionally simpler when an issue explicitly scopes work to packaged flows only.
