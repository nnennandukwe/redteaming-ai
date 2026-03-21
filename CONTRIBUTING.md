# Contributing

Thanks for contributing to `redteaming-ai`.

## Before You Start

- Read open issues before starting work to avoid duplicated effort.
- Prefer opening or commenting on an issue before making large changes.
- Keep pull requests focused. Small, reviewable changes move faster.
- Treat this project as security-adjacent software. Be explicit about assumptions and tradeoffs.

## Local Workflow

- Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/) as the only required local tool.
- Create a local `.env` file from `.env.example`. For smoke tests and local demo work, keep `LLM_PROVIDER=mock`.
- Sync the environment from the committed lockfile:
  ```bash
  uv sync --frozen --extra dev
  ```
- Use a feature branch for your work.
- Keep commits scoped to a single concern when practical.
- Run the relevant local checks before opening a pull request:
  ```bash
  uv run pytest -q
  uv run ruff check .
  ```
- Use the packaged workflows as the default maintenance surface:
  ```bash
  uv run redteam
  uv run redteam-api
  ```
- Treat `demo.py` and `streamlit_demo.py` as secondary demo entrypoints:
  ```bash
  uv run python demo.py
  uv run streamlit run streamlit_demo.py
  ```
- Update docs when behavior, interfaces, or setup steps change.

## Pull Request Guidelines

- Explain the problem being solved.
- Explain the approach and major tradeoffs.
- Include validation steps and observed results.
- Link the relevant issue when one exists.
- Call out follow-up work instead of quietly expanding scope.

## Code and Docs Expectations

- Prefer clear, maintainable changes over cleverness.
- Preserve established project conventions unless the pull request intentionally changes them.
- Avoid bundling refactors with behavior changes unless they are tightly related.
- Add or update tests when changing behavior.
- Keep public-facing docs honest about what is implemented versus planned.

## Security

Do not open public issues for unpatched security problems, credential exposure, or anything that would create a live exploit path for users of the project. Follow the process in [SECURITY.md](SECURITY.md).

## Community Standards

By participating in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
