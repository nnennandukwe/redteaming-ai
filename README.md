# redteaming-ai

`redteaming-ai` is an alpha open-source red-teaming project for exploring common security failure modes in LLM-integrated applications.

Today, this repo is best understood as a credible OSS foundation with demo-friendly entrypoints, not a finished platform. It is useful for experimenting with prompt injection, data exfiltration, jailbreak-style prompts, unsafe tool exposure, persisted assessments, and evaluator-backed reporting in a controlled local environment. It is still intentionally small in scope and not yet a high-confidence assessment system for real production applications.

## Current Status

- Packaged CLI and API: yes
- Reproducible local workflow and CI: yes
- Good for presentations, local experimentation, and teaching: yes
- Production-ready platform: no
- Good for assessing real systems with high confidence: not yet

The codebase currently centers on:

- a deliberately vulnerable sample app
- a managed attack corpus with seeded generation strategies
- packaged CLI and API assessment flows
- a CLI demo flow and Streamlit demo UI

## What This Repo Is

- A compact sandbox for demonstrating common LLM security problems
- A small but structured OSS red-teaming foundation
- A place to experiment locally with reproducible runs, persisted reports, and evaluator-backed findings

## What This Repo Is Not Yet

- A general-purpose red-teaming platform
- A rigorous evaluation harness for real-world LLM systems
- A service with multi-user APIs, benchmark dashboards, or production-grade evidence workflows

## Quick Start

### Cross-Platform Bootstrap

1. Install [`uv`](https://docs.astral.sh/uv/getting-started/installation/).
2. Create a local `.env` file from `.env.example`. For local smoke tests and demo runs, keep `LLM_PROVIDER=mock`.
3. Sync the project environment from the committed lockfile:

```bash
uv sync --frozen --extra dev
```

The `uv` commands below are the canonical workflow and work the same on macOS, Linux, and Windows.

### Packaged Workflows (Primary)

```bash
uv run redteam --auto
uv run redteam --auto --attack-strategy corpus --seed 0
uv run redteam --auto --attack-strategy mutate --attack-categories prompt_injection,jailbreak --seed 42
uv run redteam --auto --attack-strategy fuzz --attack-categories prompt_injection,data_exfiltration,jailbreak --attack-budget 12 --seed 7
uv run redteam --auto --target-type hosted_chat_model --target-provider openai --target-model gpt-4.1
uv run redteam --history
uv run redteam --replay <run-id>
uv run redteam --export <run-id> --format json
uv run redteam --export <run-id> --format markdown --output ./report.md
uv run redteam --compare <run-a> <run-b>
uv run redteam-api
```

Exports are written to `~/.redteaming-ai/exports/` by default when `--output` is not provided.
Replay and export now consume the stored report artifact when available, which keeps the CLI aligned with persisted findings and other structured report data.
`uv run redteam --auto` accepts `--target-type`, `--target-provider`, `--target-model`, `--target-config '<json>'`, `--attack-categories <csv>`, `--attack-strategy corpus|mutate|fuzz`, `--attack-budget <int>`, and `--seed <int>` for packaged assessment runs.

Hosted chat example with declarative capability metadata:

```bash
uv run redteam --auto \
  --target-type hosted_chat_model \
  --target-provider anthropic \
  --target-model claude-3-5-haiku-latest \
  --target-config '{"system_prompt":"You are a support assistant.","capabilities":{"tool_use":false,"memory":false,"retrieval":true,"policy_layer":true},"constraints":["no-pii"]}'
```

You can also use the module entrypoint:

```bash
uv run python -m redteaming_ai --history
```

### Demo/UI Workflows (Secondary)

```bash
uv run python demo.py
uv run python demo.py --auto
uv run streamlit run streamlit_demo.py
```

The API starts on `http://127.0.0.1:8000` with OpenAPI docs at `http://127.0.0.1:8000/docs`.

Create an assessment against the built-in demo target:

```bash
curl -X POST http://127.0.0.1:8000/assessments \
  -H "Content-Type: application/json" \
  -d '{"target_type":"vulnerable_llm_app","target_provider":"mock","target_config":{"mode":"api"}}'
```

Create an assessment against a hosted chat model:

```bash
curl -X POST http://127.0.0.1:8000/assessments \
  -H "Content-Type: application/json" \
  -d '{"target_type":"hosted_chat_model","target_provider":"openai","target_model":"gpt-4.1","target_config":{"system_prompt":"You are a support assistant.","capabilities":{"tool_use":false,"memory":false,"retrieval":true,"policy_layer":true},"constraints":["no-pii"]}}'
```

Report export is available through the API as well:

```bash
curl http://127.0.0.1:8000/assessments/<run-id>/report
curl "http://127.0.0.1:8000/assessments/<run-id>/report/export?format=json"
curl "http://127.0.0.1:8000/assessments/<run-id>/report/export?format=markdown"
```

### Configuration

The application uses typed settings with fail-fast validation. All configuration is via environment variables.
Packaged CLI, API, and hosted-model adapter flows all load a repo-local `.env` file automatically when present.

**Environment Variables:**

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `LLM_PROVIDER` | Yes | LLM provider: `mock`, `openai`, or `anthropic` | (none - must be set) |
| `OPENAI_API_KEY` | Only if `LLM_PROVIDER=openai` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Only if `LLM_PROVIDER=anthropic` | Anthropic API key | - |
| `MODEL_NAME` | No | Model name (provider-specific default if not set) | provider default |

**Quick Start (mock mode - no API key needed):**
```bash
uv run redteam
```

**With real provider:**
```bash
# create .env from .env.example and edit it with your provider and API key
uv run redteam --auto --target-type hosted_chat_model --target-provider openai --target-model gpt-4.1
```

### Run Tests

```bash
uv run pytest -q
uv run ruff check .
```

## What You Can Explore Today

- Prompt injection against a toy LLM application
- Synthetic secret and PII exposure paths
- Unsafe tool-access patterns
- Conversation-history leakage
- A small scripted attack suite with terminal and Streamlit views

## Repository Layout

- `vulnerable_app.py`: intentionally vulnerable demo target
- `red_team_agents.py`: attack payloads, orchestration, and reporting logic
- `demo.py`: interactive CLI demo
- `src/redteaming_ai/cli.py`: packaged CLI with persisted history, replay, compare, and export
- `src/redteaming_ai/api.py`: packaged API for assessments, reports, evidence, and exports
- `streamlit_demo.py`: Streamlit interface

## Known Limitations

These are current limitations, not hidden gotchas:

- The demo target is synthetic and intentionally insecure.
- Much of the current attack execution and scoring is still managed through seeded corpus strategies rather than a full fuzzing platform.
- Persisted history is currently centered on the packaged CLI (`redteam` / `python -m redteaming_ai`), not every demo/UI entrypoint.
- The packaged adapter layer now supports the built-in demo target plus hosted `openai` and `anthropic` chat models, but it is still limited.
- Hosted target capabilities such as tools, memory, retrieval, and policy layers are metadata-only in the current adapter contract; they are not executed or enforced yet.
- The reporting is useful for demos, not yet strong enough for serious assessments, although structured exports are now available for persisted runs.

If you are evaluating whether this repo is ready to assess a real application, the honest answer is no. If you want a demo you can run locally, modify, and learn from, the answer is yes.

## Project Status

The OSS foundation epic is complete:

- Epic: [#14](https://github.com/nnennandukwe/redteaming-ai/issues/14)
- Core outcomes: packaged CLI and API flows, persistent storage, adapter boundaries, evaluator-backed grading, structured reporting, seeded corpus workflows, automated tests, and a cross-platform `uv`-based developer workflow

From here, the project can deepen target integrations, evaluation quality, and user experience without needing another repository-setup pass first.

## Safety Note

This repository contains intentionally vulnerable code and insecure patterns for educational purposes. Do not copy these patterns into production systems.

The demo uses synthetic placeholder secrets and synthetic PII-like data. Even so, treat the project as a teaching artifact, not a security control.

## Resources

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Injection Primer](https://github.com/jthack/PIPE)
