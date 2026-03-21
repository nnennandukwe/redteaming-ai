# redteaming-ai

`redteaming-ai` is an interactive demo project for exploring common security failure modes in LLM-integrated applications.

Today, this repo is best understood as an educational demo, not a full red-teaming platform. It is useful for experimenting with prompt injection, data exfiltration, jailbreak-style prompts, and unsafe tool exposure in a controlled local environment. The long-term goal is to evolve it into a more credible open-source red-teaming system with reproducible runs, stronger evaluation, and real target integrations.

## Current Status

- Working demo: yes
- Production-ready platform: no
- Good for presentations, local experimentation, and teaching: yes
- Good for assessing real systems with high confidence: not yet

The codebase currently centers on:

- a deliberately vulnerable sample app
- a managed attack corpus with seeded generation strategies
- a CLI demo flow
- a Streamlit demo UI

## What This Repo Is

- A compact sandbox for demonstrating common LLM security problems
- A starting point for an OSS red-teaming project
- A place to experiment locally before the platform architecture is built out

## What This Repo Is Not Yet

- A general-purpose red-teaming platform
- A rigorous evaluation harness for real-world LLM systems
- A service with multi-user APIs, benchmark dashboards, or production-grade evidence workflows

## Quick Start

### Local Demo

```bash
pip install -r requirements.txt
python demo.py
```

### Quick Automated Run

```bash
pip install -r requirements.txt
python demo.py --auto
```

### Persisted CLI Workflows

```bash
pip install -e .
redteam --auto
redteam --auto --attack-strategy corpus --seed 0
redteam --auto --attack-strategy mutate --attack-categories prompt_injection,jailbreak --seed 42
redteam --auto --attack-strategy fuzz --attack-categories prompt_injection,data_exfiltration,jailbreak --attack-budget 12 --seed 7
redteam --auto --target-type hosted_chat_model --target-provider openai --target-model gpt-4.1
redteam --history
redteam --replay <run-id>
redteam --export <run-id> --format json
redteam --export <run-id> --format markdown --output ./report.md
redteam --compare <run-a> <run-b>
```

Exports are written to `~/.redteaming-ai/exports/` by default when `--output` is not provided.
Replay and export now consume the stored report artifact when available, which keeps the CLI aligned with persisted findings and other structured report data.
`redteam --auto` accepts `--target-type`, `--target-provider`, `--target-model`, `--target-config '<json>'`, `--attack-categories <csv>`, `--attack-strategy corpus|mutate|fuzz`, `--attack-budget <int>`, and `--seed <int>` for packaged assessment runs.

Hosted chat example with declarative capability metadata:

```bash
redteam --auto \
  --target-type hosted_chat_model \
  --target-provider anthropic \
  --target-model claude-3-5-haiku-latest \
  --target-config '{"system_prompt":"You are a support assistant.","capabilities":{"tool_use":false,"memory":false,"retrieval":true,"policy_layer":true},"constraints":["no-pii"]}'
```

You can also use the module entrypoint:

```bash
python -m redteaming_ai --history
```

### Streamlit UI

```bash
pip install -r requirements.txt
streamlit run streamlit_demo.py
```

### Backend API

```bash
pip install -e .
redteam-api
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

**Environment Variables:**

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `LLM_PROVIDER` | Yes | LLM provider: `mock`, `openai`, or `anthropic` | (none - must be set) |
| `OPENAI_API_KEY` | Only if `LLM_PROVIDER=openai` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Only if `LLM_PROVIDER=anthropic` | Anthropic API key | - |
| `MODEL_NAME` | No | Model name (provider-specific default if not set) | provider default |

**Quick Start (mock mode - no API key needed):**
```bash
export LLM_PROVIDER=mock
python demo.py
```

**With real provider:**
```bash
cp .env.example .env
# edit .env with your provider and API key
python demo.py
```

### Run Tests

```bash
pip install -r requirements.txt
pytest -q
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
- `quick_start.sh`: basic launcher for demo modes

## Known Limitations

These are current limitations, not hidden gotchas:

- The demo target is synthetic and intentionally insecure.
- Much of the current attack execution and scoring is still managed through seeded corpus strategies rather than a full fuzzing platform.
- Persisted history is currently centered on the packaged CLI (`redteam` / `python -m redteaming_ai`), not every demo/UI entrypoint.
- The packaged adapter layer now supports the built-in demo target plus hosted `openai` and `anthropic` chat models, but it is still limited.
- Hosted target capabilities such as tools, memory, retrieval, and policy layers are metadata-only in the current adapter contract; they are not executed or enforced yet.
- The reporting is useful for demos, not yet strong enough for serious assessments, although structured exports are now available for persisted runs.

If you are evaluating whether this repo is ready to assess a real application, the honest answer is no. If you want a demo you can run locally, modify, and learn from, the answer is yes.

## Roadmap

The public roadmap is tracked in GitHub:

- Epic: [#14](https://github.com/nnennandukwe/redteaming-ai/issues/14)
- Correctness and trust fixes: [#9](https://github.com/nnennandukwe/redteaming-ai/issues/9)
- Test and CI foundation: [#8](https://github.com/nnennandukwe/redteaming-ai/issues/8)
- OSS readiness: [#11](https://github.com/nnennandukwe/redteaming-ai/issues/11)
- README and messaging cleanup: [#13](https://github.com/nnennandukwe/redteaming-ai/issues/13)
- Package structure and architecture: [#1](https://github.com/nnennandukwe/redteaming-ai/issues/1)
- Config, storage, API, adapters, evaluation, fuzzing, and reporting: [#2](https://github.com/nnennandukwe/redteaming-ai/issues/2), [#3](https://github.com/nnennandukwe/redteaming-ai/issues/3), [#4](https://github.com/nnennandukwe/redteaming-ai/issues/4), [#5](https://github.com/nnennandukwe/redteaming-ai/issues/5), [#6](https://github.com/nnennandukwe/redteaming-ai/issues/6), [#7](https://github.com/nnennandukwe/redteaming-ai/issues/7), [#10](https://github.com/nnennandukwe/redteaming-ai/issues/10), [#12](https://github.com/nnennandukwe/redteaming-ai/issues/12)

The current implementation work is focused on making the public repo accurate first, then building the platform foundations behind it.

## Safety Note

This repository contains intentionally vulnerable code and insecure patterns for educational purposes. Do not copy these patterns into production systems.

The demo uses synthetic placeholder secrets and synthetic PII-like data. Even so, treat the project as a teaching artifact, not a security control.

## Resources

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Prompt Injection Primer](https://github.com/jthack/PIPE)
