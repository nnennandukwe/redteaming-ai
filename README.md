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
- a small set of scripted attack agents
- a CLI demo flow
- a Streamlit demo UI

## What This Repo Is

- A compact sandbox for demonstrating common LLM security problems
- A starting point for an OSS red-teaming project
- A place to experiment locally before the platform architecture is built out

## What This Repo Is Not Yet

- A general-purpose red-teaming platform
- A rigorous evaluation harness for real-world LLM systems
- A service with persistence, APIs, benchmark history, or evidence-backed reporting

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

### Streamlit UI

```bash
pip install -r requirements.txt
streamlit run streamlit_demo.py
```

### Optional Real Provider Configuration

```bash
cp .env.example .env
# edit .env and add your provider key
python demo.py
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
- `streamlit_demo.py`: Streamlit interface
- `quick_start.sh`: basic launcher for demo modes

## Known Limitations

These are current limitations, not hidden gotchas:

- The demo target is synthetic and intentionally insecure.
- Much of the current attack execution and scoring is heuristic/scripted.
- There is no persistent run storage or historical comparison yet.
- There is no backend API or target adapter layer yet.
- The reporting is useful for demos, not yet strong enough for serious assessments.

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

