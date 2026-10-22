# Development Guide

---

## Setup

```bash
git clone https://github.com/xscan/xscan
cd xscan
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

---

## Run tests

```bash
pytest
pytest tests/unit/
pytest tests/integration/ --run-slow
```

---

## Code style

```bash
ruff check .
ruff format .
mypy src/
```

---

## Project structure

```
src/xscan/        Source code
tests/            Tests
docs/             Documentation (indexed by Help Engine)
completions/      Shell completion scripts
scripts/          Development utilities
```

---

## Adding a new command

1. Create `src/xscan/cli/cmd_<name>.py`
2. Define a Typer app or command function
3. Register it in `src/xscan/cli/__init__.py`
4. Add `--help` text following the help architecture spec
5. Add a Markdown doc at `docs/commands/<name>.md`
6. Update `src/xscan/help/topics.py` TOPIC_ALIASES if needed

---

## Adding a new workflow

1. Create `src/xscan/workflows/<name>.py`
2. Define stages as a list of `Stage` dataclasses
3. Register in `src/xscan/workflows/__init__.py`
4. Add a Markdown doc at `docs/workflows/<name>.md`

---

## Adding a help topic

1. Add a Markdown file in the appropriate `docs/` subdirectory
2. The DocIndex will pick it up automatically on next run
3. Optionally add an alias in `topics.TOPIC_ALIASES`

---

## Architecture decisions

See `docs/architecture/` for design records.

---

## Related topics

- `xscan help architecture`
- `xscan help concepts/dag`
