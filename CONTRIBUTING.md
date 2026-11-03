# Contributing

Thanks for taking a look. Bug reports and detection ideas are the most useful things you can send. Open an issue with the matching template.

## Setting up

```bash
git clone https://github.com/CasimirTerr/Strata.git
cd strata
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install   # optional, runs ruff and the generated-file checks before each commit
pytest
```

## Adding a detection

1. **Add the rule** to `RULES` in `strata/rules.py`: an ID, a plain-English title, a severity, why it matters, the CloudTrail sources and event names, ATT&CK or ATLAS mappings, when it's normal, and what to do.
2. **Add the logic.** Single-event checks go in `check_event`. Anything that needs memory across events goes in its own function and gets called from `scan` in `strata/engine.py`.
3. **Write tests** in `tests/test_rules.py`. Cover a hit, a near miss that shouldn't fire, and what happens when CloudTrail hides the fields you rely on (`HIDDEN_DUE_TO_SECURITY_REASONS`).
4. **Port it to the web page.** The engine in `docs/index.html` mirrors the Python one line for line. Keep the same wording, because the two are compared field by field.
5. **Regenerate the generated files:**
   ```bash
   python scripts/sync_web.py
   python scripts/make_docs.py
   strata export-sigma sigma
   ```
   The tests fail if you forget.
6. If the rule changes what the samples show, update `scripts/make_samples.py`, run it, and update the README output.

## Style

- `ruff check .` and `ruff format .` before you push. CI runs both, plus `mypy`.
- Write detection text for the person reading an alert at 2 a.m.: what happened, to what, and by whom. Skip jargon where a plain word works.
- No third-party runtime dependencies. Strata has to run in a bare Lambda and in a browser.
