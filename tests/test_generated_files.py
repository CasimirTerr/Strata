"""Generated files (web page data, DETECTIONS.md) must match the code."""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import make_docs  # noqa: E402
import sync_web  # noqa: E402


def embedded(tag):
    html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    m = re.search(rf"/\*{tag}_START\*/(.*?)/\*{tag}_END\*/", html, re.DOTALL)
    assert m, f"{tag} block missing from docs/index.html"
    return json.loads(m.group(1).replace("<\\/", "</"))


def test_web_rules_match_python():
    assert embedded("RULES") == sync_web.rules_json(), "Run `python scripts/sync_web.py`"


def test_web_samples_match_examples():
    assert embedded("SAMPLES") == sync_web.samples_json(), "Run `python scripts/sync_web.py`"


def test_detections_doc_is_current():
    assert (ROOT / "DETECTIONS.md").read_text(encoding="utf-8") == make_docs.render() + "\n", (
        "Run `python scripts/make_docs.py`"
    )
