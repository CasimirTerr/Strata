"""Copy the rule list and sample logs into docs/index.html.

Run after editing strata/rules.py or the sample logs:

    python scripts/sync_web.py
"""

import json
import re
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from strata.rules import RULES  # noqa: E402

PAGE = ROOT / "docs" / "index.html"


def rules_json():
    return {rid: {k: v for k, v in asdict(r).items() if k != "id"} for rid, r in RULES.items()}


def _load_sample(name):
    return json.loads((ROOT / "examples" / name / "cloudtrail.json").read_text())["Records"]


def samples_json():
    return {"attack": _load_sample("attack-night"), "normal": _load_sample("normal-day")}


def put(html, tag, value):
    rx = re.compile(rf"/\*{tag}_START\*/.*?/\*{tag}_END\*/", re.DOTALL)
    if not rx.search(html):
        sys.exit(f"{tag} markers not found in docs/index.html")
    text = json.dumps(value, separators=(",", ":")).replace("</", "<\\/")
    return rx.sub(lambda _: f"/*{tag}_START*/{text}/*{tag}_END*/", html)


def main():
    html = PAGE.read_text(encoding="utf-8")
    html = put(html, "RULES", rules_json())
    html = put(html, "SAMPLES", samples_json())
    PAGE.write_text(html, encoding="utf-8")
    print("docs/index.html updated")


if __name__ == "__main__":
    main()
