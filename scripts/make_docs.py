"""Write DETECTIONS.md from the rule definitions in strata/rules.py.

python scripts/make_docs.py
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from strata.rules import RULES  # noqa: E402

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"
ATLAS_URL = "https://atlas.mitre.org/techniques/{}"


def link(tid):
    if tid.startswith("AML."):
        return f"[{tid}]({ATLAS_URL.format(tid)})"
    return f"[{tid}]({ATTACK_URL.format(tid.replace('.', '/'))})"


def render():
    out = [
        "# Detections",
        "",
        "Every rule Strata runs, what sets it off, and what to do when it fires.",
        "This file is generated from `strata/rules.py` by `scripts/make_docs.py`, so it always matches the code.",
        "",
        "| ID | Severity | Detection |",
        "| --- | --- | --- |",
    ]
    for r in RULES.values():
        out.append(f"| [{r.id}](#{r.id.lower()}) | {r.severity.title()} | {r.title} |")
    out.append("")
    for r in RULES.values():
        out += [f"## {r.id}", "", f"**{r.title}** ({r.severity.title()})", "", r.why, ""]
        if r.events:
            out.append(
                "**CloudTrail events:** "
                + ", ".join(f"`{e}`" for e in r.events)
                + " from "
                + ", ".join(f"`{s}`" for s in r.sources)
            )
            out.append("")
        maps = r.attack + r.atlas
        if maps:
            out += ["**Maps to:** " + ", ".join(link(t) for t in maps), ""]
        out += [f"**Can be normal when:** {r.false_positives}", "", f"**What to do:** {r.response}", ""]
    return "\n".join(out)


if __name__ == "__main__":
    (ROOT / "DETECTIONS.md").write_text(render() + "\n", encoding="utf-8")
    print("wrote DETECTIONS.md")
