"""Build build/strata-lambda.zip for the Terraform in deploy/terraform.

Strata has no third-party dependencies, and boto3 already ships with the Lambda
Python runtime, so the package is just the strata/ folder.

    python scripts/build_lambda.py
"""

import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "strata-lambda.zip"


def build(out=OUT):
    out.parent.mkdir(parents=True, exist_ok=True)
    files = sorted((ROOT / "strata").glob("*.py"))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            # Fixed timestamps so the same code always gives the same zip (and Terraform sees no change).
            info = zipfile.ZipInfo(f"strata/{f.name}", date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, f.read_bytes(), zipfile.ZIP_DEFLATED)
    return out, len(files)


if __name__ == "__main__":
    path, n = build()
    print(f"wrote {path.relative_to(ROOT)} ({n} files)")
