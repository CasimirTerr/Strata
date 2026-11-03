"""Time a scan over a large synthetic log set.

python scripts/benchmark.py 100000
"""

import copy
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from strata.cloudtrail import Event  # noqa: E402
from strata.engine import scan  # noqa: E402


def synthetic(n, seed=7):
    rng = random.Random(seed)
    base = [
        *json.loads((ROOT / "examples" / "attack-night" / "cloudtrail.json").read_text())["Records"],
    ]
    start = datetime(2026, 11, 1, tzinfo=timezone.utc)
    records = []
    for i in range(n):
        r = copy.deepcopy(rng.choice(base))
        r["eventTime"] = (start + timedelta(seconds=rng.randint(0, 7 * 86400))).strftime("%Y-%m-%dT%H:%M:%SZ")
        r["eventID"] = f"bench-{i}"
        role = f"role-{rng.randint(0, 400)}"
        r["userIdentity"] = {
            "arn": f"arn:aws:sts::111122223333:assumed-role/{role}/s",
            "sessionContext": {"sessionIssuer": {"arn": f"arn:aws:iam::111122223333:role/{role}"}},
        }
        records.append(r)
    return records


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    records = synthetic(n)
    t0 = time.perf_counter()
    events = sorted((Event(r) for r in records), key=lambda e: e.time)
    result = scan(events)
    elapsed = time.perf_counter() - t0
    print(
        f"{n:,} events in {elapsed:.2f}s ({n / elapsed:,.0f} events/s), "
        f"{len(result.detections):,} detections, {len(result.chains):,} chains"
    )
