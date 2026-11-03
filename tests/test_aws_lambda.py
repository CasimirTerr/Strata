"""Tests for the scheduled Lambda, against fake S3 and SNS from moto."""

import gzip
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

boto3 = pytest.importorskip("boto3")
moto = pytest.importorskip("moto")

from strata.aws_lambda import Settings, run  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
REGION = "us-east-1"
PREFIX = "AWSLogs/111122223333/CloudTrail/"


@pytest.fixture
def aws(monkeypatch):
    for k, v in {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_DEFAULT_REGION": REGION,
    }.items():
        monkeypatch.setenv(k, v)
    with moto.mock_aws():
        s3 = boto3.client("s3", region_name=REGION)
        sns = boto3.client("sns", region_name=REGION)
        sqs = boto3.client("sqs", region_name=REGION)
        s3.create_bucket(Bucket="trail-bucket")
        topic = sns.create_topic(Name="strata-alerts")["TopicArn"]
        queue = sqs.create_queue(QueueName="inbox")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)
        yield {"s3": s3, "sns": sns, "sqs": sqs, "topic": topic, "queue": queue}


def settings(aws, **kw):
    return Settings(bucket="trail-bucket", prefix=PREFIX, regions=[REGION], topic_arn=aws["topic"], **kw)


def put_log(aws, records, name="111122223333_CloudTrail_us-east-1_20261103T0215Z_abc.json.gz"):
    today = datetime.now(timezone.utc)
    key = f"{PREFIX}{REGION}/{today:%Y/%m/%d}/{name}"
    aws["s3"].put_object(Bucket="trail-bucket", Key=key, Body=gzip.compress(json.dumps({"Records": records}).encode()))
    return key


def received(aws):
    msgs = aws["sqs"].receive_message(QueueUrl=aws["queue"], MaxNumberOfMessages=10).get("Messages", [])
    return [json.loads(m["Body"]) for m in msgs]


def sample(name):
    return json.loads((ROOT / "examples" / name / "cloudtrail.json").read_text())["Records"]


def test_attack_logs_send_one_alert_with_all_chains(aws):
    put_log(aws, sample("attack-night"))
    summary = run(settings(aws), aws["s3"], aws["sns"])
    assert summary["files"] == 1 and summary["events"] == 53
    assert summary["alerted_chains"] == 3
    msgs = received(aws)
    assert len(msgs) == 1
    assert msgs[0]["Subject"].startswith("Strata: 3 attack chains")
    assert "ci-deployer" in msgs[0]["Message"]


def test_normal_day_with_allowlist_sends_nothing(aws):
    put_log(aws, sample("normal-day"))
    cfg = {
        "allow": [
            {"principal": "deploy-pipeline", "rules": ["ST-007"]},
            {"principal": "PlatformAdmin", "rules": ["ST-006"]},
        ]
    }
    summary = run(settings(aws, config=cfg), aws["s3"], aws["sns"])
    assert summary["alerted_chains"] == 0 and summary["alerted_detections"] == 0
    assert received(aws) == []


def test_files_older_than_the_window_give_context_but_no_alerts(aws):
    put_log(aws, sample("attack-night"))
    later = datetime.now(timezone.utc) + timedelta(minutes=90)
    summary = run(settings(aws), aws["s3"], aws["sns"], now=later)
    assert summary["events"] == 53  # still read for context
    assert summary["alerted_chains"] == 0  # but already alerted on in an earlier run
    assert received(aws) == []


def test_min_severity_filters_single_detections(aws):
    put_log(aws, [r for r in sample("normal-day") if r["eventName"] == "UpdatePrompt"])
    assert run(settings(aws, min_severity="HIGH"), aws["s3"], aws["sns"])["alerted_detections"] == 0
    assert run(settings(aws, min_severity="MEDIUM"), aws["s3"], aws["sns"])["alerted_detections"] == 1


def test_settings_from_env_validates():
    env = {
        "CLOUDTRAIL_BUCKET": "b",
        "CLOUDTRAIL_PREFIX": "AWSLogs/1/CloudTrail",
        "REGIONS": "us-east-1, us-west-2",
        "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:1:t",
        "STRATA_CONFIG": '{"allow": []}',
    }
    s = Settings.from_env(env)
    assert s.prefix.endswith("/") and s.regions == ["us-east-1", "us-west-2"] and s.config == {"allow": []}
    with pytest.raises(ValueError, match="REGIONS"):
        Settings.from_env({k: v for k, v in env.items() if k != "REGIONS"})
    with pytest.raises(ValueError, match="MIN_SEVERITY"):
        Settings.from_env({**env, "MIN_SEVERITY": "URGENT"})
    with pytest.raises(ValueError, match="larger"):
        Settings.from_env({**env, "LOOKBACK_MINUTES": "30"})


def test_lambda_package_is_importable_and_reproducible(tmp_path):
    import subprocess
    import sys
    import zipfile

    sys.path.insert(0, str(ROOT / "scripts"))
    import build_lambda

    a, _ = build_lambda.build(tmp_path / "a.zip")
    b, _ = build_lambda.build(tmp_path / "b.zip")
    assert a.read_bytes() == b.read_bytes()
    with zipfile.ZipFile(a) as zf:
        names = zf.namelist()
        zf.extractall(tmp_path / "pkg")
    assert "strata/aws_lambda.py" in names
    # Import the handler from the unzipped package only, the way Lambda will.
    pkg = tmp_path / "pkg"
    code = (
        f"import sys; sys.path.insert(0, {str(pkg)!r}); import strata.aws_lambda as m; "
        "assert callable(m.handler); print(m.__file__)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=tmp_path, check=True)
    assert str(pkg) in out.stdout
