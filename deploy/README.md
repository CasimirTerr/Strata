# Running Strata in AWS

The Terraform in `terraform/` runs Strata as a Lambda function on a schedule. Every hour it reads the CloudTrail files delivered in the last two hours, scans them together, and sends new findings to an SNS topic.

```
EventBridge schedule ─▶ Lambda ─▶ reads CloudTrail files in S3 (last 2 hours)
  (every 60 min)           │
                           └─▶ SNS topic ─▶ email, Slack, PagerDuty, SIEM
CloudWatch alarm on Lambda errors ─────────▶ same SNS topic
```

## Why it reads two hours but alerts on one

Attack chains can start before one run and finish after it. Reading two hours of files lets each run see the whole chain. To avoid repeat alerts, a run only reports detections from files that **arrived** since the last run. Strata goes by S3 delivery time, not event time, because CloudTrail can deliver an event several minutes after it happened. Going by delivery time means a late event still lands in exactly one run.

## Deploy

```bash
python scripts/build_lambda.py          # writes build/strata-lambda.zip
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars   # then edit it
terraform init
terraform plan
terraform apply
```

If you set `alert_email`, AWS sends a confirmation email you have to click before alerts arrive.

## What it's allowed to do

The function's role can only:

- list objects under your CloudTrail prefix (`s3:ListBucket` with an `s3:prefix` condition)
- read objects under that prefix (`s3:GetObject`)
- publish to its own SNS topic
- write to its own log group
- decrypt with your KMS key, only if you set `kms_key_arn`

Nothing else, and nothing that writes to your logs or your account.

## Settings

| Variable | Default | What it does |
| --- | --- | --- |
| `cloudtrail_bucket` | required | Bucket your trail writes to |
| `cloudtrail_prefix` | required | Path down to the region folders, ending in `/CloudTrail/` |
| `regions` | `["us-east-1"]` | Regions to read |
| `alert_email` | none | Email to subscribe to alerts |
| `min_severity` | `HIGH` | Lowest severity that alerts. Attack chains always alert. |
| `schedule_minutes` | `60` | How often it runs |
| `lookback_minutes` | `120` | How much history each run reads. Keep it at least double the schedule. |
| `strata_config` | none | Allowlist and agent Lambdas as JSON, same format as the CLI's `--config` |
| `kms_key_arn` | none | Key for SSE-KMS encrypted trails |

## Cost

At the default settings it's 720 runs a month, each a few seconds long. That's within the Lambda free tier for most accounts. The S3 GET requests are the main cost, and those scale with how many CloudTrail files you have.

## Testing it without waiting an hour

```bash
aws lambda invoke --function-name strata out.json && cat out.json
```

The output shows how many files and events it read and how many alerts it sent.
