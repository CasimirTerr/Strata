data "aws_partition" "current" {}

locals {
  partition  = data.aws_partition.current.partition
  bucket_arn = "arn:${local.partition}:s3:::${var.cloudtrail_bucket}"

  environment = merge(
    {
      CLOUDTRAIL_BUCKET    = var.cloudtrail_bucket
      CLOUDTRAIL_PREFIX    = var.cloudtrail_prefix
      REGIONS              = join(",", var.regions)
      SNS_TOPIC_ARN        = aws_sns_topic.alerts.arn
      MIN_SEVERITY         = var.min_severity
      LOOKBACK_MINUTES     = tostring(var.lookback_minutes)
      ALERT_WINDOW_MINUTES = tostring(var.schedule_minutes)
    },
    var.strata_config == "" ? {} : { STRATA_CONFIG = var.strata_config },
  )
}

# Alerts

resource "aws_sns_topic" "alerts" {
  name = "${var.name}-alerts"
  tags = var.tags
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# Permissions: read only the CloudTrail prefix, publish only to this topic, write only its own logs.

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = var.name
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "ListCloudTrailPrefix"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["${var.cloudtrail_prefix}*"]
    }
  }

  statement {
    sid       = "ReadCloudTrailFiles"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arn}/${var.cloudtrail_prefix}*"]
  }

  statement {
    sid       = "PublishAlerts"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn == "" ? [] : [var.kms_key_arn]

    content {
      sid       = "DecryptCloudTrailFiles"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.name}-least-privilege"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

# Function

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = var.log_retention_days
  tags              = var.tags
}

resource "aws_lambda_function" "strata" {
  function_name    = var.name
  description      = "Scans recent CloudTrail files for attacks on Bedrock and AgentCore"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "strata.aws_lambda.handler"
  filename         = var.lambda_zip
  source_code_hash = filebase64sha256(var.lambda_zip)
  timeout          = 300
  memory_size      = 512
  tags             = var.tags

  environment {
    variables = local.environment
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]
}

# Schedule

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name}-schedule"
  description         = "Runs Strata every ${var.schedule_minutes} minutes"
  schedule_expression = "rate(${var.schedule_minutes} minutes)"
  tags                = var.tags
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.strata.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowScheduleInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.strata.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# If Strata itself fails, say so on the same topic instead of failing quietly.

resource "aws_cloudwatch_metric_alarm" "errors" {
  alarm_name          = "${var.name}-errors"
  alarm_description   = "Strata failed to run. Check its CloudWatch logs."
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  tags                = var.tags

  dimensions = {
    FunctionName = aws_lambda_function.strata.function_name
  }
}
