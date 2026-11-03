output "alerts_topic_arn" {
  description = "SNS topic that receives Strata alerts. Subscribe Slack, PagerDuty or a SIEM here."
  value       = aws_sns_topic.alerts.arn
}

output "function_name" {
  description = "Name of the Strata Lambda function."
  value       = aws_lambda_function.strata.function_name
}

output "log_group" {
  description = "Where the function writes its run summaries."
  value       = aws_cloudwatch_log_group.lambda.name
}
