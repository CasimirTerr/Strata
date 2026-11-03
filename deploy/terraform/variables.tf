variable "name" {
  description = "Name used for the Lambda function, IAM role, SNS topic and schedule."
  type        = string
  default     = "strata"
}

variable "cloudtrail_bucket" {
  description = "S3 bucket your CloudTrail trail writes to."
  type        = string
}

variable "cloudtrail_prefix" {
  description = "Path down to the region folders, ending in a slash. For example AWSLogs/111122223333/CloudTrail/ or, for an organization trail, AWSLogs/o-abc123/111122223333/CloudTrail/."
  type        = string

  validation {
    condition     = endswith(var.cloudtrail_prefix, "/CloudTrail/")
    error_message = "cloudtrail_prefix must end with /CloudTrail/ (the folder that holds the region folders)."
  }
}

variable "regions" {
  description = "Regions whose CloudTrail files Strata should read."
  type        = list(string)
  default     = ["us-east-1"]
}

variable "alert_email" {
  description = "Email address to subscribe to alerts. Leave empty to subscribe something else to the topic yourself."
  type        = string
  default     = ""
}

variable "min_severity" {
  description = "Lowest severity that sends an alert. Attack chains always alert."
  type        = string
  default     = "HIGH"

  validation {
    condition     = contains(["CRITICAL", "HIGH", "MEDIUM", "LOW"], var.min_severity)
    error_message = "min_severity must be CRITICAL, HIGH, MEDIUM or LOW."
  }
}

variable "schedule_minutes" {
  description = "How often Strata runs. New files from this many minutes back are alerted on."
  type        = number
  default     = 60

  validation {
    condition     = var.schedule_minutes >= 5
    error_message = "schedule_minutes must be at least 5."
  }
}

variable "lookback_minutes" {
  description = "How much history each run reads for context, so attack chains that span two runs are still caught. Must be at least schedule_minutes."
  type        = number
  default     = 120
}

variable "strata_config" {
  description = "Optional JSON with \"agent_lambdas\" and \"allow\" lists, the same format as the CLI's --config file."
  type        = string
  default     = ""
}

variable "kms_key_arn" {
  description = "KMS key that encrypts the CloudTrail files, if the trail uses SSE-KMS. Leave empty otherwise."
  type        = string
  default     = ""
}

variable "lambda_zip" {
  description = "Path to the Lambda package built by scripts/build_lambda.py."
  type        = string
  default     = "../../build/strata-lambda.zip"
}

variable "log_retention_days" {
  description = "How long to keep the function's own logs."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags added to every resource."
  type        = map(string)
  default     = {}
}
