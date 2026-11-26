variable "name_prefix" {
  description = "Prefix applied to FinOps guardrail resources."
  type        = string
  default     = "finops-guardrails"
}

variable "monthly_budget_limit_usd" {
  description = "Hard monthly AWS cost budget ceiling in USD."
  type        = number

  validation {
    condition     = var.monthly_budget_limit_usd > 0
    error_message = "monthly_budget_limit_usd must be greater than 0."
  }
}

variable "budget_alert_thresholds_percent" {
  description = "Percentage thresholds of monthly_budget_limit_usd that trigger ACTUAL spend alerts (e.g. [33, 80, 100])."
  type        = list(number)
  default     = [50, 80, 100]
}

variable "enable_forecasted_alert" {
  description = "Send an early-warning alert when forecasted monthly spend exceeds 100% of budget."
  type        = bool
  default     = true
}

variable "alert_emails" {
  description = "Email addresses subscribed to budget and cost-anomaly notifications."
  type        = list(string)

  validation {
    condition     = length(var.alert_emails) > 0
    error_message = "At least one alert email address is required."
  }
}

variable "anomaly_threshold_usd" {
  description = "Minimum absolute USD spike in daily spend required to trigger AWS Cost Anomaly Detection."
  type        = number
  default     = 10
}

variable "enable_readonly_audit_role" {
  description = "Create a least-privilege cross-account IAM role (protected by ExternalId) for read-only waste scanning."
  type        = bool
  default     = true
}

variable "auditor_principal_arn" {
  description = "Trusted AWS IAM principal ARN allowed to assume the read-only FinOps audit role. Defaults to current account root when empty."
  type        = string
  default     = ""
}

variable "audit_external_id" {
  description = "Unique ExternalId required during sts:AssumeRole to prevent confused-deputy attacks."
  type        = string
  default     = "change-me-unique-external-id"
  sensitive   = true

  validation {
    condition     = length(var.audit_external_id) >= 12
    error_message = "audit_external_id must be at least 12 characters."
  }
}

variable "tags" {
  description = "Common tags applied to all supported AWS resources."
  type        = map(string)
  default = {
    ManagedBy = "Terraform"
    Module    = "aws-finops-guardrails"
  }
}
