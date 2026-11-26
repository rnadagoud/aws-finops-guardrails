# Ready-to-apply Sandbox Guardrail ($5 / $15 / $30 alerts on a $30 ceiling)
# Usage:
#   terraform init
#   terraform apply -var="alert_email=aravnadagoud@gmail.com" -var="audit_external_id=$(openssl rand -hex 16)"

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "ap-south-1"
}

variable "alert_email" {
  type        = string
  description = "Email address for $5 / $15 / $30 AWS budget alerts."
}

variable "audit_external_id" {
  type        = string
  sensitive   = true
  description = "Unique ExternalId (>=12 chars) for read-only waste scanner role."
}

module "finops_guardrails" {
  source = "../../terraform"

  name_prefix              = "sandbox-finops"
  monthly_budget_limit_usd = 30
  # 17% (~$5), 50% ($15), 100% ($30) hard budget alerts
  budget_alert_thresholds_percent = [17, 50, 100]
  enable_forecasted_alert         = true
  alert_emails                    = [var.alert_email]
  anomaly_threshold_usd           = 5
  enable_readonly_audit_role      = true
  audit_external_id               = var.audit_external_id
}

output "audit_role_arn" {
  value = module.finops_guardrails.readonly_auditor_role_arn
}
