output "sns_topic_arn" {
  description = "ARN of the KMS-encrypted SNS topic receiving budget and cost-anomaly alerts."
  value       = aws_sns_topic.finops_alerts.arn
}

output "budget_name" {
  description = "Name of the configured monthly AWS cost budget."
  value       = aws_budgets_budget.monthly_cost.name
}

output "anomaly_monitor_arn" {
  description = "ARN of the AWS Cost Anomaly Detection service monitor."
  value       = aws_ce_anomaly_monitor.service_monitor.arn
}

output "readonly_auditor_role_arn" {
  description = "ARN of the least-privilege read-only FinOps audit IAM role (if enabled)."
  value       = var.enable_readonly_audit_role ? aws_iam_role.readonly_auditor[0].arn : null
}
