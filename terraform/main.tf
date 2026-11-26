data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  trusted_auditor_arn = (
    var.auditor_principal_arn != ""
    ? var.auditor_principal_arn
    : "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"
  )
}

# ------------------------------------------------------------------------------
# KMS Key (Encrypted SNS Alerts — satisfies Checkov CKV_AWS_26 & KMS rotation)
# Note: In an AWS KMS resource policy, resources = ["*"] refers strictly to THIS
# KMS key (referencing aws_kms_key.this.arn creates a Terraform cycle). Checkov
# evaluates standalone aws_iam_policy_document blocks as identity policies unless
# annotated.
# ------------------------------------------------------------------------------
data "aws_iam_policy_document" "sns_kms" {
  #checkov:skip=CKV_AWS_109:KMS key policy requires root delegation on "*" (refers only to this KMS key).
  #checkov:skip=CKV_AWS_111:KMS key policy requires kms:* for account root and GenerateDataKey* for AWS Budgets/Anomaly services on this key.
  #checkov:skip=CKV_AWS_356:AWS KMS key resource policies mandate Resource = "*" to represent the key itself without circular ARN references.

  statement {
    sid       = "EnableRootAccountPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowBudgetsAndCostAnomalyToUseKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*"
    ]
    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "budgets.amazonaws.com",
        "costalerts.amazonaws.com"
      ]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "finops_alerts" {
  description             = "KMS key encrypting ${var.name_prefix} SNS billing & anomaly notifications"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.sns_kms.json
  tags                    = var.tags
}

resource "aws_kms_alias" "finops_alerts" {
  name          = "alias/${var.name_prefix}-alerts"
  target_key_id = aws_kms_key.finops_alerts.key_id
}

# ------------------------------------------------------------------------------
# SNS Topic & Subscriptions for Budget + Cost Anomaly Alerts
# ------------------------------------------------------------------------------
resource "aws_sns_topic" "finops_alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = aws_kms_key.finops_alerts.id
  tags              = var.tags
}

data "aws_iam_policy_document" "finops_sns_topic" {
  statement {
    sid       = "AllowAWSBudgetsPublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.finops_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["budgets.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid       = "AllowCostAnomalyPublish"
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.finops_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["costalerts.amazonaws.com"]
    }
  }
}

resource "aws_sns_topic_policy" "finops_alerts" {
  arn    = aws_sns_topic.finops_alerts.arn
  policy = data.aws_iam_policy_document.finops_sns_topic.json
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.finops_alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# ------------------------------------------------------------------------------
# Multi-Threshold Monthly AWS Cost Budget
# ------------------------------------------------------------------------------
resource "aws_budgets_budget" "monthly_cost" {
  name              = "${var.name_prefix}-monthly-usd"
  budget_type       = "COST"
  limit_amount      = tostring(var.monthly_budget_limit_usd)
  limit_unit        = "USD"
  time_unit         = "MONTHLY"
  time_period_start = "2026-01-01_00:00"

  dynamic "notification" {
    for_each = toset([for t in var.budget_alert_thresholds_percent : tostring(t)])
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = tonumber(notification.value)
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_sns_topic_arns  = [aws_sns_topic.finops_alerts.arn]
      subscriber_email_addresses = var.alert_emails
    }
  }

  dynamic "notification" {
    for_each = var.enable_forecasted_alert ? [1] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 100
      threshold_type             = "PERCENTAGE"
      notification_type          = "FORECASTED"
      subscriber_sns_topic_arns  = [aws_sns_topic.finops_alerts.arn]
      subscriber_email_addresses = var.alert_emails
    }
  }

  tags = var.tags
}

# ------------------------------------------------------------------------------
# AWS Cost Anomaly Detection (Catches sudden runaway EC2/NAT/Bedrock spikes)
# ------------------------------------------------------------------------------
resource "aws_ce_anomaly_monitor" "service_monitor" {
  name              = "${var.name_prefix}-service-monitor"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
  tags              = var.tags
}

resource "aws_ce_anomaly_subscription" "alerts" {
  name      = "${var.name_prefix}-anomaly-alerts"
  frequency = "IMMEDIATE"

  monitor_arn_list = [
    aws_ce_anomaly_monitor.service_monitor.arn
  ]

  subscriber {
    type    = "SNS"
    address = aws_sns_topic.finops_alerts.arn
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(var.anomaly_threshold_usd)]
    }
  }

  tags = var.tags
}

# ------------------------------------------------------------------------------
# Least-Privilege Read-Only IAM Audit Role (Zero Data/Secret Read Access!)
# ------------------------------------------------------------------------------
data "aws_iam_policy_document" "audit_assume_role" {
  count = var.enable_readonly_audit_role ? 1 : 0

  statement {
    sid     = "RequireExternalIdForAuditAssumeRole"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.trusted_auditor_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.audit_external_id]
    }
  }
}

resource "aws_iam_role" "readonly_auditor" {
  count                = var.enable_readonly_audit_role ? 1 : 0
  name                 = "${var.name_prefix}-readonly-auditor"
  description          = "Strictly scoped metadata-only IAM role for FinOps waste scanning (cannot read S3 objects, DB rows, or Secrets)."
  assume_role_policy   = data.aws_iam_policy_document.audit_assume_role[0].json
  max_session_duration = 3600
  tags                 = var.tags
}

data "aws_iam_policy_document" "readonly_auditor_permissions" {
  count = var.enable_readonly_audit_role ? 1 : 0

  # 1. Actions that AWS IAM does NOT allow scoping to specific resource ARNs.
  statement {
    sid    = "UnrestrictableAccountMetadataDescribe"
    effect = "Allow"
    actions = [
      "ec2:DescribeVolumes",
      "ec2:DescribeSnapshots",
      "ec2:DescribeAddresses",
      "ec2:DescribeInstances",
      "ec2:DescribeNatGateways",
      "ec2:DescribeRegions",
      "s3:ListAllMyBuckets",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "cloudwatch:GetMetricStatistics",
      "cloudwatch:GetMetricData",
      "ce:GetCostAndUsage",
      "sts:GetCallerIdentity"
    ]
    resources = ["*"]
  }

  # 2. Actions that support resource-level ARN scoping — restricted to this account's resources.
  # Explicitly excludes s3:GetObject, secretsmanager:GetSecretValue, ssm:GetParameter, dynamodb:Scan, etc.
  statement {
    sid    = "ScopedAccountMetadataRead"
    effect = "Allow"
    actions = [
      "rds:DescribeDBInstances",
      "budgets:ViewBudget"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:rds:*:${data.aws_caller_identity.current.account_id}:db:*",
      "arn:${data.aws_partition.current.partition}:budgets::${data.aws_caller_identity.current.account_id}:budget/*"
    ]
  }

  statement {
    sid    = "ScopedS3BucketHygieneMetadata"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetLifecycleConfiguration",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetEncryptionConfiguration"
    ]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::*"
    ]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role_policy" "readonly_auditor" {
  count  = var.enable_readonly_audit_role ? 1 : 0
  name   = "${var.name_prefix}-metadata-scan-policy"
  role   = aws_iam_role.readonly_auditor[0].id
  policy = data.aws_iam_policy_document.readonly_auditor_permissions[0].json
}
