# ADR-001: Custom Metadata-Only IAM Policy Instead of AWS Managed `ReadOnlyAccess`

- **Status:** Accepted
- **Date:** 2026-11-26
- **Author:** Rahul Nadagoud

## Context
When performing a 7-day AWS Cost & Security Health Audit for a startup or SMB client, the #1 objection from CTOs is security risk:
> *"If we grant an external consultant AWS `ReadOnlyAccess`, can they read our S3 customer files, SSM parameters, or database backups?"*

Surprisingly, the AWS-managed `arn:aws:iam::aws:policy/ReadOnlyAccess` policy **does** grant `s3:GetObject` across buckets and broad read access to sensitive configuration metadata — creating unnecessary blast radius during a billing and infrastructure audit. ( AWS also provides `ViewOnlyAccess`, which is safer, yet still grants hundreds of unused service permissions.)

## Decision
1. Provision a dedicated cross-account IAM Role (`aws_iam_role.readonly_auditor`) requiring **`sts:ExternalId`** on `sts:AssumeRole` (mitigating the confused-deputy problem) and capped at a 1-hour `max_session_duration`.
2. Attach an **explicit, 19-action metadata-only inline IAM policy** split cleanly into:
   - Unrestrictable account-level `Describe*` / `GetMetric*` actions on `resources = ["*"]`, and
   - Resource-scoped metadata reads (`rds:DescribeDBInstances`, `budgets:ViewBudget`, and `s3:Get*Configuration` restricted via `aws:ResourceAccount` to the target AWS account's buckets only — verified in CI by Checkov `CKV_AWS_356`).
3. **Never** include `s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `kms:Decrypt`, or `dynamodb:Scan`/`GetItem`.

## Consequences
- **Pros:** Clients can review the entire IAM policy in 30 seconds before applying Terraform; zero access to customer PII, object contents, or application secrets; zero static IAM user keys ever created.
- **Trade-offs:** Adding a 9th check for a new AWS service (e.g., OpenSearch or ElastiCache) requires explicitly adding its `Describe*` action to `terraform/main.tf`. That friction is intentional.
