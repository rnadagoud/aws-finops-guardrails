# AWS Cost & Security Hygiene — Executive Audit Report

- **AWS Account:** `123456789012 (Demo SaaS Startup)`
- **Regions Scanned:** `ap-south-1, us-east-1` (+ Global S3)
- **Generated:** `2026-11-26 01:48 UTC` (`demo` mode)
- **Identified Monthly Savings:** **$472.61 / month**
- **Projected Annualized Savings:** **$5,671.32 / year**
- **Findings Breakdown:** 9 total (5 HIGH, 2 MEDIUM, 2 LOW)

---

## Prioritized Findings

| Severity | Check | Category | Resource | Region | Est. Save / Mo | Est. Save / Yr |
| :--- | :--- | :--- | :--- | :--- | ---: | ---: |
| **HIGH** | `RDS-001` | Idle / Oversized RDS | `staging-analytics-pg (db.m5.large, Multi-AZ)` | `us-east-1` | $225.00 | $2,700.00 |
| **HIGH** | `NET-002` | Idle / Low-Traffic NAT Gateway | `nat-0a84f91e32b71c002 & nat-0f19c82d44e10a119 (2 redundant dev AZs)` | `us-east-1` | $65.70 | $788.40 |
| **HIGH** | `CMP-001` | Idle / Oversized EC2 | `i-094c2e17b83a510f4 (t3.xlarge)` | `ap-south-1` | $60.80 | $729.60 |
| **HIGH** | `EBS-001` | Unattached EBS Volume | `vol-07c3910ab52e8f110 (500 GB gp2)` | `us-east-1` | $50.00 | $600.00 |
| **HIGH** | `S3-001` | S3 Lifecycle & Hygiene | `s3://acme-app-debug-exports-2024` | `global` | $8.50 | $102.00 |
| **MEDIUM** | `EBS-002` | GP2 to GP3 Upgrade | `4x prod EBS volumes (1,200 GB total gp2)` | `us-east-1` | $24.00 | $288.00 |
| **MEDIUM** | `ELB-001` | Idle Load Balancer | `old-v1-api-alb (application)` | `ap-south-1` | $16.43 | $197.16 |
| **LOW** | `EBS-003` | Aging EBS Snapshot | `18x manual snapshots (>180 days old, 850 GB source)` | `us-east-1` | $14.88 | $178.56 |
| **LOW** | `NET-001` | Unassociated Elastic IP | `eipalloc-04d8e91c22f0a1234 (3.110.x.x) + 1 more` | `ap-south-1` | $7.30 | $87.60 |

---

## Actionable Remediation Runbook

### 1. [HIGH] Idle / Oversized RDS — `staging-analytics-pg (db.m5.large, Multi-AZ)` (`us-east-1`)
- **Estimated Savings:** $225.00/mo ($2,700.00/yr)
- **Diagnosis:** 14-day average CPU is 1.4% with near-zero DB connections. Staging DB left on Multi-AZ db.m5.large 24/7.
- **Verify & Remediate (AWS CLI):**
```bash
aws rds modify-db-instance --region us-east-1 --db-instance-identifier staging-analytics-pg --no-multi-az --db-instance-class db.t4g.medium --apply-immediately
```

### 2. [HIGH] Idle / Low-Traffic NAT Gateway — `nat-0a84f91e32b71c002 & nat-0f19c82d44e10a119 (2 redundant dev AZs)` (`us-east-1`)
- **Estimated Savings:** $65.70/mo ($788.40/yr)
- **Diagnosis:** 3 NAT Gateways provisioned in dev VPC; 2 AZs processed <0.15 GB in 14 days + missing free S3 Gateway VPC Endpoint.
- **Verify & Remediate (AWS CLI):**
```bash
aws ec2 delete-nat-gateway --region us-east-1 --nat-gateway-id nat-0a84f91e32b71c002
```

### 3. [HIGH] Idle / Oversized EC2 — `i-094c2e17b83a510f4 (t3.xlarge)` (`ap-south-1`)
- **Estimated Savings:** $60.80/mo ($729.60/yr)
- **Diagnosis:** 14-day average CPU is 2.8% on legacy worker host. Candidate for t3.large / t4g.large Graviton right-sizing.
- **Verify & Remediate (AWS CLI):**
```bash
aws ec2 stop-instances --region ap-south-1 --instance-ids i-094c2e17b83a510f4
```

### 4. [HIGH] Unattached EBS Volume — `vol-07c3910ab52e8f110 (500 GB gp2)` (`us-east-1`)
- **Estimated Savings:** $50.00/mo ($600.00/yr)
- **Diagnosis:** 500 GB gp2 volume in 'available' state left behind after old migration cutover.
- **Verify & Remediate (AWS CLI):**
```bash
aws ec2 create-snapshot --region us-east-1 --volume-id vol-07c3910ab52e8f110 --description 'Pre-delete backup' && aws ec2 delete-volume --region us-east-1 --volume-id vol-07c3910ab52e8f110
```

### 5. [HIGH] S3 Lifecycle & Hygiene — `s3://acme-app-debug-exports-2024` (`global`)
- **Estimated Savings:** $8.50/mo ($102.00/yr)
- **Diagnosis:** Bucket missing S3 Lifecycle policy (unbounded Standard-tier log growth) + PublicAccessBlock INCOMPLETE.
- **Verify & Remediate (AWS CLI):**
```bash
aws s3api put-public-access-block --bucket acme-app-debug-exports-2024 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 6. [MEDIUM] GP2 to GP3 Upgrade — `4x prod EBS volumes (1,200 GB total gp2)` (`us-east-1`)
- **Estimated Savings:** $24.00/mo ($288.00/yr)
- **Diagnosis:** In-use 1,200 GB gp2 volumes can be modified online with zero downtime to gp3 (~20% cheaper + 3,000 baseline IOPS).
- **Verify & Remediate (AWS CLI):**
```bash
aws ec2 modify-volume --region us-east-1 --volume-id vol-01ab23cd45ef67890 --volume-type gp3
```

### 7. [MEDIUM] Idle Load Balancer — `old-v1-api-alb (application)` (`ap-south-1`)
- **Estimated Savings:** $16.43/mo ($197.16/yr)
- **Diagnosis:** Load balancer has 0 registered targets while incurring ~$16.43/mo fixed hourly charges.
- **Verify & Remediate (AWS CLI):**
```bash
aws elbv2 delete-load-balancer --region ap-south-1 --load-balancer-arn arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/old-v1-api-alb/0000
```

### 8. [LOW] Aging EBS Snapshot — `18x manual snapshots (>180 days old, 850 GB source)` (`us-east-1`)
- **Estimated Savings:** $14.88/mo ($178.56/yr)
- **Diagnosis:** Orphaned pre-release snapshots >180 days old with no Data Lifecycle Manager retention policy.
- **Verify & Remediate (AWS CLI):**
```bash
aws ec2 delete-snapshot --region us-east-1 --snapshot-id snap-0abc12345def67890
```

### 9. [LOW] Unassociated Elastic IP — `eipalloc-04d8e91c22f0a1234 (3.110.x.x) + 1 more` (`ap-south-1`)
- **Estimated Savings:** $7.30/mo ($87.60/yr)
- **Diagnosis:** 2 unassociated IPv4 Elastic IPs incurring idle public IPv4 charges ($0.005/hr each).
- **Verify & Remediate (AWS CLI):**
```bash
aws ec2 release-address --region ap-south-1 --allocation-id eipalloc-04d8e91c22f0a1234
```

---
*Generated by [aws-finops-guardrails](https://github.com/rnadagoud/aws-finops-guardrails) — Metadata-only read scan (zero customer data or secret access).*
