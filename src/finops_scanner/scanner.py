from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from finops_scanner.models import AuditSummary, Finding

# Conservative on-demand US/APAC baseline pricing estimates used for executive sizing
PRICE_GP2_PER_GB_MO = 0.10
PRICE_GP3_PER_GB_MO = 0.08
PRICE_EBS_SNAPSHOT_PER_GB_MO = 0.05
PRICE_IDLE_EIP_MO = 3.65  # $0.005/hr * 730h (AWS public IPv4 charge)
PRICE_ALB_NLB_BASE_MO = 16.43  # ~$0.0225/hr * 730h
PRICE_NAT_GATEWAY_BASE_MO = 32.85  # ~$0.045/hr * 730h

# Rough monthly on-demand baseline lookup by instance family/size prefix for quick sizing
EC2_APPROX_MONTHLY_USD: dict[str, float] = {
    "t3.micro": 7.6,
    "t3.small": 15.2,
    "t3.medium": 30.4,
    "t3.large": 60.8,
    "t3.xlarge": 121.6,
    "m5.large": 70.1,
    "m5.xlarge": 140.2,
    "m6i.large": 70.1,
    "c5.large": 62.0,
    "r5.large": 92.0,
}

RDS_APPROX_MONTHLY_USD: dict[str, float] = {
    "db.t3.micro": 12.4,
    "db.t3.small": 24.8,
    "db.t3.medium": 49.6,
    "db.t4g.medium": 47.0,
    "db.m5.large": 125.0,
    "db.r5.large": 175.0,
}


def build_boto3_session(role_arn: str | None = None, external_id: str | None = None) -> Any:
    """Build a boto3 Session, optionally assuming the read-only ExternalId audit role."""
    import boto3

    base_session = boto3.Session()
    if not role_arn:
        return base_session

    sts = base_session.client("sts")
    assume_kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": "finops-guardrails-readonly-scan",
        "DurationSeconds": 3600,
    }
    if external_id:
        assume_kwargs["ExternalId"] = external_id

    creds = sts.assume_role(**assume_kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _avg_cloudwatch_metric(
    cw_client: Any,
    namespace: str,
    metric_name: str,
    dimensions: list[dict[str, str]],
    days: int = 14,
    stat: str = "Average",
) -> float | None:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    resp = cw_client.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        Dimensions=dimensions,
        StartTime=start,
        EndTime=end,
        Period=86400,
        Statistics=[stat],
    )
    points = resp.get("Datapoints", [])
    if not points:
        return None
    if stat == "Sum":
        return float(sum(p[stat] for p in points))
    return float(sum(p[stat] for p in points) / len(points))


# ------------------------------------------------------------------------------
# Check 1: Unattached EBS Volumes
# ------------------------------------------------------------------------------
def check_unattached_ebs(ec2_client: Any, region: str) -> list[Finding]:
    findings: list[Finding] = []
    paginator = ec2_client.get_paginator("describe_volumes")
    for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
        for vol in page.get("Volumes", []):
            vol_id = vol["VolumeId"]
            size_gb = int(vol.get("Size", 0))
            vol_type = vol.get("VolumeType", "gp3")
            rate = PRICE_GP2_PER_GB_MO if vol_type == "gp2" else PRICE_GP3_PER_GB_MO
            savings = round(size_gb * rate, 2)
            findings.append(
                Finding(
                    check_id="EBS-001",
                    category="Unattached EBS Volume",
                    severity="HIGH" if savings >= 20 else "MEDIUM",
                    resource_id=vol_id,
                    region=region,
                    estimated_monthly_savings_usd=savings,
                    summary=f"{size_gb} GB {vol_type} volume in 'available' state (unattached to any EC2 instance).",
                    remediation_cli=(
                        f"aws ec2 create-snapshot --region {region} --volume-id {vol_id} "
                        f"--description 'Pre-delete backup {vol_id}' && "
                        f"aws ec2 delete-volume --region {region} --volume-id {vol_id}"
                    ),
                )
            )
    return findings


# ------------------------------------------------------------------------------
# Check 2: Legacy GP2 Volumes Eligible for Zero-Downtime GP3 Upgrade
# ------------------------------------------------------------------------------
def check_gp2_to_gp3(ec2_client: Any, region: str) -> list[Finding]:
    findings: list[Finding] = []
    paginator = ec2_client.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[
            {"Name": "volume-type", "Values": ["gp2"]},
            {"Name": "status", "Values": ["in-use"]},
        ]
    ):
        for vol in page.get("Volumes", []):
            vol_id = vol["VolumeId"]
            size_gb = int(vol.get("Size", 0))
            savings = round(size_gb * (PRICE_GP2_PER_GB_MO - PRICE_GP3_PER_GB_MO), 2)
            if savings < 1.0:
                continue
            findings.append(
                Finding(
                    check_id="EBS-002",
                    category="GP2 to GP3 Upgrade",
                    severity="LOW" if savings < 15 else "MEDIUM",
                    resource_id=vol_id,
                    region=region,
                    estimated_monthly_savings_usd=savings,
                    summary=f"In-use {size_gb} GB gp2 volume can be modified in-place to gp3 (~20% lower storage cost + 3,000 baseline IOPS).",
                    remediation_cli=f"aws ec2 modify-volume --region {region} --volume-id {vol_id} --volume-type gp3",
                )
            )
    return findings


# ------------------------------------------------------------------------------
# Check 3: Aging EBS Snapshots (> N days)
# ------------------------------------------------------------------------------
def check_aging_snapshots(ec2_client: Any, region: str, max_age_days: int = 90) -> list[Finding]:
    findings: list[Finding] = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    paginator = ec2_client.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"]):
        for snap in page.get("Snapshots", []):
            start_time: datetime = snap["StartTime"]
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            if start_time < cutoff:
                snap_id = snap["SnapshotId"]
                size_gb = int(snap.get("VolumeSize", 0))
                age_days = (datetime.now(timezone.utc) - start_time).days
                # Incremental blocks typically average ~35% of full volume size in conservative sizing
                est_stored_gb = max(1.0, size_gb * 0.35)
                savings = round(est_stored_gb * PRICE_EBS_SNAPSHOT_PER_GB_MO, 2)
                findings.append(
                    Finding(
                        check_id="EBS-003",
                        category="Aging EBS Snapshot",
                        severity="LOW" if savings < 15 else "MEDIUM",
                        resource_id=snap_id,
                        region=region,
                        estimated_monthly_savings_usd=savings,
                        summary=f"Snapshot is {age_days} days old (source volume {size_gb} GB). Verify AMI linkage or archive via Lifecycle Manager.",
                        remediation_cli=f"aws ec2 delete-snapshot --region {region} --snapshot-id {snap_id}",
                    )
                )
    return findings


# ------------------------------------------------------------------------------
# Check 4: Unassociated Public Elastic IPs
# ------------------------------------------------------------------------------
def check_unassociated_eips(ec2_client: Any, region: str) -> list[Finding]:
    findings: list[Finding] = []
    resp = ec2_client.describe_addresses()
    for addr in resp.get("Addresses", []):
        if not addr.get("AssociationId"):
            alloc_id = addr.get("AllocationId", addr.get("PublicIp", "unknown-eip"))
            pub_ip = addr.get("PublicIp", "")
            findings.append(
                Finding(
                    check_id="NET-001",
                    category="Unassociated Elastic IP",
                    severity="LOW",
                    resource_id=f"{alloc_id} ({pub_ip})".strip(),
                    region=region,
                    estimated_monthly_savings_usd=PRICE_IDLE_EIP_MO,
                    summary="Allocated public IPv4 Elastic IP is not attached to any ENI/instance ($0.005/hr idle charge).",
                    remediation_cli=f"aws ec2 release-address --region {region} --allocation-id {alloc_id}",
                )
            )
    return findings


# ------------------------------------------------------------------------------
# Check 5: Idle / Low-CPU EC2 & RDS Instances (14-Day CloudWatch Metrics)
# ------------------------------------------------------------------------------
def check_idle_ec2_and_rds(
    ec2_client: Any, rds_client: Any, cw_client: Any, region: str
) -> list[Finding]:
    findings: list[Finding] = []

    # EC2 Running Instances
    paginator = ec2_client.get_paginator("describe_instances")
    for page in paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    ):
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                inst_id = inst["InstanceId"]
                inst_type = inst.get("InstanceType", "t3.medium")
                avg_cpu = _avg_cloudwatch_metric(
                    cw_client,
                    "AWS/EC2",
                    "CPUUtilization",
                    [{"Name": "InstanceId", "Value": inst_id}],
                )
                if avg_cpu is not None and avg_cpu < 5.0:
                    base_cost = EC2_APPROX_MONTHLY_USD.get(inst_type, 45.0)
                    # Conservative 50% right-size savings (or 100% if non-prod stopped)
                    savings = round(base_cost * 0.50, 2)
                    findings.append(
                        Finding(
                            check_id="CMP-001",
                            category="Idle / Oversized EC2",
                            severity="HIGH" if savings >= 40 else "MEDIUM",
                            resource_id=f"{inst_id} ({inst_type})",
                            region=region,
                            estimated_monthly_savings_usd=savings,
                            summary=f"14-day average CPU is {avg_cpu:.1f}%. Candidate for downsizing one tier, Graviton migration, or dev stop-schedule.",
                            remediation_cli=f"aws ec2 stop-instances --region {region} --instance-ids {inst_id}",
                        )
                    )

    # RDS Available DB Instances
    rds_resp = rds_client.describe_db_instances()
    for db in rds_resp.get("DBInstances", []):
        if db.get("DBInstanceStatus") != "available":
            continue
        db_id = db["DBInstanceIdentifier"]
        db_class = db.get("DBInstanceClass", "db.t3.medium")
        multi_az = bool(db.get("MultiAZ", False))
        avg_cpu = _avg_cloudwatch_metric(
            cw_client,
            "AWS/RDS",
            "CPUUtilization",
            [{"Name": "DBInstanceIdentifier", "Value": db_id}],
        )
        avg_conns = _avg_cloudwatch_metric(
            cw_client,
            "AWS/RDS",
            "DatabaseConnections",
            [{"Name": "DBInstanceIdentifier", "Value": db_id}],
        )
        if avg_cpu is not None and avg_cpu < 5.0:
            base_cost = RDS_APPROX_MONTHLY_USD.get(db_class, 60.0) * (2.0 if multi_az else 1.0)
            is_zero_conn = avg_conns is not None and avg_conns < 0.2
            savings = round(base_cost * (0.90 if is_zero_conn else 0.45), 2)
            conn_note = "near-zero DB connections" if is_zero_conn else f"avg {avg_conns or 0:.1f} connections"
            findings.append(
                Finding(
                    check_id="RDS-001",
                    category="Idle / Oversized RDS",
                    severity="HIGH" if savings >= 40 else "MEDIUM",
                    resource_id=f"{db_id} ({db_class}{', Multi-AZ' if multi_az else ''})",
                    region=region,
                    estimated_monthly_savings_usd=savings,
                    summary=f"14-day average CPU is {avg_cpu:.1f}% with {conn_note}. Downsize instance class, disable non-prod Multi-AZ, or snapshot & delete.",
                    remediation_cli=(
                        f"aws rds stop-db-instance --region {region} --db-instance-identifier {db_id}"
                    ),
                )
            )
    return findings


# ------------------------------------------------------------------------------
# Check 6: S3 Buckets Missing Lifecycle Rules & Public Access Block Check
# ------------------------------------------------------------------------------
def check_s3_lifecycle_and_security(s3_client: Any) -> list[Finding]:
    from botocore.exceptions import ClientError

    findings: list[Finding] = []
    buckets = s3_client.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        has_lifecycle = True
        try:
            s3_client.get_bucket_lifecycle_configuration(Bucket=name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "NoSuchLifecycleConfiguration":
                has_lifecycle = False

        public_blocked = False
        try:
            pab = s3_client.get_bucket_public_access_block(Bucket=name).get(
                "PublicAccessBlockConfiguration", {}
            )
            public_blocked = all(
                pab.get(k, False)
                for k in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            )
        except ClientError:
            public_blocked = False

        if not has_lifecycle or not public_blocked:
            sec_flag = " + PublicAccessBlock INCOMPLETE" if not public_blocked else ""
            findings.append(
                Finding(
                    check_id="S3-001",
                    category="S3 Lifecycle & Hygiene",
                    severity="HIGH" if not public_blocked else "LOW",
                    resource_id=f"s3://{name}",
                    region="global",
                    estimated_monthly_savings_usd=8.50 if not has_lifecycle else 0.0,
                    summary=(
                        f"Bucket missing S3 Lifecycle policy (unbounded Standard-tier growth & orphaned multipart uploads){sec_flag}."
                    ),
                    remediation_cli=(
                        f"aws s3api put-public-access-block --bucket {name} "
                        f"--public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ),
                )
            )
    return findings


# ------------------------------------------------------------------------------
# Check 7: Idle Application / Network Load Balancers
# ------------------------------------------------------------------------------
def check_idle_load_balancers(elbv2_client: Any, cw_client: Any, region: str) -> list[Finding]:
    findings: list[Finding] = []
    lbs = elbv2_client.describe_load_balancers().get("LoadBalancers", [])
    for lb in lbs:
        lb_arn = lb["LoadBalancerArn"]
        lb_name = lb["LoadBalancerName"]
        lb_type = lb.get("Type", "application")
        arn_suffix = "/".join(lb_arn.split("/")[-3:])

        tgs = elbv2_client.describe_target_groups(LoadBalancerArn=lb_arn).get("TargetGroups", [])
        has_targets = False
        for tg in tgs:
            health = elbv2_client.describe_target_health(
                TargetGroupArn=tg["TargetGroupArn"]
            ).get("TargetHealthDescriptions", [])
            if health:
                has_targets = True
                break

        namespace = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB"
        metric = "RequestCount" if lb_type == "application" else "ProcessedBytes"
        total_activity = _avg_cloudwatch_metric(
            cw_client,
            namespace,
            metric,
            [{"Name": "LoadBalancer", "Value": arn_suffix}],
            stat="Sum",
        )

        if (not has_targets) or (total_activity is not None and total_activity == 0):
            reason = "0 registered targets" if not has_targets else "0 traffic over 14 days"
            findings.append(
                Finding(
                    check_id="ELB-001",
                    category="Idle Load Balancer",
                    severity="MEDIUM",
                    resource_id=f"{lb_name} ({lb_type})",
                    region=region,
                    estimated_monthly_savings_usd=PRICE_ALB_NLB_BASE_MO,
                    summary=f"Load balancer has {reason} while incurring ~$16.43/mo fixed hourly charges.",
                    remediation_cli=f"aws elbv2 delete-load-balancer --region {region} --load-balancer-arn {lb_arn}",
                )
            )
    return findings


# ------------------------------------------------------------------------------
# Check 8: Idle or Redundant Non-Prod NAT Gateways
# ------------------------------------------------------------------------------
def check_nat_gateways(ec2_client: Any, cw_client: Any, region: str) -> list[Finding]:
    findings: list[Finding] = []
    nats = ec2_client.describe_nat_gateways(
        Filter=[{"Name": "state", "Values": ["available"]}]
    ).get("NatGateways", [])

    for nat in nats:
        nat_id = nat["NatGatewayId"]
        bytes_out = _avg_cloudwatch_metric(
            cw_client,
            "AWS/NATGateway",
            "BytesOutToDestination",
            [{"Name": "NatGatewayId", "Value": nat_id}],
            stat="Sum",
        )
        gb_14d = (bytes_out or 0.0) / (1024**3)
        if bytes_out is not None and gb_14d < 1.0:
            findings.append(
                Finding(
                    check_id="NET-002",
                    category="Idle / Low-Traffic NAT Gateway",
                    severity="HIGH",
                    resource_id=nat_id,
                    region=region,
                    estimated_monthly_savings_usd=PRICE_NAT_GATEWAY_BASE_MO,
                    summary=(
                        f"NAT Gateway processed only {gb_14d:.2f} GB in 14 days (~$32.85/mo fixed fee). "
                        f"Consider gateway VPC Endpoints (S3/DynamoDB are free) or consolidating dev AZ NATs."
                    ),
                    remediation_cli=f"aws ec2 delete-nat-gateway --region {region} --nat-gateway-id {nat_id}",
                )
            )
    return findings


def run_live_audit(
    regions: list[str],
    role_arn: str | None = None,
    external_id: str | None = None,
    snapshot_days: int = 90,
) -> AuditSummary:
    session = build_boto3_session(role_arn=role_arn, external_id=external_id)
    account_id = session.client("sts").get_caller_identity()["Account"]
    summary = AuditSummary(account_id=account_id, regions_scanned=regions, mode="live")

    # Global S3 check once
    s3_client = session.client("s3")
    summary.findings.extend(check_s3_lifecycle_and_security(s3_client))

    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        rds = session.client("rds", region_name=region)
        cw = session.client("cloudwatch", region_name=region)
        elbv2 = session.client("elbv2", region_name=region)

        summary.findings.extend(check_unattached_ebs(ec2, region))
        summary.findings.extend(check_gp2_to_gp3(ec2, region))
        summary.findings.extend(check_aging_snapshots(ec2, region, max_age_days=snapshot_days))
        summary.findings.extend(check_unassociated_eips(ec2, region))
        summary.findings.extend(check_idle_ec2_and_rds(ec2, rds, cw, region))
        summary.findings.extend(check_idle_load_balancers(elbv2, cw, region))
        summary.findings.extend(check_nat_gateways(ec2, cw, region))

    return summary


def get_demo_audit_summary() -> AuditSummary:
    """Realistic anonymized SaaS startup audit dataset for instant demo & CI validation."""
    return AuditSummary(
        account_id="123456789012 (Demo SaaS Startup)",
        regions_scanned=["ap-south-1", "us-east-1"],
        mode="demo",
        findings=[
            Finding(
                check_id="RDS-001",
                category="Idle / Oversized RDS",
                severity="HIGH",
                resource_id="staging-analytics-pg (db.m5.large, Multi-AZ)",
                region="us-east-1",
                estimated_monthly_savings_usd=225.00,
                summary="14-day average CPU is 1.4% with near-zero DB connections. Staging DB left on Multi-AZ db.m5.large 24/7.",
                remediation_cli="aws rds modify-db-instance --region us-east-1 --db-instance-identifier staging-analytics-pg --no-multi-az --db-instance-class db.t4g.medium --apply-immediately",
            ),
            Finding(
                check_id="NET-002",
                category="Idle / Low-Traffic NAT Gateway",
                severity="HIGH",
                resource_id="nat-0a84f91e32b71c002 & nat-0f19c82d44e10a119 (2 redundant dev AZs)",
                region="us-east-1",
                estimated_monthly_savings_usd=65.70,
                summary="3 NAT Gateways provisioned in dev VPC; 2 AZs processed <0.15 GB in 14 days + missing free S3 Gateway VPC Endpoint.",
                remediation_cli="aws ec2 delete-nat-gateway --region us-east-1 --nat-gateway-id nat-0a84f91e32b71c002",
            ),
            Finding(
                check_id="CMP-001",
                category="Idle / Oversized EC2",
                severity="HIGH",
                resource_id="i-094c2e17b83a510f4 (t3.xlarge)",
                region="ap-south-1",
                estimated_monthly_savings_usd=60.80,
                summary="14-day average CPU is 2.8% on legacy worker host. Candidate for t3.large / t4g.large Graviton right-sizing.",
                remediation_cli="aws ec2 stop-instances --region ap-south-1 --instance-ids i-094c2e17b83a510f4",
            ),
            Finding(
                check_id="EBS-001",
                category="Unattached EBS Volume",
                severity="HIGH",
                resource_id="vol-07c3910ab52e8f110 (500 GB gp2)",
                region="us-east-1",
                estimated_monthly_savings_usd=50.00,
                summary="500 GB gp2 volume in 'available' state left behind after old migration cutover.",
                remediation_cli="aws ec2 create-snapshot --region us-east-1 --volume-id vol-07c3910ab52e8f110 --description 'Pre-delete backup' && aws ec2 delete-volume --region us-east-1 --volume-id vol-07c3910ab52e8f110",
            ),
            Finding(
                check_id="EBS-002",
                category="GP2 to GP3 Upgrade",
                severity="MEDIUM",
                resource_id="4x prod EBS volumes (1,200 GB total gp2)",
                region="us-east-1",
                estimated_monthly_savings_usd=24.00,
                summary="In-use 1,200 GB gp2 volumes can be modified online with zero downtime to gp3 (~20% cheaper + 3,000 baseline IOPS).",
                remediation_cli="aws ec2 modify-volume --region us-east-1 --volume-id vol-01ab23cd45ef67890 --volume-type gp3",
            ),
            Finding(
                check_id="ELB-001",
                category="Idle Load Balancer",
                severity="MEDIUM",
                resource_id="old-v1-api-alb (application)",
                region="ap-south-1",
                estimated_monthly_savings_usd=16.43,
                summary="Load balancer has 0 registered targets while incurring ~$16.43/mo fixed hourly charges.",
                remediation_cli="aws elbv2 delete-load-balancer --region ap-south-1 --load-balancer-arn arn:aws:elasticloadbalancing:ap-south-1:123456789012:loadbalancer/app/old-v1-api-alb/0000",
            ),
            Finding(
                check_id="EBS-003",
                category="Aging EBS Snapshot",
                severity="LOW",
                resource_id="18x manual snapshots (>180 days old, 850 GB source)",
                region="us-east-1",
                estimated_monthly_savings_usd=14.88,
                summary="Orphaned pre-release snapshots >180 days old with no Data Lifecycle Manager retention policy.",
                remediation_cli="aws ec2 delete-snapshot --region us-east-1 --snapshot-id snap-0abc12345def67890",
            ),
            Finding(
                check_id="S3-001",
                category="S3 Lifecycle & Hygiene",
                severity="HIGH",
                resource_id="s3://acme-app-debug-exports-2024",
                region="global",
                estimated_monthly_savings_usd=8.50,
                summary="Bucket missing S3 Lifecycle policy (unbounded Standard-tier log growth) + PublicAccessBlock INCOMPLETE.",
                remediation_cli="aws s3api put-public-access-block --bucket acme-app-debug-exports-2024 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ),
            Finding(
                check_id="NET-001",
                category="Unassociated Elastic IP",
                severity="LOW",
                resource_id="eipalloc-04d8e91c22f0a1234 (3.110.x.x) + 1 more",
                region="ap-south-1",
                estimated_monthly_savings_usd=7.30,
                summary="2 unassociated IPv4 Elastic IPs incurring idle public IPv4 charges ($0.005/hr each).",
                remediation_cli="aws ec2 release-address --region ap-south-1 --allocation-id eipalloc-04d8e91c22f0a1234",
            ),
        ],
    )
