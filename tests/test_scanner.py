from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

from finops_scanner.cli import main
from finops_scanner.report import render_html_report, render_markdown_report
from finops_scanner.scanner import (
    check_aging_snapshots,
    check_gp2_to_gp3,
    check_idle_ec2_and_rds,
    check_idle_load_balancers,
    check_nat_gateways,
    check_unassociated_eips,
    check_unattached_ebs,
    get_demo_audit_summary,
)


class TestFinOpsScannerChecks(unittest.TestCase):
    def test_check_unattached_ebs_flags_available_volume(self) -> None:
        ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Volumes": [{"VolumeId": "vol-123", "Size": 250, "VolumeType": "gp2"}]}
        ]
        ec2.get_paginator.return_value = paginator

        findings = check_unattached_ebs(ec2, "ap-south-1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].check_id, "EBS-001")
        self.assertEqual(findings[0].estimated_monthly_savings_usd, 25.0)
        self.assertEqual(findings[0].severity, "HIGH")

    def test_check_gp2_to_gp3_calculates_20_percent_delta(self) -> None:
        ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Volumes": [{"VolumeId": "vol-gp2", "Size": 500, "VolumeType": "gp2"}]}
        ]
        ec2.get_paginator.return_value = paginator

        findings = check_gp2_to_gp3(ec2, "us-east-1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].estimated_monthly_savings_usd, 10.0)

    def test_check_aging_snapshots_filters_recent_and_flags_old(self) -> None:
        ec2 = MagicMock()
        paginator = MagicMock()
        old_date = datetime.now(timezone.utc) - timedelta(days=150)
        recent_date = datetime.now(timezone.utc) - timedelta(days=10)
        paginator.paginate.return_value = [
            {
                "Snapshots": [
                    {"SnapshotId": "snap-old", "StartTime": old_date, "VolumeSize": 200},
                    {"SnapshotId": "snap-new", "StartTime": recent_date, "VolumeSize": 200},
                ]
            }
        ]
        ec2.get_paginator.return_value = paginator

        findings = check_aging_snapshots(ec2, "us-east-1", max_age_days=90)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].resource_id, "snap-old")

    def test_check_unassociated_eips(self) -> None:
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = {
            "Addresses": [
                {"AllocationId": "eipalloc-free", "PublicIp": "1.2.3.4"},
                {"AllocationId": "eipalloc-used", "PublicIp": "5.6.7.8", "AssociationId": "eipassoc-1"},
            ]
        }
        findings = check_unassociated_eips(ec2, "ap-south-1")
        self.assertEqual(len(findings), 1)
        self.assertIn("eipalloc-free", findings[0].resource_id)

    def test_check_idle_ec2_and_rds(self) -> None:
        ec2 = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-idle", "InstanceType": "t3.xlarge"}]}]}
        ]
        ec2.get_paginator.return_value = paginator

        rds = MagicMock()
        rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "staging-db",
                    "DBInstanceStatus": "available",
                    "DBInstanceClass": "db.m5.large",
                    "MultiAZ": True,
                }
            ]
        }

        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": [{"Average": 1.2}]}

        findings = check_idle_ec2_and_rds(ec2, rds, cw, "us-east-1")
        self.assertEqual(len(findings), 2)
        check_ids = {f.check_id for f in findings}
        self.assertEqual(check_ids, {"CMP-001", "RDS-001"})

    def test_check_idle_load_balancers_and_nat_gateways(self) -> None:
        elbv2 = MagicMock()
        elbv2.describe_load_balancers.return_value = {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/my-alb/abcd",
                    "LoadBalancerName": "my-alb",
                    "Type": "application",
                }
            ]
        }
        elbv2.describe_target_groups.return_value = {"TargetGroups": []}

        ec2 = MagicMock()
        ec2.describe_nat_gateways.return_value = {
            "NatGateways": [{"NatGatewayId": "nat-idle123"}]
        }

        cw = MagicMock()
        cw.get_metric_statistics.return_value = {"Datapoints": [{"Sum": 0.0}]}

        lb_findings = check_idle_load_balancers(elbv2, cw, "us-east-1")
        nat_findings = check_nat_gateways(ec2, cw, "us-east-1")
        self.assertEqual(len(lb_findings), 1)
        self.assertEqual(len(nat_findings), 1)
        self.assertEqual(nat_findings[0].estimated_monthly_savings_usd, 32.85)

    def test_demo_cli_generates_valid_markdown_and_html_reports(self) -> None:
        summary = get_demo_audit_summary()
        self.assertGreater(summary.total_monthly_savings_usd, 400.0)
        md = render_markdown_report(summary)
        html_doc = render_html_report(summary)
        self.assertIn("Executive Audit Report", md)
        self.assertIn("Infrastructure Waste &amp; Security Guardrails Audit", html_doc)

        with tempfile.TemporaryDirectory() as tmp:
            rc = main(["--demo", "--output-dir", tmp])
            self.assertEqual(rc, 0)
            self.assertTrue((Path(tmp) / "executive-audit-report.md").exists())
            self.assertTrue((Path(tmp) / "executive-audit-report.html").exists())


if __name__ == "__main__":
    unittest.main()
