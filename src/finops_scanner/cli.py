from __future__ import annotations

import argparse
import sys

from finops_scanner.report import write_reports
from finops_scanner.scanner import get_demo_audit_summary, run_live_audit


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="finops-scan",
        description="Read-only AWS infrastructure waste scanner and executive report generator.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Generate sample executive reports using realistic anonymized SaaS data (no AWS credentials needed).",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=["ap-south-1", "us-east-1"],
        help="AWS regions to scan in live mode (default: ap-south-1 us-east-1).",
    )
    parser.add_argument(
        "--role-arn",
        default=None,
        help="Optional cross-account read-only IAM Role ARN to assume via STS.",
    )
    parser.add_argument(
        "--external-id",
        default=None,
        help="ExternalId condition value required when --role-arn is specified.",
    )
    parser.add_argument(
        "--snapshot-days",
        type=int,
        default=90,
        help="Flag EBS snapshots older than N days (default: 90).",
    )
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory where executive-audit-report.{md,html} will be written (default: ./reports).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.demo:
        summary = get_demo_audit_summary()
    else:
        summary = run_live_audit(
            regions=args.regions,
            role_arn=args.role_arn,
            external_id=args.external_id,
            snapshot_days=args.snapshot_days,
        )

    md_path, html_path = write_reports(summary, args.output_dir)
    print(f"[finops-scan] Scanned account: {summary.account_id} ({summary.mode} mode)")
    print(f"[finops-scan] Findings: {len(summary.findings)}")
    print(
        f"[finops-scan] Estimated savings: ${summary.total_monthly_savings_usd:,.2f}/mo "
        f"(${summary.total_annual_savings_usd:,.2f}/yr)"
    )
    print(f"[finops-scan] Markdown report -> {md_path}")
    print(f"[finops-scan] HTML report     -> {html_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
