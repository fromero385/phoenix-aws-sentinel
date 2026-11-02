#!/usr/bin/env python3
"""
Phoenix AWS Sentinel — Local-First Architectural Cloud Leak & Zombie Asset Detector.

Autonomous, read-only scanner that detects silent infrastructure bleeds in AWS:
- Active NAT Gateways routing S3 traffic without a free Gateway VPC Endpoint ($0.045/GB bleed)
- Unattached EBS volumes lingering in 'available' state ($0.10/GB-month bleed)
- Legacy gp2 EBS volumes that can migrate to gp3 for immediate 20% savings
- Unassociated Elastic IPs incurring idle hourly reservation fees

Guarantees:
- 100% LOCAL-FIRST & ZERO TELEMETRY: No network telemetry, analytics, or phone-home requests.
- 100% READ-ONLY: Never requests or invokes Create/Delete/Modify/Put/Update actions.
- ZERO CREDENTIAL STORAGE: Never logs, transmits, or persists AWS credentials.
- NO SENSITIVE EXPOSURE: Differentiates model estimates from verified realized savings.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional


# ==============================================================================
# PRICING CONSTANTS (AWS US-East-1 Reference Standard)
# ==============================================================================
NAT_GATEWAY_DATA_PER_GB_USD = 0.045      # $45.00 per 1,000 GB processed
EBS_GP2_PRICE_PER_GB_MONTH_USD = 0.10    # $0.10 per GB-month
EBS_GP3_PRICE_PER_GB_MONTH_USD = 0.08    # $0.08 per GB-month (20% reduction)
IDLE_EIP_PRICE_PER_HOUR_USD = 0.005      # ~$3.65 per month for unassociated IPv4


@dataclass
class FindingConfidenceModel:
    """Explicit 5-tier finding confidence structure."""
    observed_resource: str
    estimated_waste: str
    estimated_savings: str
    recommendation: str
    verified_realized_savings: str  # Always $0.00 until verified in audited billing


@dataclass
class ArchitecturalFinding:
    finding_id: str
    category: str
    severity: str
    confidence: FindingConfidenceModel
    monthly_bleed_estimate_usd: float
    verified_realized_savings_usd: float
    resource_id: str
    resource_type: str
    region: str
    vpc_id: Optional[str]
    explanation: str
    remediation_action: str
    remediation_terraform_snippet: str
    remediation_cli_command: str
    is_non_destructive: bool = True
    data_source: str = "SYNTHETIC_DEMO"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SentinelReport:
    audit_id: str
    timestamp: str
    account_id: str
    region: str
    mode: str
    total_findings: int
    estimated_monthly_bleed_usd: float
    verified_realized_savings_usd: float
    findings: List[ArchitecturalFinding]
    differentiation_summary: Dict[str, Any]
    feedback_prompt: str
    disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AwsSentinelScanner:
    """Local-first scanner for AWS architecture leaks."""

    def __init__(self, mode: str = "SYNTHETIC_DEMO"):
        self.mode = mode

    def run_synthetic_audit(self, fixture_data: Optional[Dict[str, Any]] = None) -> SentinelReport:
        """Runs audit against synthetic or user-supplied JSON fixture."""
        fixture = fixture_data or self._load_default_synthetic_fixture()
        account_id = fixture.get("account_id", "SYNTHETIC_ACCOUNT")
        region = fixture.get("primary_region", "us-east-1")
        return self._evaluate_topology(fixture, account_id, region, mode="SYNTHETIC_DEMO")

    def run_live_aws_audit(self, region: str = "us-east-1") -> SentinelReport:
        """
        Runs read-only audit against real AWS account via boto3.
        Invokes ONLY Describe* APIs. Zero write, create, or delete actions.
        """
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
        except ImportError:
            raise RuntimeError(
                "Package 'boto3' is required for live AWS scanning. "
                "Install it with: pip install boto3"
            )

        try:
            session = boto3.Session(region_name=region)
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            account_id = identity.get("Account", "UNKNOWN_ACCOUNT")
            ec2 = session.client("ec2")

            # Strictly Describe* calls
            vpcs_resp = ec2.describe_vpcs()
            rts_resp = ec2.describe_route_tables()
            nat_resp = ec2.describe_nat_gateways(Filters=[{"Name": "state", "Values": ["available"]}])
            endpoints_resp = ec2.describe_vpc_endpoints()
            volumes_resp = ec2.describe_volumes()
            eips_resp = ec2.describe_addresses()
        except NoCredentialsError:
            raise RuntimeError("No AWS credentials found. Configure via 'aws configure' or environment variables.")
        except ClientError as e:
            raise RuntimeError(f"AWS API call failed: {e}")

        # Assemble normalized topology fixture from Describe output
        normalized_fixture = self._normalize_aws_describe_data(
            vpcs_resp, rts_resp, nat_resp, endpoints_resp, volumes_resp, eips_resp, account_id, region
        )
        return self._evaluate_topology(normalized_fixture, account_id, region, mode="REAL_AWS_READONLY")

    def _normalize_aws_describe_data(
        self, vpcs_resp: Dict[str, Any], rts_resp: Dict[str, Any],
        nat_resp: Dict[str, Any], endpoints_resp: Dict[str, Any],
        volumes_resp: Dict[str, Any], eips_resp: Dict[str, Any],
        account_id: str, region: str
    ) -> Dict[str, Any]:
        """Normalizes Describe* payloads without storing or leaking credential metadata."""
        vpcs_list = []
        for vpc in vpcs_resp.get("Vpcs", []):
            vpc_id = vpc.get("VpcId")
            
            # Check S3 Gateway Endpoint
            has_s3_endpoint = any(
                ep.get("VpcId") == vpc_id and
                ep.get("ServiceName", "").endswith(".s3") and
                ep.get("VpcEndpointType") == "Gateway" and
                ep.get("State") == "available"
                for ep in endpoints_resp.get("VpcEndpoints", [])
            )

            # Check NAT Gateways in this VPC
            nat_gateways = [
                {"nat_gateway_id": ng.get("NatGatewayId"), "state": ng.get("State")}
                for ng in nat_resp.get("NatGateways", [])
                if ng.get("VpcId") == vpc_id
            ]

            # Route table ID for private routes
            private_rt_id = "rtb-unknown"
            for rt in rts_resp.get("RouteTables", []):
                if rt.get("VpcId") == vpc_id:
                    for route in rt.get("Routes", []):
                        if route.get("NatGatewayId"):
                            private_rt_id = rt.get("RouteTableId")
                            break

            vpcs_list.append({
                "vpc_id": vpc_id,
                "region": region,
                "has_s3_gateway_endpoint": has_s3_endpoint,
                "monthly_s3_traffic_via_nat_gb": 1000.0,  # Baseline heuristic for active NATs
                "private_route_table_id": private_rt_id,
                "nat_gateways": nat_gateways
            })

        ebs_list = []
        for vol in volumes_resp.get("Volumes", []):
            ebs_list.append({
                "volume_id": vol.get("VolumeId"),
                "size_gb": vol.get("Size", 0),
                "volume_type": vol.get("VolumeType", "gp2"),
                "state": vol.get("State"),
                "region": region
            })

        eip_list = []
        for eip in eips_resp.get("Addresses", []):
            eip_list.append({
                "allocation_id": eip.get("AllocationId", eip.get("PublicIp")),
                "public_ip": eip.get("PublicIp"),
                "is_associated": bool(eip.get("AssociationId") or eip.get("InstanceId")),
                "region": region
            })

        return {
            "account_id": account_id,
            "primary_region": region,
            "vpcs": vpcs_list,
            "ebs_volumes": ebs_list,
            "elastic_ips": eip_list
        }

    def _evaluate_topology(
        self, fixture: Dict[str, Any], account_id: str, region: str, mode: str
    ) -> SentinelReport:
        findings: List[ArchitecturalFinding] = []
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        audit_id = f"SENTINEL_AUDIT_{int(time.time())}"

        # 1. Correlate NAT Gateways x S3 Gateway Endpoints
        for vpc in fixture.get("vpcs", []):
            vpc_id = vpc.get("vpc_id")
            vpc_region = vpc.get("region", region)
            has_s3 = vpc.get("has_s3_gateway_endpoint", False)
            nat_gateways = vpc.get("nat_gateways", [])
            s3_traffic_gb = float(vpc.get("monthly_s3_traffic_via_nat_gb", 0))

            if nat_gateways and not has_s3 and s3_traffic_gb > 0:
                bleed = round(s3_traffic_gb * NAT_GATEWAY_DATA_PER_GB_USD, 2)
                ng_id = nat_gateways[0]["nat_gateway_id"]
                rt_id = vpc.get("private_route_table_id", "rtb-private")

                findings.append(ArchitecturalFinding(
                    finding_id=f"FIND_NAT_S3_{vpc_id}",
                    category="NAT_GATEWAY_LEAK",
                    severity="HIGH",
                    confidence=FindingConfidenceModel(
                        observed_resource=f"VPC {vpc_id} with NAT Gateway {ng_id} and 0 S3 Gateway Endpoints",
                        estimated_waste=f"~{s3_traffic_gb:.0f} GB/mo S3 traffic incurring ${NAT_GATEWAY_DATA_PER_GB_USD}/GB NAT fee",
                        estimated_savings=f"${bleed:.2f}/month (${bleed * 12:.2f}/year)",
                        recommendation="Attach free AWS Gateway VPC Endpoint for S3 to private route tables",
                        verified_realized_savings="$0.00 (Requires billing audit after remediation)"
                    ),
                    monthly_bleed_estimate_usd=bleed,
                    verified_realized_savings_usd=0.00,
                    resource_id=ng_id,
                    resource_type="AWS::EC2::NatGateway",
                    region=vpc_region,
                    vpc_id=vpc_id,
                    explanation=(
                        f"VPC {vpc_id} routes outbound traffic through NAT Gateway {ng_id}. "
                        f"No free S3 Gateway Endpoint was detected. S3 traffic across NAT Gateways "
                        f"incurs an unnecessary ${NAT_GATEWAY_DATA_PER_GB_USD}/GB data processing surcharge."
                    ),
                    remediation_action="Create free S3 Gateway VPC Endpoint and bind to private route tables.",
                    remediation_terraform_snippet=(
                        f'resource "aws_vpc_endpoint" "s3" {{\n'
                        f'  vpc_id          = "{vpc_id}"\n'
                        f'  service_name    = "com.amazonaws.{vpc_region}.s3"\n'
                        f'  route_table_ids = ["{rt_id}"]\n'
                        f'  tags = {{\n'
                        f'    ManagedBy = "PhoenixAwsSentinel"\n'
                        f'  }}\n'
                        f'}}'
                    ),
                    remediation_cli_command=(
                        f"aws ec2 create-vpc-endpoint --vpc-id {vpc_id} "
                        f"--service-name com.amazonaws.{vpc_region}.s3 "
                        f"--route-table-ids {rt_id} --dry-run"
                    ),
                    is_non_destructive=True,
                    data_source=mode
                ))

        # 2. Correlate EBS Volumes (Orphaned & Legacy gp2)
        for vol in fixture.get("ebs_volumes", []):
            vol_id = vol.get("volume_id")
            size_gb = vol.get("size_gb", 0)
            vol_type = vol.get("volume_type", "gp2")
            state = vol.get("state", "in-use")
            vol_region = vol.get("region", region)

            if state == "available":
                price = EBS_GP3_PRICE_PER_GB_MONTH_USD if vol_type == "gp3" else EBS_GP2_PRICE_PER_GB_MONTH_USD
                bleed = round(size_gb * price, 2)
                findings.append(ArchitecturalFinding(
                    finding_id=f"FIND_EBS_ORPHAN_{vol_id}",
                    category="ORPHANED_EBS",
                    severity="MEDIUM",
                    confidence=FindingConfidenceModel(
                        observed_resource=f"EBS Volume {vol_id} ({size_gb} GB, {vol_type}) in state 'available'",
                        estimated_waste=f"${bleed:.2f}/month unattached storage fee",
                        estimated_savings=f"${bleed:.2f}/month upon verified decommission",
                        recommendation="Snapshot volume for backup and delete unattached storage",
                        verified_realized_savings="$0.00 (Requires manual snapshot & decommission)"
                    ),
                    monthly_bleed_estimate_usd=bleed,
                    verified_realized_savings_usd=0.00,
                    resource_id=vol_id,
                    resource_type="AWS::EC2::Volume",
                    region=vol_region,
                    vpc_id=None,
                    explanation=(
                        f"EBS Volume {vol_id} ({size_gb} GB {vol_type}) is unattached to any EC2 instance "
                        f"and continuously incurs charges."
                    ),
                    remediation_action="Take backup snapshot and delete orphaned volume.",
                    remediation_terraform_snippet=f"# Review and delete unattached volume {vol_id} in state.",
                    remediation_cli_command=(
                        f"aws ec2 create-snapshot --volume-id {vol_id} --description 'Sentinel backup' && "
                        f"aws ec2 delete-volume --volume-id {vol_id} --dry-run"
                    ),
                    is_non_destructive=False,
                    data_source=mode
                ))
            elif state == "in-use" and vol_type == "gp2" and size_gb >= 100:
                savings = round(size_gb * (EBS_GP2_PRICE_PER_GB_MONTH_USD - EBS_GP3_PRICE_PER_GB_MONTH_USD), 2)
                findings.append(ArchitecturalFinding(
                    finding_id=f"FIND_EBS_GP3_{vol_id}",
                    category="LEGACY_GP2_VOLUME",
                    severity="LOW",
                    confidence=FindingConfidenceModel(
                        observed_resource=f"EBS Volume {vol_id} ({size_gb} GB) using legacy gp2",
                        estimated_waste=f"${savings:.2f}/month premium over gp3 baseline",
                        estimated_savings=f"${savings:.2f}/month via online modification",
                        recommendation="Migrate volume from gp2 to gp3 (zero downtime)",
                        verified_realized_savings="$0.00 (Requires volume modification completion)"
                    ),
                    monthly_bleed_estimate_usd=savings,
                    verified_realized_savings_usd=0.00,
                    resource_id=vol_id,
                    resource_type="AWS::EC2::Volume",
                    region=vol_region,
                    vpc_id=None,
                    explanation=(
                        f"Volume {vol_id} ({size_gb} GB) uses gp2. gp3 delivers identical baseline "
                        f"throughput (3000 IOPS / 125 MB/s) at 20% lower cost per GB."
                    ),
                    remediation_action="Modify volume type to gp3 online without instance restart.",
                    remediation_terraform_snippet=f'# Update type = "gp3" in aws_ebs_volume block.',
                    remediation_cli_command=f"aws ec2 modify-volume --volume-id {vol_id} --volume-type gp3 --dry-run",
                    is_non_destructive=True,
                    data_source=mode
                ))

        # 3. Unassociated Elastic IPs
        for eip in fixture.get("elastic_ips", []):
            eip_id = eip.get("allocation_id")
            ip = eip.get("public_ip")
            is_assoc = eip.get("is_associated", False)
            eip_region = eip.get("region", region)

            if not is_assoc:
                bleed = round(IDLE_EIP_PRICE_PER_HOUR_USD * 730, 2)
                findings.append(ArchitecturalFinding(
                    finding_id=f"FIND_EIP_IDLE_{eip_id}",
                    category="UNATTACHED_EIP",
                    severity="LOW",
                    confidence=FindingConfidenceModel(
                        observed_resource=f"Elastic IP {ip} ({eip_id}) not associated to any ENI",
                        estimated_waste=f"${bleed:.2f}/month idle reservation fee",
                        estimated_savings=f"${bleed:.2f}/month upon release",
                        recommendation="Release unassociated public IPv4 address to AWS pool",
                        verified_realized_savings="$0.00 (Requires release confirmation)"
                    ),
                    monthly_bleed_estimate_usd=bleed,
                    verified_realized_savings_usd=0.00,
                    resource_id=eip_id,
                    resource_type="AWS::EC2::EIP",
                    region=eip_region,
                    vpc_id=None,
                    explanation=f"Public IPv4 {ip} is allocated but not associated to any running resource.",
                    remediation_action="Release unassociated Elastic IP address.",
                    remediation_terraform_snippet=f"# Delete unassociated aws_eip {eip_id}.",
                    remediation_cli_command=f"aws ec2 release-address --allocation-id {eip_id} --dry-run",
                    is_non_destructive=False,
                    data_source=mode
                ))

        total_bleed = round(sum(f.monthly_bleed_estimate_usd for f in findings), 2)

        return SentinelReport(
            audit_id=audit_id,
            timestamp=now_iso,
            account_id=account_id,
            region=region,
            mode=mode,
            total_findings=len(findings),
            estimated_monthly_bleed_usd=total_bleed,
            verified_realized_savings_usd=0.00,
            findings=findings,
            differentiation_summary={
                "cross_service_correlation": "VPC Route Tables x NAT Gateways x S3 Endpoints correlated deterministically",
                "privacy_model": "LOCAL_FIRST_ZERO_UPLOAD (Zero data or tokens sent to remote cloud)",
                "remediation_format": "TERRAFORM_HCL_AND_DRY_RUN_CLI_SNIPPETS",
                "telemetry": "DISABLED_BY_DEFAULT"
            },
            feedback_prompt=(
                "What feature would make this tool worth paying for? "
                "(Multi-account scanning, CI/CD policy blocking, historical trend tracking). "
                "Open an issue at: https://github.com/fromero385/phoenix-aws-sentinel/issues"
            ),
            disclaimer=(
                "EPISTEMIC NOTICE: Values shown are estimated architectural models based on AWS list pricing. "
                "Verified realized savings are $0.00 until changes are deployed and verified on your AWS invoice."
            )
        )

    def _load_default_synthetic_fixture(self) -> Dict[str, Any]:
        """Built-in synthetic startup fixture for zero-credential demo runs."""
        return {
            "account_id": "112233445566-SYNTHETIC-DEMO",
            "primary_region": "us-east-1",
            "vpcs": [
                {
                    "vpc_id": "vpc-0a1b2c3d4e5f6g7h8",
                    "region": "us-east-1",
                    "has_s3_gateway_endpoint": False,
                    "monthly_s3_traffic_via_nat_gb": 7000.0,
                    "private_route_table_id": "rtb-0123456789abcdef0",
                    "nat_gateways": [
                        {
                            "nat_gateway_id": "nat-0987654321fedcba0",
                            "subnet_id": "subnet-public-1a",
                            "state": "available"
                        }
                    ]
                }
            ],
            "ebs_volumes": [
                {
                    "volume_id": "vol-0123456789abcdef1",
                    "size_gb": 200,
                    "volume_type": "gp2",
                    "state": "available",
                    "region": "us-east-1"
                },
                {
                    "volume_id": "vol-0123456789abcdef2",
                    "size_gb": 500,
                    "volume_type": "gp2",
                    "state": "available",
                    "region": "us-east-1"
                },
                {
                    "volume_id": "vol-0123456789abcdef3",
                    "size_gb": 300,
                    "volume_type": "gp2",
                    "state": "in-use",
                    "region": "us-east-1"
                }
            ],
            "elastic_ips": [
                {
                    "allocation_id": "eipalloc-0123456789abcdef0",
                    "public_ip": "54.210.100.42",
                    "is_associated": False,
                    "region": "us-east-1"
                }
            ]
        }


# ==============================================================================
# FORMATTING & CLI OUTPUT
# ==============================================================================
def render_report_table(report: SentinelReport) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(f"  PHOENIX AWS SENTINEL — ARCHITECTURAL AUDIT REPORT ({report.mode})")
    lines.append("=" * 78)
    lines.append(f"  Account ID : {report.account_id}")
    lines.append(f"  Region     : {report.region}")
    lines.append(f"  Audit Time : {report.timestamp}")
    lines.append(f"  Findings   : {report.total_findings}")
    lines.append(f"  Est. Bleed : ${report.estimated_monthly_bleed_usd:.2f} / month  (${report.estimated_monthly_bleed_usd * 12:.2f} / year)")
    lines.append(f"  Realized   : ${report.verified_realized_savings_usd:.2f} (Verified realized savings)")
    lines.append("-" * 78)

    for idx, f in enumerate(report.findings, 1):
        lines.append(f"[{idx}] {f.severity} | {f.category} | {f.resource_id}")
        lines.append(f"    Observed       : {f.confidence.observed_resource}")
        lines.append(f"    Estimated Waste: {f.confidence.estimated_waste}")
        lines.append(f"    Est. Savings   : {f.confidence.estimated_savings}")
        lines.append(f"    Realized Value : {f.confidence.verified_realized_savings}")
        lines.append(f"    Terraform HCL Fix:")
        for tf_line in f.remediation_terraform_snippet.split("\n"):
            lines.append(f"      {tf_line}")
        lines.append(f"    Dry-Run CLI Command:")
        lines.append(f"      $ {f.remediation_cli_command}")
        lines.append("")

    lines.append("-" * 78)
    lines.append(f"  [ROADMAP FEEDBACK]: {report.feedback_prompt}")
    lines.append(f"  [NOTICE]: {report.disclaimer}")
    lines.append("=" * 78)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Phoenix AWS Sentinel: Read-Only Architectural Cloud Leak & Zombie Asset Detector"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--demo", action="store_true", default=True, help="Run safe built-in SYNTHETIC_DEMO audit (default)")
    group.add_argument("--fixture", type=str, help="Path to custom offline JSON topology fixture")
    group.add_argument("--aws", action="store_true", help="Run read-only audit against real AWS account (requires boto3 & AWS credentials)")

    parser.add_argument("--region", type=str, default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--format", choices=["table", "json"], default="table", help="Output format (table or json)")
    parser.add_argument("--output", type=str, help="Optional path to write output file")

    args = parser.parse_args()
    scanner = AwsSentinelScanner()

    try:
        if args.aws:
            report = scanner.run_live_aws_audit(region=args.region)
        elif args.fixture:
            with open(args.fixture, "r", encoding="utf-8") as fh:
                fixture_data = json.load(fh)
            report = scanner.run_synthetic_audit(fixture_data=fixture_data)
        else:
            report = scanner.run_synthetic_audit()

        if args.format == "json":
            out_str = json.dumps(report.to_dict(), indent=2)
        else:
            out_str = render_report_table(report)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out_str)
            print(f"Report written to {args.output}")
        else:
            print(out_str)

    except Exception as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()

