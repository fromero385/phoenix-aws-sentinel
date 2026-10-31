# Phoenix AWS Sentinel

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Read-Only](https://img.shields.io/badge/Security-100%25_Read--Only-green)](#security-model)
[![Zero Telemetry](https://img.shields.io/badge/Privacy-Zero_Telemetry-success)](#privacy)

A local-first, read-only architectural cloud leak and zombie asset detector for Amazon Web Services (AWS).

> **Disclaimer:** Phoenix AWS Sentinel is an independent open-source project and is not affiliated with, sponsored by, or endorsed by Amazon Web Services, Inc., Microsoft Corporation, or HashiCorp, Inc.

---

## 1. Problem

Modern cloud engineering teams frequently suffer silent monthly invoice bleeds caused by subtle architectural routing oversights and disconnected lifecycle stages:
- **NAT Gateway Data Processing Surcharges:** Internal data flowing from private subnets to Amazon S3 (e.g., container images, analytical dumps, backups, CloudWatch logs) often traverses an active NAT Gateway at **$0.045 per GB**, even though AWS provides free Gateway VPC Endpoints for S3.
- **Orphaned Storage Volumes:** Terminated EC2 instances leave behind unattached EBS volumes in the `available` state that silently bill storage fees indefinitely.
- **Legacy Storage Formats:** Volumes provisioned years ago remain on `gp2`, paying a 20% premium over modern `gp3` volumes with identical baseline performance.
- **Unassociated Elastic IPs:** Reserved public IPv4 addresses not associated with running instances incur continuous hourly reservation fees.

Traditional cost dashboards typically alert you 24–48 hours after the money is already spent, without indicating the exact Terraform routing block needed to stop the leak.

---

## 2. What It Detects

| Category | Detected Condition | Estimated Impact (US-East-1) | Remediation Generated |
| :--- | :--- | :--- | :--- |
| **NAT_GATEWAY_LEAK** | Private subnet routing `0.0.0.0/0` to a NAT Gateway with 0 S3 Gateway Endpoints | $0.045 per GB processed (~$45 / 1,000 GB) | `aws_vpc_endpoint` Terraform HCL + AWS CLI dry-run |
| **ORPHANED_EBS** | EBS volume in `available` state (unattached to any instance) | $0.10 per GB-month (gp2) / $0.08 per GB-month (gp3) | Backup snapshot command + volume delete dry-run |
| **LEGACY_GP2_VOLUME** | Active EBS volume utilizing legacy `gp2` storage (≥100 GB) | ~20% higher storage cost than `gp3` | In-place volume type modification (zero downtime) |
| **UNATTACHED_EIP** | Allocated public IPv4 address not associated with any ENI or instance | $0.005 per hour (~$3.65 / month per IP) | Elastic IP release dry-run command |

---

## 3. How It Works

Phoenix AWS Sentinel inspects relationships between networking topology and resource lifecycle states rather than solely inspecting billing reports:

```
[Private Subnet Route Table]
             │
             ├──► 0.0.0.0/0 ──► [NAT Gateway ($0.045/GB)] ──► [Amazon S3]  (LEAK DETECTED)
             │
             └──► [Fix: Add Gateway VPC Endpoint (Free)] ──► Direct S3 Routing
```

1. **Topology Correlation:** Retrieves VPC route tables, active NAT gateways, and VPC endpoints to verify whether high-volume AWS services (like S3) bypass NAT gateways.
2. **Resource Lifecycle Audit:** Scans EC2 volumes and Elastic IPs to isolate assets without active attachment bindings.
3. **Remediation Generation:** Emits copy-paste Terraform HCL snippets and AWS CLI commands using `--dry-run` to ensure zero unintended side effects.

---

## 4. Read-Only Permissions

Phoenix AWS Sentinel requires **strictly read-only Describe permissions**. It never requests, requires, or invokes `Create`, `Delete`, `Modify`, `Put`, or `Update` API actions.

The complete minimum IAM policy is located at [`iam-policy.json`](./iam-policy.json):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PhoenixAwsSentinelReadOnlyAudit",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVolumes",
        "ec2:DescribeAddresses"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 5. Installation

Phoenix AWS Sentinel is built on standard Python (>=3.9) with zero external dependencies required for synthetic and fixture modes.

```bash
# Clone the standalone package
git clone https://github.com/fromero385/phoenix.git
cd phoenix/packages/aws-sentinel

# (Optional) Install boto3 only if you plan to scan live AWS accounts
pip install boto3
```

---

## 6. Safe Demo (Zero AWS Credentials Needed)

To test the tool immediately without providing any AWS credentials or contacting any remote network:

```bash
python sentinel.py --demo
```

Or pass a custom offline JSON topology fixture:

```bash
python sentinel.py --fixture fixtures/synthetic_demo.json --format table
```

---

## 7. Real AWS Mode

To scan an active AWS account in read-only mode using standard AWS credentials configured on your machine (`~/.aws/credentials` or environment variables):

```bash
# Ensure read-only IAM credentials are set in your shell
export AWS_REGION="us-east-1"

# Run read-only scan
python sentinel.py --aws --region us-east-1 --format table
```

---

## 8. Example Output

```text
==============================================================================
  PHOENIX AWS SENTINEL — ARCHITECTURAL AUDIT REPORT (SYNTHETIC_DEMO)
==============================================================================
  Account ID : 112233445566-SYNTHETIC-DEMO
  Region     : us-east-1
  Audit Time : 2026-10-31T18:49:40Z
  Findings   : 5
  Est. Bleed : $394.65 / month  ($4735.80 / year)
  Realized   : $0.00 (Verified realized savings)
------------------------------------------------------------------------------
[1] HIGH | NAT_GATEWAY_LEAK | nat-0987654321fedcba0
    Observed       : VPC vpc-0a1b2c3d4e5f6g7h8 with NAT Gateway nat-0987654321fedcba0 and 0 S3 Gateway Endpoints
    Estimated Waste: ~7000 GB/mo S3 traffic incurring $0.045/GB NAT fee
    Est. Savings   : $315.00/month ($3780.00/year)
    Realized Value : $0.00 (Requires billing audit after remediation)
    Terraform HCL Fix:
      resource "aws_vpc_endpoint" "s3" {
        vpc_id          = "vpc-0a1b2c3d4e5f6g7h8"
        service_name    = "com.amazonaws.us-east-1.s3"
        route_table_ids = ["rtb-0123456789abcdef0"]
        tags = {
          ManagedBy = "PhoenixAwsSentinel"
        }
      }
    Dry-Run CLI Command:
      $ aws ec2 create-vpc-endpoint --vpc-id vpc-0a1b2c3d4e5f6g7h8 --service-name com.amazonaws.us-east-1.s3 --route-table-ids rtb-0123456789abcdef0 --dry-run
...
```

---

## 9. Limitations

- **Pricing Heuristics:** Financial figures represent standard AWS public catalog rates (e.g. US-East-1). Enterprise Discount Programs (EDP) or custom negotiated savings plans are not automatically applied.
- **Traffic Estimations:** NAT data transfer volume estimation relies on route configuration heuristics or user-provided flow log metrics unless CloudWatch metric queries are specifically supplied.
- **Single-Region Scope per Invocation:** Multi-region scanning currently requires running individual passes per target region.

---

## 10. Security Model

- **Read-Only Guarantee:** The codebase contains zero API calls that modify, delete, or create cloud resources.
- **Dry-Run by Default:** All remediation commands outputted for operator inspection explicitly include the `--dry-run` flag where supported.
- **Zero Ingestion of Private Keys:** The tool operates via standard AWS SDK credential resolution chains; it does not request, log, or cache secrets.

---

## 11. Privacy

- **100% Local Execution:** Computation takes place entirely on your local machine.
- **Zero Telemetry:** Phoenix AWS Sentinel does not transmit analytics, heartbeats, IP addresses, or resource metadata to any remote server.
- **No Third-Party Cloud Uploads:** No account data is transmitted to LLM providers or SaaS aggregators.

---

## 12. Competitor Difference

| Capability | AWS Cost Explorer | Cloud Custodian | Heavy FinOps SaaS (Vantage/Kubecost) | Phoenix AWS Sentinel |
| :--- | :---: | :---: | :---: | :---: |
| **Execution Model** | Cloud Dashboard | Rule YAML Engine | Managed Cloud SaaS | Local-First CLI |
| **Credentials Required** | IAM Console | Read/Write IAM | Permanent Read IAM Role | Local CLI Credential |
| **VPC Route Correlation** | No | No | Limited | **Yes** |
| **Remediation Output** | None | Automated Deletion | High-Level Advice | **Terraform HCL Snippets** |
| **Third-Party Data Upload** | Inside AWS | None | Required | **Zero Upload** |
| **Cost** | Free | Free / Self-hosted | $30–$200+/month | **Free & Open Source** |

---

## 13. Roadmap & Public Feedback

We are researching what features cloud engineers find most valuable before deciding whether to expand this project into a broader platform:

**Feedback Question:**  
*What feature would make this tool worth paying for?*
- Multi-account AWS Organizations scanning?
- Automated CI/CD pre-merge pull request blocking for Terraform?
- Historical trend tracking across billing cycles?
- Cross-region automated routing visualization?

Share your feedback, bug reports, or feature requests via GitHub Issues:  
[https://github.com/fromero385/phoenix/issues](https://github.com/fromero385/phoenix/issues)

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).

