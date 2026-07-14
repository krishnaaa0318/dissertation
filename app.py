import os
import sys
import csv
import json
import re
import subprocess
import uuid
import zipfile
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
FEEDBACK_FILE = REPORT_DIR / "feedback.csv"

ALLOWED_EXTENSIONS = {".tf", ".tfvars", ".hcl", ".zip"}
MAX_UPLOAD_MB = 8

app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key-for-production"
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

UPLOAD_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


CHECKOV_TRANSLATIONS = {
    "CKV_AWS_23": {
        "simple_title": "Security group rule is missing a description",
        "category": "Network Security",
        "risk_level": "Low",
        "what_this_means": "A security group rule does not clearly explain why the rule exists.",
        "why_it_matters": "Descriptions help users understand the purpose of firewall rules. Without them, risky rules may be left in place because nobody knows why they were added.",
        "suggested_fix": "Add a short description to each ingress and egress rule. The description should explain what the rule is used for.",
        "example_fix": 'description = "Allow SSH only from trusted administrator IP"',
    },
    "CKV_AWS_24": {
        "simple_title": "SSH is open to the internet",
        "category": "Public Exposure",
        "risk_level": "High",
        "what_this_means": "The security group allows SSH access on port 22 from 0.0.0.0/0, which means any IP address on the internet can try to connect.",
        "why_it_matters": "SSH is used for remote server access. If it is open to the whole internet, attackers can attempt brute-force login, password attacks, or exploit weak server settings.",
        "suggested_fix": "Restrict SSH to a trusted IP address or private network. Avoid using 0.0.0.0/0 for SSH access.",
        "example_fix": 'cidr_blocks = ["YOUR_PUBLIC_IP/32"]',
    },
    "CKV_AWS_260": {
        "simple_title": "HTTP is open to the internet",
        "category": "Public Exposure",
        "risk_level": "Medium",
        "what_this_means": "The security group allows HTTP traffic on port 80 from 0.0.0.0/0.",
        "why_it_matters": "Public HTTP may be required for a web server, but it should be planned carefully. If the resource is not meant to be public, it can expose the system to unwanted traffic.",
        "suggested_fix": "Only allow public HTTP when the resource is meant to be internet-facing. Otherwise, restrict access to trusted IP ranges or internal networks.",
        "example_fix": 'cidr_blocks = ["10.0.0.0/16"]',
    },
    "CKV_AWS_382": {
        "simple_title": "Outbound traffic is fully open",
        "category": "Network Security",
        "risk_level": "Medium",
        "what_this_means": "The security group allows all outbound traffic to any IP address.",
        "why_it_matters": "Open outbound traffic can make it easier for a compromised resource to send data out or contact unsafe external systems.",
        "suggested_fix": "Limit outbound traffic to the ports and destinations that the resource actually needs.",
        "example_fix": 'cidr_blocks = ["10.0.0.0/16"]',
    },
    "CKV2_AWS_5": {
        "simple_title": "Security group is not attached to a resource",
        "category": "Network Security",
        "risk_level": "Low",
        "what_this_means": "A security group exists in the Terraform file but is not attached to an EC2 instance or network interface.",
        "why_it_matters": "Unused security groups can cause confusion and make cloud security harder to review.",
        "suggested_fix": "Attach the security group to the correct resource or remove it if it is not needed.",
        "example_fix": "vpc_security_group_ids = [aws_security_group.example.id]",
    },
    "CKV_AWS_20": {
        "simple_title": "S3 bucket allows public read access",
        "category": "Storage Security",
        "risk_level": "High",
        "what_this_means": "The S3 bucket has a setting that may allow people on the internet to read objects in the bucket.",
        "why_it_matters": "Public S3 buckets can expose files, logs, backups, or other sensitive data if they are uploaded by mistake.",
        "suggested_fix": "Remove public ACL settings and use private access unless the bucket is specifically designed for public content.",
        "example_fix": 'acl = "private"',
    },
    "CKV2_AWS_6": {
        "simple_title": "S3 public access block is missing or weak",
        "category": "Storage Security",
        "risk_level": "High",
        "what_this_means": "The S3 bucket does not have strong public access blocking enabled.",
        "why_it_matters": "Without public access blocking, a bucket can become public through ACLs or bucket policies.",
        "suggested_fix": "Enable all S3 public access block settings unless the bucket must be public.",
        "example_fix": "block_public_acls = true\nblock_public_policy = true\nignore_public_acls = true\nrestrict_public_buckets = true",
    },
    "CKV_AWS_18": {
        "simple_title": "S3 access logging is not enabled",
        "category": "Logging and Monitoring",
        "risk_level": "Medium",
        "what_this_means": "The S3 bucket does not record access logs.",
        "why_it_matters": "Access logs help investigate who accessed the bucket and when. Without logs, it is harder to review suspicious activity.",
        "suggested_fix": "Enable server access logging and send logs to a separate logging bucket.",
        "example_fix": "resource \"aws_s3_bucket_logging\" \"example\" { ... }",
    },
    "CKV_AWS_21": {
        "simple_title": "S3 versioning is not enabled",
        "category": "Resilience and Recovery",
        "risk_level": "Medium",
        "what_this_means": "The S3 bucket does not keep older versions of objects.",
        "why_it_matters": "Versioning helps recover files if they are deleted or overwritten by mistake.",
        "suggested_fix": "Enable S3 bucket versioning for important buckets.",
        "example_fix": 'status = "Enabled"',
    },
    "CKV_AWS_145": {
        "simple_title": "S3 bucket encryption should use KMS",
        "category": "Encryption",
        "risk_level": "Medium",
        "what_this_means": "The S3 bucket is not configured to use KMS encryption by default.",
        "why_it_matters": "Encryption helps protect stored data. KMS gives better control over keys and auditing.",
        "suggested_fix": "Enable default bucket encryption using a KMS key where suitable.",
        "example_fix": 'sse_algorithm = "aws:kms"',
    },
    "CKV_AWS_144": {
        "simple_title": "S3 cross-region replication is not enabled",
        "category": "Resilience and Recovery",
        "risk_level": "Low",
        "what_this_means": "The S3 bucket is not configured to copy data to another region.",
        "why_it_matters": "Replication can help recovery if there is a regional outage or accidental data loss.",
        "suggested_fix": "Enable replication for important buckets that need strong recovery protection.",
        "example_fix": "Configure aws_s3_bucket_replication_configuration for critical buckets.",
    },
    "CKV2_AWS_61": {
        "simple_title": "S3 lifecycle rule is missing",
        "category": "Resilience and Recovery",
        "risk_level": "Low",
        "what_this_means": "The S3 bucket does not have lifecycle rules for old objects.",
        "why_it_matters": "Lifecycle rules help manage storage, retention, and clean-up of old data.",
        "suggested_fix": "Add a lifecycle rule if the bucket stores data that should expire or move to cheaper storage.",
        "example_fix": "resource \"aws_s3_bucket_lifecycle_configuration\" \"example\" { ... }",
    },
    "CKV2_AWS_62": {
        "simple_title": "S3 event notification is not enabled",
        "category": "Logging and Monitoring",
        "risk_level": "Low",
        "what_this_means": "The S3 bucket does not send event notifications when objects change.",
        "why_it_matters": "Notifications can support monitoring, automation, and security response.",
        "suggested_fix": "Add event notifications if the bucket needs monitoring or automated processing.",
        "example_fix": "resource \"aws_s3_bucket_notification\" \"example\" { ... }",
    },
    "CKV_AWS_16": {
        "simple_title": "RDS storage encryption is disabled",
        "category": "Database Security",
        "risk_level": "High",
        "what_this_means": "The RDS database is not encrypted at rest.",
        "why_it_matters": "Database storage may contain sensitive information. Encryption helps protect data if storage is accessed without permission.",
        "suggested_fix": "Enable storage encryption for the database before deployment.",
        "example_fix": "storage_encrypted = true",
    },
    "CKV_AWS_17": {
        "simple_title": "RDS database is publicly accessible",
        "category": "Database Security",
        "risk_level": "High",
        "what_this_means": "The RDS database can be reached from the public internet.",
        "why_it_matters": "Public databases are high-risk because attackers can try to connect directly to the database endpoint.",
        "suggested_fix": "Set the database as private and allow access only from trusted application networks.",
        "example_fix": "publicly_accessible = false",
    },
    "CKV_AWS_118": {
        "simple_title": "RDS enhanced monitoring is not enabled",
        "category": "Logging and Monitoring",
        "risk_level": "Medium",
        "what_this_means": "The RDS database does not have enhanced monitoring enabled.",
        "why_it_matters": "Monitoring helps detect performance problems and unusual behaviour.",
        "suggested_fix": "Enable enhanced monitoring when the database needs better visibility.",
        "example_fix": "monitoring_interval = 60",
    },
    "CKV_AWS_129": {
        "simple_title": "RDS logs are not enabled",
        "category": "Logging and Monitoring",
        "risk_level": "Medium",
        "what_this_means": "The RDS database is not exporting the expected database logs.",
        "why_it_matters": "Logs help review errors, suspicious activity, and database events.",
        "suggested_fix": "Enable the correct log exports for the database engine being used.",
        "example_fix": 'enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]',
    },
    "CKV_AWS_133": {
        "simple_title": "RDS backup retention is too low",
        "category": "Resilience and Recovery",
        "risk_level": "High",
        "what_this_means": "The RDS database does not keep backups for recovery.",
        "why_it_matters": "Without backups, data may be lost after accidental deletion, failure, or corruption.",
        "suggested_fix": "Set a backup retention period that matches the importance of the database.",
        "example_fix": "backup_retention_period = 7",
    },
    "CKV_AWS_157": {
        "simple_title": "RDS Multi-AZ is not enabled",
        "category": "Resilience and Recovery",
        "risk_level": "Medium",
        "what_this_means": "The database is not configured for high availability across multiple availability zones.",
        "why_it_matters": "If one availability zone has a problem, a single-AZ database may have more downtime.",
        "suggested_fix": "Enable Multi-AZ for important databases that need higher availability.",
        "example_fix": "multi_az = true",
    },
    "CKV_AWS_161": {
        "simple_title": "RDS IAM authentication is not enabled",
        "category": "Identity and Access Management",
        "risk_level": "Medium",
        "what_this_means": "The database does not use IAM-based authentication.",
        "why_it_matters": "IAM authentication can improve access control and reduce the use of long-term database passwords.",
        "suggested_fix": "Enable IAM database authentication where it fits the application design.",
        "example_fix": "iam_database_authentication_enabled = true",
    },
    "CKV_AWS_226": {
        "simple_title": "RDS automatic minor upgrades are disabled",
        "category": "Patch Management",
        "risk_level": "Medium",
        "what_this_means": "The database will not automatically receive minor engine updates.",
        "why_it_matters": "Minor upgrades can include stability and security improvements.",
        "suggested_fix": "Enable automatic minor version upgrades unless the project needs strict manual patch control.",
        "example_fix": "auto_minor_version_upgrade = true",
    },
    "CKV_AWS_293": {
        "simple_title": "RDS deletion protection is disabled",
        "category": "Resilience and Recovery",
        "risk_level": "Medium",
        "what_this_means": "The database can be deleted without deletion protection.",
        "why_it_matters": "A mistake in Terraform or the console could delete the database more easily.",
        "suggested_fix": "Enable deletion protection for important databases.",
        "example_fix": "deletion_protection = true",
    },
    "CKV2_AWS_60": {
        "simple_title": "RDS copy tags to snapshots is disabled",
        "category": "Governance",
        "risk_level": "Low",
        "what_this_means": "Tags from the database are not copied to snapshots.",
        "why_it_matters": "Tags help with ownership, cost tracking, and governance. Missing tags can make snapshots harder to manage.",
        "suggested_fix": "Enable copy tags to snapshots for better management.",
        "example_fix": "copy_tags_to_snapshot = true",
    },
    "CKV_AWS_62": {
        "simple_title": "IAM policy allows full administrator access",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The IAM policy allows all actions on all resources.",
        "why_it_matters": "Full administrator permissions are dangerous if attached to the wrong user, group, or role.",
        "suggested_fix": "Replace wildcard permissions with only the actions and resources that are needed.",
        "example_fix": 'Action = ["s3:GetObject"]\nResource = "arn:aws:s3:::example-bucket/*"',
    },
    "CKV_AWS_63": {
        "simple_title": "IAM policy uses wildcard actions",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The IAM policy uses * for actions, which can allow too many permissions.",
        "why_it_matters": "Wildcard actions break the least privilege principle and may allow unwanted changes.",
        "suggested_fix": "List the exact actions required instead of using *.",
        "example_fix": 'Action = ["ec2:DescribeInstances"]',
    },
    "CKV_AWS_355": {
        "simple_title": "IAM policy uses wildcard resources",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The IAM policy allows actions on all resources using Resource = *.",
        "why_it_matters": "This can give access to more cloud resources than needed.",
        "suggested_fix": "Restrict the policy to specific resource ARNs where possible.",
        "example_fix": 'Resource = "arn:aws:s3:::example-bucket/*"',
    },
    "CKV_AWS_286": {
        "simple_title": "IAM policy may allow privilege escalation",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The policy may allow a user or role to gain higher permissions than intended.",
        "why_it_matters": "Privilege escalation can turn a limited account into a powerful account.",
        "suggested_fix": "Remove permissions that allow users to create, attach, or change powerful IAM policies unless required.",
        "example_fix": "Avoid permissions such as iam:AttachUserPolicy, iam:PutRolePolicy, and iam:CreatePolicyVersion unless required.",
    },
    "CKV_AWS_287": {
        "simple_title": "IAM policy may expose credentials",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The policy may allow access to secrets, keys, or credentials.",
        "why_it_matters": "Exposed credentials can be used to access cloud resources without permission.",
        "suggested_fix": "Remove unnecessary access to secrets and credentials. Give access only to trusted roles that need it.",
        "example_fix": "Limit access to secretsmanager:GetSecretValue and similar actions.",
    },
    "CKV_AWS_288": {
        "simple_title": "IAM policy may allow data exfiltration",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The policy may allow data to be copied or exported from cloud services.",
        "why_it_matters": "Attackers could use this access to move sensitive data out of the cloud account.",
        "suggested_fix": "Restrict data read and export permissions to only the resources and users that need them.",
        "example_fix": "Avoid broad read permissions across storage, database, and backup services.",
    },
    "CKV_AWS_289": {
        "simple_title": "IAM policy may expose resources without limits",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The policy may allow permissions or resource changes without clear restrictions.",
        "why_it_matters": "Unrestricted permissions management can weaken account security.",
        "suggested_fix": "Add resource restrictions and remove broad permissions management actions where possible.",
        "example_fix": "Use specific actions and resource ARNs instead of broad wildcards.",
    },
    "CKV_AWS_290": {
        "simple_title": "IAM policy allows write access without enough limits",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The policy may allow broad write actions without clear restrictions.",
        "why_it_matters": "Broad write access can allow users or attackers to change important resources.",
        "suggested_fix": "Limit write permissions to only the services, actions, and resources required.",
        "example_fix": "Avoid wide write permissions such as service:* on Resource = *.",
    },
    "CKV_AWS_273": {
        "simple_title": "IAM user is used instead of SSO",
        "category": "Identity and Access Management",
        "risk_level": "Medium",
        "what_this_means": "The Terraform file defines an IAM user instead of using central identity access such as SSO.",
        "why_it_matters": "IAM users can create long-term access keys. SSO is usually easier to manage and revoke.",
        "suggested_fix": "Use SSO or role-based access where possible instead of creating long-term IAM users.",
        "example_fix": "Prefer AWS IAM Identity Center or roles for human access.",
    },
    "CKV_AWS_40": {
        "simple_title": "IAM policy is attached directly to a user",
        "category": "Identity and Access Management",
        "risk_level": "Medium",
        "what_this_means": "The policy is attached directly to an IAM user instead of a group or role.",
        "why_it_matters": "Direct user policy attachments are harder to manage and can lead to excessive permissions.",
        "suggested_fix": "Attach policies to groups or roles instead of directly to users where possible.",
        "example_fix": "Use aws_iam_group_policy_attachment or role-based access.",
    },
    "CKV2_AWS_40": {
        "simple_title": "IAM policy allows full IAM privileges",
        "category": "Identity and Access Management",
        "risk_level": "High",
        "what_this_means": "The policy allows very broad control over IAM permissions.",
        "why_it_matters": "Full IAM privileges can allow a user or role to create powerful access, change permissions, or take over resources.",
        "suggested_fix": "Remove full IAM access and only allow the exact IAM actions needed.",
        "example_fix": "Avoid iam:* unless there is a clear administrative reason.",
    },
}


def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    """Extract zip while preventing Zip Slip path traversal."""
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        for member in zip_ref.infolist():
            member_path = destination / member.filename
            if not str(member_path.resolve()).startswith(str(destination.resolve())):
                raise ValueError("Unsafe zip file path detected")
        zip_ref.extractall(destination)


def prepare_scan_folder(uploaded_file) -> tuple[Path, str]:
    scan_id = str(uuid.uuid4())[:8]
    scan_dir = UPLOAD_DIR / scan_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    original_name = uploaded_file.filename or "uploaded_file"
    safe_name = secure_filename(original_name)
    if not safe_name:
        raise ValueError("Invalid file name")

    saved_path = scan_dir / safe_name
    uploaded_file.save(saved_path)

    if saved_path.suffix.lower() == ".zip":
        extract_dir = scan_dir / "extracted"
        extract_dir.mkdir(exist_ok=True)
        safe_extract_zip(saved_path, extract_dir)
        saved_path.unlink(missing_ok=True)
        return extract_dir, scan_id

    return scan_dir, scan_id


def run_checkov(scan_dir: Path) -> tuple[dict | None, str | None]:
    command = [
        sys.executable,
        "-m",
        "checkov.main",
        "-d",
        str(scan_dir),
        "--framework",
        "terraform",
        "--output",
        "json",
        "--quiet",
    ]

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "The scan took too long and was stopped. Try a smaller Terraform file."
    except Exception as exc:
        return None, f"Checkov scan failed: {exc}"

    raw_output = completed.stdout.strip()

    if not raw_output:
        return None, completed.stderr.strip() or "Checkov did not return JSON output."

    try:
        return json.loads(raw_output), None
    except json.JSONDecodeError:
        return None, (
            "Could not read Checkov JSON output. "
            f"Error output: {completed.stderr.strip()}"
        )


def flatten_checkov_results(checkov_json) -> dict:
    """Normalise Checkov JSON whether it returns one result object or a list."""
    if isinstance(checkov_json, list):
        result_blocks = checkov_json
    else:
        result_blocks = [checkov_json]

    passed = []
    failed = []
    skipped = []

    summary = {
        "passed": 0,
        "failed": 0,
        "skipped": 0,
        "parsing_errors": 0,
    }

    for block in result_blocks:
        results = block.get("results", {}) if isinstance(block, dict) else {}

        passed.extend(results.get("passed_checks", []) or [])
        failed.extend(results.get("failed_checks", []) or [])
        skipped.extend(results.get("skipped_checks", []) or [])

        block_summary = block.get("summary", {}) if isinstance(block, dict) else {}

        summary["passed"] += int(block_summary.get("passed", 0) or 0)
        summary["failed"] += int(block_summary.get("failed", 0) or 0)
        summary["skipped"] += int(block_summary.get("skipped", 0) or 0)
        summary["parsing_errors"] += int(
            block_summary.get("parsing_errors", 0) or 0
        )

    if summary["passed"] == 0:
        summary["passed"] = len(passed)

    if summary["failed"] == 0:
        summary["failed"] = len(failed)

    if summary["skipped"] == 0:
        summary["skipped"] = len(skipped)

    return {
        "summary": summary,
        "failed_checks": failed,
        "passed_checks": passed,
        "skipped_checks": skipped,
    }



def classify_finding(check_name: str) -> str:
    text = check_name.lower()

    if any(word in text for word in ["encrypt", "kms", "ssl", "tls", "https"]):
        return "Encryption"

    if any(word in text for word in ["public", "0.0.0.0", "cidr", "internet", "acl", "ingress"]):
        return "Public Exposure"

    if any(word in text for word in ["logging", "log", "monitor", "flow", "audit", "cloudtrail"]):
        return "Logging and Monitoring"

    if any(word in text for word in ["iam", "policy", "privilege", "role", "user", "wildcard"]):
        return "Identity and Access Management"

    if any(word in text for word in ["backup", "versioning", "retention", "recovery", "deletion"]):
        return "Resilience and Recovery"

    if any(word in text for word in ["rds", "database", "db instance"]):
        return "Database Security"

    if any(word in text for word in ["s3", "bucket", "storage"]):
        return "Storage Security"

    return "General Cloud Security"


def fallback_translation(check_id: str, check_name: str, category: str) -> dict:
    """Create a simple explanation when a Checkov ID is not in the mapping dictionary."""
    category_advice = {
        "Encryption": {
            "risk_level": "Medium",
            "why": "Unencrypted data can be harder to protect if storage or traffic is exposed.",
            "fix": "Enable encryption at rest or in transit using the cloud provider's recommended setting.",
        },
        "Public Exposure": {
            "risk_level": "High",
            "why": "Public access can allow unknown users on the internet to reach the resource.",
            "fix": "Restrict access to trusted IP ranges, private networks, or approved identities.",
        },
        "Logging and Monitoring": {
            "risk_level": "Medium",
            "why": "Without logs, it is harder to investigate security events or prove what happened.",
            "fix": "Enable logging, monitoring, or audit settings for the resource.",
        },
        "Identity and Access Management": {
            "risk_level": "High",
            "why": "Over-permissive access can allow users or attackers to do more than they should.",
            "fix": "Use least privilege and give only the permissions required for the task.",
        },
        "Resilience and Recovery": {
            "risk_level": "Medium",
            "why": "Weak recovery settings can make data loss or service downtime harder to manage.",
            "fix": "Enable suitable backup, versioning, retention, or recovery settings.",
        },
        "Database Security": {
            "risk_level": "High",
            "why": "Databases often store important data, so weak configuration can create serious risk.",
            "fix": "Review database access, encryption, backup, logging, and public exposure settings.",
        },
        "Storage Security": {
            "risk_level": "Medium",
            "why": "Storage services may contain sensitive files, logs, or backups.",
            "fix": "Review public access, encryption, logging, versioning, and retention settings.",
        },
    }

    advice = category_advice.get(
        category,
        {
            "risk_level": "Medium",
            "why": "This setting may not follow secure cloud configuration practice.",
            "fix": "Review the resource and update the Terraform code before deployment.",
        },
    )

    return {
        "simple_title": check_name,
        "category": category,
        "risk_level": advice["risk_level"],
        "what_this_means": f"Checkov detected this issue: {check_name}. A custom explanation is not available for this rule yet, so the report is showing general guidance for this type of risk.",
        "why_it_matters": advice["why"],
        "suggested_fix": advice["fix"],
        "example_fix": "",
    }


def translate_check(check_id: str, check_name: str) -> tuple[dict, str]:
    custom = CHECKOV_TRANSLATIONS.get(check_id)
    if custom:
        return custom, "custom"

    category = classify_finding(check_name)
    return fallback_translation(check_id, check_name, category), "fallback"


def detect_cloud_provider(check_id: str, resource: str, file_path: str) -> str:
    """Guess the cloud provider so the results page can filter large scans."""
    text = f"{check_id} {resource} {file_path}".lower()

    if "_aws_" in text or "aws_" in text:
        return "AWS"
    if "_azure_" in text or "azurerm_" in text or "azure" in text:
        return "Azure"
    if "_gcp_" in text or "google_" in text or "gcp" in text:
        return "GCP"

    return "Other"


def get_issue_type(check_id: str, translation: dict, check_name: str) -> str:
    if check_id in CHECKOV_ISSUE_TYPES:
        return CHECKOV_ISSUE_TYPES[check_id]

    category = translation.get("category") or classify_finding(check_name)
    return CATEGORY_ISSUE_TYPES.get(category, "General cloud security issue")


def priority_score(finding: dict) -> tuple[int, int]:
    """Lower score means higher priority in the Fix First panel."""
    risk_score = {"High": 0, "Medium": 1, "Low": 2}.get(finding.get("risk_level"), 3)
    category_order = {
        "Public Exposure": 0,
        "Identity and Access Management": 1,
        "Database Security": 2,
        "Encryption": 3,
        "Storage Security": 4,
        "Network Security": 5,
        "Logging and Monitoring": 6,
        "Resilience and Recovery": 7,
    }
    category_score = category_order.get(finding.get("category"), 9)
    return risk_score, category_score


def build_priority_findings(findings: list[dict]) -> list[dict]:
    """Select the top three findings a beginner should review first."""
    selected = []
    seen = set()

    for finding in sorted(findings, key=priority_score):
        key = (finding.get("simple_title"), finding.get("resource"))
        if key in seen:
            continue
        seen.add(key)
        selected.append(
            {
                "simple_title": finding.get("simple_title"),
                "risk_level": finding.get("risk_level"),
                "category": finding.get("category"),
                "provider": finding.get("provider"),
                "resource": finding.get("resource"),
                "check_id": finding.get("check_id"),
            }
        )
        if len(selected) == 3:
            break

    return selected


def real_code_example(example: str) -> str:
    """Only show example text when it looks like a real Terraform setting or block."""
    if not example:
        return ""

    stripped = example.strip()
    if not stripped:
        return ""

    lower = stripped.lower()
    if lower.startswith(("configure ", "prefer ", "avoid ", "limit ", "use ")):
        return ""

    if "=" in stripped or stripped.startswith("resource ") or stripped.startswith("module "):
        return stripped

    return ""


# Rule-specific guidance used by the results page.
# The app uses these steps to give users clearer advice about what to change.
CHECKOV_FIX_STEPS = {
    "CKV_AWS_23": [
        "Open the security group resource shown in the result.",
        "Find each ingress or egress rule with an empty description.",
        "Add a short description that explains why the rule is needed.",
        "Run the scan again to check that the warning is reduced or removed.",
    ],
    "CKV_AWS_24": [
        "Find the ingress rule that uses port 22.",
        "Change cidr_blocks from 0.0.0.0/0 to a trusted IP range.",
        "Use /32 for one trusted public IP address, for example YOUR_PUBLIC_IP/32.",
        "Keep SSH closed to the internet unless there is a clear reason.",
    ],
    "CKV_AWS_260": [
        "Find the ingress rule that uses port 80.",
        "Decide whether the resource really needs public HTTP access.",
        "If it is not a public web service, restrict the CIDR range to a private or trusted network.",
        "If the service must be public, consider HTTPS and a controlled load balancer design.",
    ],
    "CKV_AWS_382": [
        "Find the egress rule that allows all traffic to 0.0.0.0/0.",
        "Replace the open destination with the specific network or service that is required.",
        "Limit the protocol and port where possible instead of using protocol = -1.",
        "Remove the rule if the resource does not need outbound internet access.",
    ],
    "CKV2_AWS_5": [
        "Check whether the security group is actually used by another resource.",
        "Attach it to the correct EC2 instance, load balancer, database, or network interface if needed.",
        "Remove the security group from Terraform if it is not needed.",
    ],
    "CKV_AWS_20": [
        "Find the S3 ACL or bucket policy that allows public access.",
        "Change the ACL to private or remove the public ACL block.",
        "Use IAM roles or bucket policies with specific trusted principals instead of public access.",
        "Re-scan the file and check that public access findings are reduced.",
    ],
    "CKV2_AWS_6": [
        "Find the aws_s3_bucket_public_access_block resource.",
        "Set all four public access block values to true.",
        "Do not disable these settings unless the bucket is intentionally public.",
    ],
    "CKV_AWS_18": [
        "Add an S3 logging configuration for important buckets.",
        "Send logs to a separate logging bucket, not the same bucket.",
        "Check that the log bucket is private and protected.",
    ],
    "CKV_AWS_21": [
        "Add or update the S3 versioning configuration.",
        "Set versioning status to Enabled for important buckets.",
        "Re-scan to confirm versioning is detected.",
    ],
    "CKV_AWS_145": [
        "Add default server-side encryption to the bucket.",
        "Use a KMS key if the project needs stronger key control and auditing.",
        "Check that new objects will be encrypted by default.",
    ],
    "CKV_AWS_16": [
        "Find the RDS database resource shown in the result.",
        "Add or change storage_encrypted to true.",
        "Use a KMS key for stronger key control where suitable.",
        "Because this setting can require replacement, review it before real deployment.",
    ],
    "CKV_AWS_17": [
        "Find the RDS database resource shown in the result.",
        "Change publicly_accessible to false.",
        "Place the database in private subnets and allow access only from the application security group.",
    ],
    "CKV_AWS_118": [
        "Enable enhanced monitoring for the RDS database if better visibility is required.",
        "Set a suitable monitoring_interval value.",
        "Make sure the required monitoring role is configured.",
    ],
    "CKV_AWS_129": [
        "Enable database log exports for the database engine being used.",
        "For MySQL, consider error, general, and slowquery logs where suitable.",
        "Send logs to CloudWatch for easier review.",
    ],
    "CKV_AWS_133": [
        "Find backup_retention_period in the RDS resource.",
        "Change the value from 0 to a suitable number of days.",
        "Use at least a short backup period for learning tests, and a stronger policy for real systems.",
    ],
    "CKV_AWS_293": [
        "Find deletion_protection in the RDS resource.",
        "Change the value to true for important databases.",
        "Keep this setting enabled to reduce accidental database deletion risk.",
    ],
    "CKV_AWS_62": [
        "Find the IAM policy statement with Action = * and Resource = *.",
        "Replace the wildcard action with only the actions needed.",
        "Replace the wildcard resource with a specific resource ARN where possible.",
        "Use least privilege instead of full administrator access.",
    ],
    "CKV_AWS_63": [
        "Find the IAM policy action that uses a wildcard.",
        "Replace * with exact actions, such as s3:GetObject or ec2:DescribeInstances.",
        "Avoid service:* unless there is a clear reason and strong control.",
    ],
    "CKV_AWS_355": [
        "Find Resource = * in the IAM policy.",
        "Replace it with the specific ARN of the resource that is needed.",
        "Use separate statements if different resources need different access.",
    ],
}

# These patterns help the app highlight likely Terraform lines to review.
# Checkov normally gives a line range, not always one exact line. These hints make the result more useful.
CHECKOV_LINE_HINTS = {
    "CKV_AWS_23": [r'description\s*=\s*""'],
    "CKV_AWS_24": [r'from_port\s*=\s*22', r'to_port\s*=\s*22', r'cidr_blocks\s*=\s*\[.*0\.0\.0\.0/0.*\]'],
    "CKV_AWS_260": [r'from_port\s*=\s*80', r'to_port\s*=\s*80', r'cidr_blocks\s*=\s*\[.*0\.0\.0\.0/0.*\]'],
    "CKV_AWS_382": [r'protocol\s*=\s*"-1"', r'from_port\s*=\s*0', r'to_port\s*=\s*0', r'cidr_blocks\s*=\s*\[.*0\.0\.0\.0/0.*\]'],
    "CKV_AWS_20": [r'acl\s*=\s*"public', r'Principal\s*=\s*"\*"', r'Action\s*=\s*"s3:\*"'],
    "CKV2_AWS_6": [r'block_public_acls\s*=\s*false', r'block_public_policy\s*=\s*false', r'ignore_public_acls\s*=\s*false', r'restrict_public_buckets\s*=\s*false'],
    "CKV_AWS_16": [r'storage_encrypted\s*=\s*false'],
    "CKV_AWS_17": [r'publicly_accessible\s*=\s*true'],
    "CKV_AWS_133": [r'backup_retention_period\s*=\s*0'],
    "CKV_AWS_293": [r'deletion_protection\s*=\s*false'],
    "CKV_AWS_62": [r'Action\s*=\s*"\*"', r'Resource\s*=\s*"\*"', r'Action\s*=\s*\[\s*"\*"\s*\]', r'Resource\s*=\s*\[\s*"\*"\s*\]'],
    "CKV_AWS_63": [r'Action\s*=\s*"\*"', r'Action\s*=\s*\[\s*"\*"\s*\]'],
    "CKV_AWS_355": [r'Resource\s*=\s*"\*"', r'Resource\s*=\s*\[\s*"\*"\s*\]'],
}


RISK_DESCRIPTIONS = {
    "High": "High risk means this issue may expose data, allow public access, or give too much permission. Fix these first.",
    "Medium": "Medium risk means the setting is weak or incomplete. It should be reviewed before deployment.",
    "Low": "Low risk means the issue is mainly a good-practice or maintainability concern, but it is still worth improving.",
}

CATEGORY_ISSUE_TYPES = {
    "Public Exposure": "Public exposure",
    "Identity and Access Management": "Weak access control",
    "Encryption": "Missing or weak encryption",
    "Logging and Monitoring": "Missing logging or monitoring",
    "Resilience and Recovery": "Weak recovery setting",
    "Database Security": "Database security issue",
    "Storage Security": "Storage security issue",
    "Network Security": "Network rule issue",
    "Patch Management": "Patch management issue",
    "Governance": "Governance issue",
}

CHECKOV_ISSUE_TYPES = {
    "CKV_AWS_24": "Misconfigured value",
    "CKV_AWS_260": "Misconfigured value",
    "CKV_AWS_382": "Misconfigured value",
    "CKV_AWS_20": "Public storage setting",
    "CKV2_AWS_6": "Public access control issue",
    "CKV_AWS_16": "Misconfigured value",
    "CKV_AWS_17": "Misconfigured value",
    "CKV_AWS_62": "Weak access control",
    "CKV_AWS_63": "Weak access control",
    "CKV_AWS_355": "Weak access control",
}

# These checks often fail because something is missing, not because one single line is visibly wrong.
MISSING_SETTING_IDS = {
    "CKV_AWS_18", "CKV_AWS_21", "CKV_AWS_118", "CKV_AWS_129",
    "CKV_AWS_145", "CKV_AWS_144", "CKV2_AWS_61", "CKV2_AWS_62",
    "CKV_AWS_157", "CKV_AWS_161", "CKV_AWS_226", "CKV2_AWS_60",
}

CHECKOV_FIX_EXAMPLES = {
    "CKV_AWS_24": {
        "before": 'cidr_blocks = ["0.0.0.0/0"]',
        "after": 'cidr_blocks = ["YOUR_PUBLIC_IP/32"]',
    },
    "CKV_AWS_260": {
        "before": 'cidr_blocks = ["0.0.0.0/0"]',
        "after": 'cidr_blocks = ["10.0.0.0/16"]  # or only the trusted range needed',
    },
    "CKV_AWS_382": {
        "before": 'protocol = "-1"\ncidr_blocks = ["0.0.0.0/0"]',
        "after": 'protocol = "tcp"\nfrom_port = 443\nto_port = 443\ncidr_blocks = ["10.0.0.0/16"]',
    },
    "CKV_AWS_23": {
        "before": 'description = ""',
        "after": 'description = "Allow SSH only from trusted administrator IP"',
    },
    "CKV_AWS_20": {
        "before": 'acl = "public-read"',
        "after": 'acl = "private"',
    },
    "CKV2_AWS_6": {
        "before": 'block_public_acls = false\nblock_public_policy = false\nignore_public_acls = false\nrestrict_public_buckets = false',
        "after": 'block_public_acls = true\nblock_public_policy = true\nignore_public_acls = true\nrestrict_public_buckets = true',
    },
    "CKV_AWS_16": {
        "before": 'storage_encrypted = false',
        "after": 'storage_encrypted = true',
    },
    "CKV_AWS_17": {
        "before": 'publicly_accessible = true',
        "after": 'publicly_accessible = false',
    },
    "CKV_AWS_133": {
        "before": 'backup_retention_period = 0',
        "after": 'backup_retention_period = 7',
    },
    "CKV_AWS_293": {
        "before": 'deletion_protection = false',
        "after": 'deletion_protection = true',
    },
    "CKV_AWS_62": {
        "before": 'Action = "*"\nResource = "*"',
        "after": 'Action = ["s3:GetObject"]\nResource = "arn:aws:s3:::example-bucket/*"',
    },
    "CKV_AWS_63": {
        "before": 'Action = "*"',
        "after": 'Action = ["ec2:DescribeInstances"]',
    },
    "CKV_AWS_355": {
        "before": 'Resource = "*"',
        "after": 'Resource = "arn:aws:s3:::example-bucket/*"',
    },
    "CKV_AWS_21": {
        "before": '# No aws_s3_bucket_versioning resource is configured',
        "after": 'resource "aws_s3_bucket_versioning" "example" {\n  bucket = aws_s3_bucket.example.id\n  versioning_configuration {\n    status = "Enabled"\n  }\n}',
    },
    "CKV_AWS_18": {
        "before": '# No aws_s3_bucket_logging resource is configured',
        "after": 'resource "aws_s3_bucket_logging" "example" {\n  bucket = aws_s3_bucket.example.id\n  target_bucket = aws_s3_bucket.log_bucket.id\n  target_prefix = "access-logs/"\n}',
    },
}


def normalise_line_range(value) -> tuple[int | None, int | None]:
    """Convert Checkov line range into start and end line numbers."""
    if isinstance(value, list) and value:
        try:
            start = int(value[0])
            end = int(value[-1]) if len(value) > 1 else start
            return start, end
        except (TypeError, ValueError):
            return None, None

    if isinstance(value, str):
        numbers = re.findall(r"\d+", value)
        if numbers:
            start = int(numbers[0])
            end = int(numbers[-1])
            return start, end

    return None, None


def resolve_source_file(scan_dir: Path, file_path: str) -> Path | None:
    """Find the Terraform file referenced by Checkov inside the scan folder."""
    if not file_path or file_path == "N/A":
        return None

    clean_path = file_path.replace("\\", "/").lstrip("/")
    candidates = [scan_dir / clean_path]

    # If Checkov returns only a file name, search the scan folder.
    candidates.extend(scan_dir.rglob(Path(clean_path).name))

    for candidate in candidates:
        try:
            if candidate.exists() and candidate.is_file() and candidate.resolve().is_relative_to(scan_dir.resolve()):
                return candidate
        except Exception:
            continue

    return None


def build_code_context(scan_dir: Path, file_path: str, line_range, check_id: str) -> dict:
    """Return nearby source code lines and highlight likely lines to change."""
    source_file = resolve_source_file(scan_dir, file_path)
    start, end = normalise_line_range(line_range)

    if not source_file or start is None:
        return {
            "available": False,
            "message": "Source line preview is not available for this finding.",
            "review_type": "not_available",
            "lines": [],
            "likely_lines": [],
            "start_line": start,
            "end_line": end,
        }

    try:
        all_lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return {
            "available": False,
            "message": "The source file could not be read for line preview.",
            "review_type": "not_available",
            "lines": [],
            "likely_lines": [],
            "start_line": start,
            "end_line": end,
        }

    padding = 3
    preview_start = max(1, start - padding)
    preview_end = min(len(all_lines), end + padding)
    patterns = [re.compile(pattern, re.IGNORECASE) for pattern in CHECKOV_LINE_HINTS.get(check_id, [])]

    likely_lines = []
    context_lines = []

    for line_number in range(preview_start, preview_end + 1):
        text = all_lines[line_number - 1]
        in_checkov_range = start <= line_number <= end
        is_likely_change = in_checkov_range and any(pattern.search(text) for pattern in patterns)

        if is_likely_change:
            likely_lines.append(line_number)

        context_lines.append(
            {
                "number": line_number,
                "content": text,
                "in_range": in_checkov_range,
                "is_likely_change": is_likely_change,
            }
        )

    if likely_lines:
        review_type = "exact_line"
        message = "Risky line found. Review and change the red highlighted line."
        if len(likely_lines) > 1:
            message = "Risky lines found. Review and change the red highlighted lines."
    elif check_id in MISSING_SETTING_IDS:
        review_type = "missing_setting"
        message = "No single wrong line was found. This issue is likely caused by a missing security setting inside this resource block. Review the amber range and add the required setting."
    else:
        review_type = "line_range"
        message = "Checkov reported this issue in the shown resource block. Review the amber line range and update the relevant setting."

    return {
        "available": True,
        "message": message,
        "review_type": review_type,
        "lines": context_lines,
        "likely_lines": likely_lines,
        "start_line": start,
        "end_line": end,
    }


def get_fix_steps(check_id: str, translation: dict) -> list[str]:
    """Return rule-specific steps or a simple fallback."""
    if check_id in CHECKOV_FIX_STEPS:
        return CHECKOV_FIX_STEPS[check_id]

    category = translation.get("category", "cloud security")
    steps = [
        "Open the Terraform file and resource shown in the result.",
        "Review the highlighted line range or resource block.",
        f"Update the {category.lower()} setting using the recommended change above.",
        "Run the scan again and check that the finding is reduced or removed.",
    ]
    return steps


def simplify_failed_checks(failed_checks: list[dict], scan_dir: Path) -> list[dict]:
    simplified = []

    for check in failed_checks:
        check_id = check.get("check_id", "N/A")
        check_name = check.get("check_name", "Unknown check")
        translation, mapping_source = translate_check(check_id, check_name)

        file_path = check.get("file_path", "N/A")
        file_line_range = check.get("file_line_range", [])
        resource = check.get("resource", "N/A")
        code_context = build_code_context(scan_dir, file_path, file_line_range, check_id)
        fix_steps = get_fix_steps(check_id, translation)
        risk_level = translation["risk_level"]
        provider = detect_cloud_provider(check_id, resource, file_path)

        simplified.append(
            {
                "check_id": check_id,
                "check_name": check_name,
                "simple_title": translation["simple_title"],
                "category": translation["category"],
                "issue_type": get_issue_type(check_id, translation, check_name),
                "provider": provider,
                "risk_level": risk_level,
                "risk_description": RISK_DESCRIPTIONS.get(risk_level, "Review this issue before deployment."),
                "what_this_means": translation["what_this_means"],
                "why_it_matters": translation["why_it_matters"],
                "suggested_fix": translation["suggested_fix"],
                "fix_steps": fix_steps,
                "fix_example": CHECKOV_FIX_EXAMPLES.get(check_id),
                "example_fix": real_code_example(translation.get("example_fix", "")),
                "resource": resource,
                "file_path": file_path,
                "file_line_range": file_line_range,
                "code_context": code_context,
                "guideline": check.get("guideline", "No guideline link provided"),
                "technical_severity": check.get("severity") or "Not provided by local scan",
                "mapping_source": mapping_source,
            }
        )

    return simplified


def calculate_overall_risk(summary: dict, findings: list[dict]) -> str:
    if not findings:
        return "Low"

    if any(finding.get("risk_level") == "High" for finding in findings):
        return "High"

    if summary.get("failed", 0) >= 3 or any(finding.get("risk_level") == "Medium" for finding in findings):
        return "Medium"

    return "Low"


def make_report(scan_id: str, checkov_json: dict, scan_dir: Path) -> dict:
    normalised = flatten_checkov_results(checkov_json)
    findings = simplify_failed_checks(normalised["failed_checks"], scan_dir)
    summary = normalised["summary"]

    summary["custom_explanations"] = sum(1 for finding in findings if finding["mapping_source"] == "custom")
    summary["fallback_explanations"] = sum(1 for finding in findings if finding["mapping_source"] == "fallback")
    provider_counts = {}
    for finding in findings:
        provider = finding.get("provider", "Other")
        provider_counts[provider] = provider_counts.get(provider, 0) + 1

    report = {
        "scan_id": scan_id,
        "summary": summary,
        "risk_level": calculate_overall_risk(summary, findings),
        "risk_description": RISK_DESCRIPTIONS.get(calculate_overall_risk(summary, findings), "Review the findings before deployment."),
        "provider_counts": provider_counts,
        "priority_findings": build_priority_findings(findings),
        "findings": findings,
    }

    report_path = REPORT_DIR / f"{scan_id}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return report


def append_feedback_to_csv(data: dict) -> None:
    """
    Saves every feedback response automatically for the owner.
    The owner can find all saved responses in reports/feedback.csv.
    """
    file_exists = FEEDBACK_FILE.exists()

    fieldnames = [
        "timestamp",
        "scan_id",
        "role",
        "ease_of_use",
        "report_clarity",
        "line_guidance_helpfulness",
        "mitigation_usefulness",
        "checkov_output_simplified",
        "confidence_after_use",
        "most_useful_part",
        "confusing_part",
        "comments",
    ]

    with FEEDBACK_FILE.open("a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(data)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded_file = request.files.get("terraform_file")

        if not uploaded_file or uploaded_file.filename == "":
            flash("Please upload a Terraform .tf file or a .zip folder.", "error")
            return redirect(url_for("index"))

        if not allowed_file(uploaded_file.filename):
            flash("Only .tf, .tfvars, .hcl, and .zip files are allowed.", "error")
            return redirect(url_for("index"))

        try:
            scan_dir, scan_id = prepare_scan_folder(uploaded_file)
            checkov_json, error = run_checkov(scan_dir)
        except Exception as exc:
            flash(f"Upload or scan preparation failed: {exc}", "error")
            return redirect(url_for("index"))

        if error:
            flash(error, "error")
            return redirect(url_for("index"))

        report = make_report(scan_id, checkov_json, scan_dir)
        return render_template("results.html", report=report)

    return render_template("index.html")


@app.route("/feedback/<scan_id>", methods=["GET", "POST"])
def feedback(scan_id: str):
    safe_id = secure_filename(scan_id)
    report_path = REPORT_DIR / f"{safe_id}.json"

    if not report_path.exists():
        flash("Scan report not found. Please run a scan first.", "error")
        return redirect(url_for("index"))

    if request.method == "POST":
        feedback_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_id": safe_id,
            "role": request.form.get("role", "").strip(),
            "ease_of_use": request.form.get("ease_of_use", "").strip(),
            "report_clarity": request.form.get("report_clarity", "").strip(),
            "line_guidance_helpfulness": request.form.get("line_guidance_helpfulness", "").strip(),
            "mitigation_usefulness": request.form.get("mitigation_usefulness", "").strip(),
            "checkov_output_simplified": request.form.get("checkov_output_simplified", "").strip(),
            "confidence_after_use": request.form.get("confidence_after_use", "").strip(),
            "most_useful_part": request.form.get("most_useful_part", "").strip(),
            "confusing_part": request.form.get("confusing_part", "").strip(),
            "comments": request.form.get("comments", "").strip(),
        }

        append_feedback_to_csv(feedback_data)
        return render_template("feedback_success.html", scan_id=safe_id)

    return render_template("feedback.html", scan_id=safe_id)


@app.route("/download/<scan_id>")
def download_report(scan_id: str):
    safe_id = secure_filename(scan_id)
    report_path = REPORT_DIR / f"{safe_id}.json"

    if not report_path.exists():
        flash("Report not found.", "error")
        return redirect(url_for("index"))

    return send_file(
        report_path,
        as_attachment=True,
        download_name=f"terraform_security_report_{safe_id}.json",
    )


@app.route("/download-feedback")
def download_feedback():
    if not FEEDBACK_FILE.exists():
        flash("No feedback has been submitted yet.", "error")
        return redirect(url_for("index"))

    return send_file(
        FEEDBACK_FILE,
        as_attachment=True,
        download_name="prototype_feedback.csv",
    )


@app.errorhandler(413)
def file_too_large(error):
    flash(f"File too large. Maximum upload size is {MAX_UPLOAD_MB} MB.", "error")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
