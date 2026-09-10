from __future__ import annotations

import json
import sys
import tempfile
import types
import zipfile
from pathlib import Path

# Minimal stubs allow importing app.py in this verification environment where
# Flask is not installed. The tests below exercise only project-specific pure
# application functions and do not use Flask request handling or Checkov.
flask = types.ModuleType("flask")

class DummyFlask:
    def __init__(self, *args, **kwargs):
        self.config = {}
    def route(self, *args, **kwargs):
        return lambda fn: fn
    def errorhandler(self, *args, **kwargs):
        return lambda fn: fn

flask.Flask = DummyFlask
flask.render_template = lambda *a, **k: None
flask.request = types.SimpleNamespace()
flask.redirect = lambda *a, **k: None
flask.url_for = lambda *a, **k: ""
flask.flash = lambda *a, **k: None
flask.send_file = lambda *a, **k: None
flask.session = {}
sys.modules.setdefault("flask", flask)

werkzeug = types.ModuleType("werkzeug")
werkzeug_utils = types.ModuleType("werkzeug.utils")
def secure_filename(name):
    return Path(name).name.replace(" ", "_")
werkzeug_utils.secure_filename = secure_filename
sys.modules.setdefault("werkzeug", werkzeug)
sys.modules.setdefault("werkzeug.utils", werkzeug_utils)

PROJECT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIR))
import app as target

results = []

def record(test_id, target_name, expected, observed, passed):
    results.append({
        "id": test_id,
        "verification_target": target_name,
        "expected": expected,
        "observed": observed,
        "result": "PASS" if passed else "FAIL",
    })
    status = "PASS" if passed else "FAIL"
    print(f"{test_id}  {status}  {target_name}")
    print(f"      Expected: {expected}")
    print(f"      Observed: {observed}")

# SV01 - accept supported Terraform extension
observed = target.allowed_file("main.tf")
record("SV01", "Accept Terraform .tf extension", "main.tf accepted", f"allowed_file('main.tf') -> {observed}", observed is True)

# SV02 - reject unsupported extension
observed = target.allowed_file("payload.exe")
record("SV02", "Reject unsupported extension", "payload.exe rejected", f"allowed_file('payload.exe') -> {observed}", observed is False)

# SV03 - select custom mapping
translation, source = target.translate_check("CKV_AWS_24", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22")
passed = source == "custom" and translation.get("simple_title") == "SSH is open to the internet"
record("SV03", "Select custom translation", "CKV_AWS_24 uses custom mapping", f"mapping_source={source}; title={translation.get('simple_title')}", passed)

# SV04 - fallback for unsupported Azure-like public access rule
translation, source = target.translate_check("CKV_AZURE_999", "Ensure public access is disabled")
passed = source == "fallback" and translation.get("category") == "Public Exposure"
record("SV04", "Use fallback for unsupported rule", "Unknown Azure public-access rule classified as Public Exposure", f"mapping_source={source}; category={translation.get('category')}", passed)

# SV05 - AWS provider detection
observed = target.detect_cloud_provider("CKV_AWS_24", "aws_security_group.open_ssh", "/main.tf")
record("SV05", "Detect AWS provider", "AWS check/resource -> AWS", observed, observed == "AWS")

# SV06 - Azure provider detection
observed = target.detect_cloud_provider("CKV_AZURE_10", "azurerm_network_security_group.example", "/main.tf")
record("SV06", "Detect Azure provider", "azurerm resource -> Azure", observed, observed == "Azure")

# SV07 - GCP provider detection
observed = target.detect_cloud_provider("CKV_GCP_2", "google_compute_firewall.example", "/main.tf")
record("SV07", "Detect GCP provider", "google resource -> GCP", observed, observed == "GCP")

# SV08 - line guidance for an open SSH fixture
with tempfile.TemporaryDirectory() as td:
    scan_dir = Path(td)
    fixture = scan_dir / "open_ssh.tf"
    fixture.write_text(
        'resource "aws_security_group" "open_ssh" {\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n',
        encoding="utf-8",
    )
    context = target.build_code_context(scan_dir, "/open_ssh.tf", [2, 7], "CKV_AWS_24")
    observed_lines = context.get("likely_lines")
    passed = observed_lines == [3, 4, 6]
    record("SV08", "Identify likely risky source line", "Open SSH fixture includes lines 3, 4 and 6 as likely-change lines", f"likely_lines={observed_lines}", passed)

# SV09 - overall risk calculation
observed = target.calculate_overall_risk({"failed": 1}, [{"risk_level": "High"}])
record("SV09", "Calculate overall risk", "High mapped finding -> High overall risk", observed, observed == "High")

# SV10 - priority list contains public SSH finding
priority_input = [
    {"simple_title": "Logging missing", "risk_level": "Medium", "category": "Logging and Monitoring", "provider": "AWS", "resource": "aws_s3_bucket.example", "check_id": "CKV_AWS_18"},
    {"simple_title": "SSH is open to the internet", "risk_level": "High", "category": "Public Exposure", "provider": "AWS", "resource": "aws_security_group.open_ssh", "check_id": "CKV_AWS_24"},
]
priority = target.build_priority_findings(priority_input)
ids = [x.get("check_id") for x in priority]
record("SV10", "Build priority list", "CKV_AWS_24 appears in priority findings", f"priority_ids={ids}", "CKV_AWS_24" in ids)

# SV11 - report counts custom explanation
with tempfile.TemporaryDirectory() as td:
    scan_dir = Path(td)
    (scan_dir / "main.tf").write_text(
        'resource "aws_security_group" "open_ssh" {\n'
        '  ingress {\n'
        '    from_port   = 22\n'
        '    to_port     = 22\n'
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        '  }\n'
        '}\n', encoding="utf-8")
    fake_checkov = {
        "results": {
            "passed_checks": [],
            "failed_checks": [{
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "resource": "aws_security_group.open_ssh",
                "file_path": "/main.tf",
                "file_line_range": [1, 8],
                "guideline": "https://www.checkov.io/",
            }],
            "skipped_checks": [],
        },
        "summary": {"passed": 0, "failed": 1, "skipped": 0, "parsing_errors": 0},
    }
    report = target.make_report("sv11test", fake_checkov, scan_dir)
    observed = report["summary"].get("custom_explanations")
    record("SV11", "Count explanation source", "Report records one custom explanation", f"custom_explanations={observed}", observed == 1)
    # Remove generated temporary report from extracted project copy.
    try:
        (target.REPORT_DIR / "sv11test.json").unlink()
    except FileNotFoundError:
        pass

# SV12 - block ZIP path traversal
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    zip_path = base / "unsafe.zip"
    destination = base / "extract"
    destination.mkdir()
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("../evil.tf", "resource = unsafe")
    blocked = False
    observed = "No exception"
    try:
        target.safe_extract_zip(zip_path, destination)
    except ValueError as exc:
        blocked = True
        observed = f"ValueError: {exc}"
    record("SV12", "Protect ZIP extraction", "../evil.tf path traversal is blocked", observed, blocked)

passed_count = sum(r["result"] == "PASS" for r in results)
failed_count = len(results) - passed_count
print("\nSUMMARY")
print(f"Passed: {passed_count}/{len(results)}")
print(f"Failed: {failed_count}/{len(results)}")
print("Overall: " + ("PASS" if failed_count == 0 else "FAIL"))

out_json = Path(__file__).resolve().with_name("source_level_verification_results.json")
out_json.write_text(json.dumps({"passed": passed_count, "failed": failed_count, "tests": results}, indent=2), encoding="utf-8")

if failed_count:
    raise SystemExit(1)
