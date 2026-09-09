from pathlib import Path
import sys
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
sys.path.insert(0, str(PROJECT_DIR))

import app


def test_missing_rule_description():
    """
    REG01:
    Regression test for the participant-reported missing-description case.
    """

    with tempfile.TemporaryDirectory() as td:
        scan_dir = Path(td)
        fixture = scan_dir / "missing_rule_description.tf"

        fixture.write_text(
            'resource "aws_security_group" "example" {\n'
            '  description = "Main security group"\n'
            '\n'
            '  ingress {\n'
            '    from_port   = 22\n'
            '    to_port     = 22\n'
            '    protocol    = "tcp"\n'
            '    cidr_blocks = ["10.0.0.0/8"]\n'
            '  }\n'
            '}\n',
            encoding="utf-8",
        )

        context = app.build_code_context(
            scan_dir,
            "/missing_rule_description.tf",
            [1, 10],
            "CKV_AWS_23",
        )

        displayed_lines = [
            line["number"]
            for line in context.get("lines", [])
        ]

        assert context.get("review_type") == "missing_setting"
        assert context.get("likely_lines") == []

        # Existing resource description must not be treated as faulty.
        assert 2 not in displayed_lines

        # Relevant ingress context should be shown.
        assert 4 in displayed_lines

        # Avoid repeating the complete resource block.
        assert len(displayed_lines) < 10

        print("REG01 PASS")
        print("Missing-description regression handled correctly.")
        print(f"Displayed lines: {displayed_lines}")


if __name__ == "__main__":
    test_missing_rule_description()
