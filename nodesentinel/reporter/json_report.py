
import json
from datetime import datetime, timezone


def build_report(target, findings):
    severity_levels = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
    ]

    summary = {
        severity: 0
        for severity in severity_levels
    }

    for finding in findings:
        severity = finding.get("severity", "Informational")

        if severity not in summary:
            summary[severity] = 0

        summary[severity] += 1

    report = {
        "tool": "NodeSentinel",
        "target": target,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "summary": summary,
        "findings": findings,
    }

    return report


def write_json_report(target, findings, output_path):
    report = build_report(target, findings)

    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return output_path
