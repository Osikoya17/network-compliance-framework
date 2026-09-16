"""
Generates a self-contained HTML compliance report from a completed scan.
No server, no external dependencies at view-time -- open the output file
directly in any browser (works fully offline, safe for a defense demo).

Usage (from main.py), after building `all_results`:

    from webreport.report_generator import generate_report
    generate_report(all_results)

`all_results` is the same list main.py already builds:
    [{"device": name, "score": score, "results": [ComplianceResult, ...]}, ...]
"""
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

SEV_COLOR = {
    "CRITICAL": "#8b2e2e",
    "HIGH": "#a85c2e",
    "MEDIUM": "#8a7530",
    "LOW": "#6b6b6b",
}

TEMPLATE_DIR = Path(__file__).parent
OUTPUT_DIR = Path("reports")


def _band(score):
    if score >= 90:
        return "band-good", "bar-good"
    if score >= 70:
        return "band-mid", "bar-mid"
    return "band-poor", "bar-poor"


def _serialize_check(result):
    return {
        "rule": result.rule,
        "interface": result.interface,
        "status": result.status,
        "expected": result.expected,
        "actual": result.actual,
        "severity": result.severity,
        "sev_color": SEV_COLOR.get(result.severity, "#a85c2e"),
    }


def _serialize_device(device_result):
    checks = [_serialize_check(r) for r in device_result["results"]]
    passes = sum(1 for c in checks if c["status"] == "PASS")
    band_text, band_bg = _band(device_result["score"])
    return {
        "name": device_result["device"],
        "score": device_result["score"],
        "pass_count": passes,
        "fail_count": len(checks) - passes,
        "results": checks,
        "band_text": band_text,
        "band_bg": band_bg,
    }


def generate_report(
    all_results,
    collection_summary="",
    project_title="Automated Network Configuration & Compliance Framework",
):
    """
    Writes reports/compliance_report_<timestamp>.html and reports/latest.html.
    Returns the path to the timestamped report.
    """
    devices = [_serialize_device(d) for d in all_results]

    total_checks = sum(len(d["results"]) for d in devices)
    pass_count = sum(d["pass_count"] for d in devices)
    fail_count = total_checks - pass_count
    overall_score = (
        round(sum(d["score"] for d in devices) / len(devices), 2)
        if devices else 0
    )
    overall_band, _ = _band(overall_score)

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)))
    template = env.get_template("template.html.j2")

    html = template.render(
        project_title=project_title,
        generated_at=datetime.now().strftime("%A, %d %B %Y %H:%M"),
        device_count=len(devices),
        total_checks=total_checks,
        pass_count=pass_count,
        fail_count=fail_count,
        overall_score=overall_score,
        overall_band=overall_band,
        devices=devices,
        collection_summary=collection_summary or "configured collection methods (see config/devices.yaml)",
    )

    OUTPUT_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    timestamped_path = OUTPUT_DIR / f"compliance_report_{timestamp}.html"
    latest_path = OUTPUT_DIR / "latest.html"

    timestamped_path.write_text(html, encoding="utf-8")
    latest_path.write_text(html, encoding="utf-8")

    print(f"\nHTML report written to {timestamped_path} (and reports/latest.html)")

    return timestamped_path
