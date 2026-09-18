"""
Flask web GUI for the network compliance framework.

Purely additive: this module only imports and calls the existing
collectors/parser/compliance/remediation/webreport packages exactly as
main.py does. No logic in those packages is modified. main.py's CLI
path (`python3 main.py`) is untouched and keeps working as before.

Run with:
    python3 app.py

Binds to 0.0.0.0 so it is reachable from outside localhost (e.g. when
running on a remote lab host over SSH).
"""
import json
import socket
import threading
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, request

from main import load_baseline, load_devices, scan_device
from remediation.applier import RemediationApplier
from remediation.generator import RemediationGenerator
from remediation.live_applier import LiveRemediationApplier
from remediation.verifier import RemediationVerifier
from webreport.report_generator import generate_remediation_report, generate_report

APP_ROOT = Path(__file__).parent
INDEX_HTML_PATH = APP_ROOT / "webapp" / "index.html"

app = Flask(__name__)

# In-memory scan/remediation history, keyed by device name. Reset on
# restart -- this is a lab tool, not a persistence layer. Guarded by a
# lock because the dev server runs threaded (an SSH-bound scan can take
# tens of seconds and shouldn't block other requests).
STATE_LOCK = threading.Lock()
STATE = {}


def _device_by_name(name):
    for device in load_devices():
        if device["name"] == name:
            return device
    return None


def _score_from_results(results):
    if not results:
        return 0
    passed = sum(1 for r in results if r.status == "PASS")
    return round((passed / len(results)) * 100, 2)


@app.route("/")
def dashboard():
    devices = load_devices()

    with STATE_LOCK:
        device_states = []
        for device in devices:
            device_state = STATE.get(device["name"], {})
            last_scan = device_state.get("last_scan")

            device_states.append({
                "name": device["name"],
                "host": device.get("host"),
                "collection_method": device.get("collection_method"),
                "scanned": last_scan is not None,
                "score": last_scan["score"] if last_scan else None,
                "results": (
                    [r.to_dict() for r in last_scan["results"]]
                    if last_scan else []
                ),
                "has_remediation": device_state.get("last_remediation") is not None,
            })

    initial_state = {
        "hostname": socket.gethostname(),
        "devices": device_states,
    }

    html = INDEX_HTML_PATH.read_text(encoding="utf-8")
    html = html.replace(
        "__INITIAL_STATE_JSON__",
        json.dumps(initial_state)
    )

    return Response(html, mimetype="text/html")


@app.route("/scan/<device_name>", methods=["POST"])
def scan(device_name):
    device = _device_by_name(device_name)

    if device is None:
        return jsonify({"error": f"Unknown device: {device_name}"}), 404

    baseline = load_baseline()

    try:
        result = scan_device(device, baseline)
    except Exception as exc:
        return jsonify({
            "error": f"Scan failed for {device_name}: {exc}"
        }), 502

    with STATE_LOCK:
        STATE.setdefault(device_name, {})["last_scan"] = {
            "results": result["results"],
            "score": result["score"],
            "timestamp": datetime.now().isoformat(),
        }

    return jsonify({
        "device": device_name,
        "score": result["score"],
        "results": [r.to_dict() for r in result["results"]],
    })


@app.route("/remediate/<device_name>", methods=["POST"])
def remediate(device_name):
    device = _device_by_name(device_name)

    if device is None:
        return jsonify({"error": f"Unknown device: {device_name}"}), 404

    body = request.get_json(silent=True) or {}
    live = bool(body.get("live", False))

    with STATE_LOCK:
        device_state = STATE.get(device_name, {})
        last_scan = device_state.get("last_scan")

    if last_scan is None:
        return jsonify({
            "error": f"No scan on record for {device_name}. Scan it first."
        }), 400

    before_results = last_scan["results"]
    before_score = last_scan["score"]
    violations = [r for r in before_results if r.status == "FAIL"]

    baseline = load_baseline()
    generator = RemediationGenerator()

    if live:
        if device.get("collection_method") != "ssh":
            return jsonify({
                "error": (
                    f"{device_name} does not use collection_method: ssh "
                    f"in devices.yaml; live remediation needs live SSH access."
                )
            }), 400
        applier = LiveRemediationApplier(device)
    else:
        applier = RemediationApplier(device["config"])

    applied = []
    skipped = []

    try:
        for violation in violations:
            remediation_text = generator.generate_for_violation(violation)

            if remediation_text is None:
                skipped.append({
                    "rule": violation.rule,
                    "interface": violation.interface,
                })
                continue

            applier.apply(remediation_text)
            applied.append({
                "rule": violation.rule,
                "interface": violation.interface,
            })

        if live:
            after = scan_device(device, baseline)
            after_results = after["results"]
            after_score = after["score"]
        else:
            verifier = RemediationVerifier(baseline)
            after_results = verifier.verify(
                device_name=device_name,
                config_path=device["config"],
            )
            after_score = _score_from_results(after_results)

    except Exception as exc:
        return jsonify({
            "error": f"Remediation failed for {device_name}: {exc}"
        }), 502

    now = datetime.now().isoformat()

    with STATE_LOCK:
        STATE.setdefault(device_name, {})["last_scan"] = {
            "results": after_results,
            "score": after_score,
            "timestamp": now,
        }
        STATE[device_name]["last_remediation"] = {
            "before_results": before_results,
            "before_score": before_score,
            "after_results": after_results,
            "after_score": after_score,
            "method": "live SSH (Netmiko)" if live else "file-based",
            "timestamp": now,
        }

    return jsonify({
        "device": device_name,
        "live": live,
        "applied": applied,
        "skipped": skipped,
        "before": {
            "score": before_score,
            "results": [r.to_dict() for r in before_results],
        },
        "after": {
            "score": after_score,
            "results": [r.to_dict() for r in after_results],
        },
    })


@app.route("/report/compliance")
def report_compliance():
    with STATE_LOCK:
        state_snapshot = {
            name: dict(device_state)
            for name, device_state in STATE.items()
        }

    all_results = []

    for device in load_devices():
        device_state = state_snapshot.get(device["name"], {})
        last_scan = device_state.get("last_scan")

        if last_scan is None:
            continue

        all_results.append({
            "device": device["name"],
            "score": last_scan["score"],
            "results": last_scan["results"],
        })

    if not all_results:
        return jsonify({
            "error": "no devices have been scanned yet"
        }), 400

    path = generate_report(
        all_results,
        collection_summary="configured collection methods (see config/devices.yaml)",
    )

    html = Path(path).read_text(encoding="utf-8")
    filename = f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    return Response(
        html,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


@app.route("/report/remediation/<device_name>")
def report_remediation(device_name):
    device = _device_by_name(device_name)

    if device is None:
        return jsonify({"error": f"Unknown device: {device_name}"}), 404

    with STATE_LOCK:
        device_state = dict(STATE.get(device_name, {}))

    last_remediation = device_state.get("last_remediation")

    if last_remediation is None:
        return jsonify({
            "error": f"no remediation has been run for {device_name} yet"
        }), 404

    path = generate_remediation_report(
        device_name=device_name,
        before_results=last_remediation["before_results"],
        before_score=last_remediation["before_score"],
        after_results=last_remediation["after_results"],
        after_score=last_remediation["after_score"],
        method=last_remediation["method"],
    )

    html = Path(path).read_text(encoding="utf-8")
    filename = f"remediation_{device_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    return Response(
        html,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)
