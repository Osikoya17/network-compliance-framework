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
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap

from main import load_baseline, load_devices, scan_device
from remediation.applier import RemediationApplier
from remediation.generator import RemediationGenerator
from remediation.live_applier import LiveRemediationApplier
from remediation.verifier import RemediationVerifier
from webreport.report_generator import generate_remediation_report, generate_report

APP_ROOT = Path(__file__).parent
INDEX_HTML_PATH = APP_ROOT / "webapp" / "index.html"
DEVICES_YAML_PATH = APP_ROOT / "config" / "devices.yaml"
BASELINE_YAML_PATH = APP_ROOT / "config" / "baseline.yaml"

app = Flask(__name__)

# In-memory scan/remediation history, keyed by device name. Reset on
# restart -- this is a lab tool, not a persistence layer. Guarded by a
# lock because the dev server runs threaded (an SSH-bound scan can take
# tens of seconds and shouldn't block other requests).
STATE_LOCK = threading.Lock()
STATE = {}

# Serializes writes to config/devices.yaml and config/baseline.yaml so
# two concurrent "Add Device" submissions can't interleave and corrupt
# either file.
DEVICES_FILE_LOCK = threading.Lock()


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


def _ryaml():
    yaml = YAML()
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.preserve_quotes = True
    return yaml


def _build_device_states():
    # Same per-device shape the dashboard's INITIAL_STATE already uses
    # -- deliberately excludes username/password, which the frontend
    # never receives (see dashboard()/add_device()).
    with STATE_LOCK:
        device_states = []
        for device in load_devices():
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
    return device_states


@app.route("/")
def dashboard():
    initial_state = {
        "hostname": socket.gethostname(),
        "devices": _build_device_states(),
    }

    html = INDEX_HTML_PATH.read_text(encoding="utf-8")
    html = html.replace(
        "__INITIAL_STATE_JSON__",
        json.dumps(initial_state)
    )

    return Response(html, mimetype="text/html")


@app.route("/devices", methods=["POST"])
def add_device():
    body = request.get_json(silent=True) or {}

    name = (body.get("name") or "").strip()
    collection_method = (body.get("collection_method") or "").strip()
    host = (body.get("host") or "").strip()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    access_ports = body.get("access_ports") or []
    trunk_ports = body.get("trunk_ports") or []

    if not name:
        return jsonify({"error": "Device name is required."}), 400

    if collection_method not in ("ssh", "file"):
        return jsonify({
            "error": "collection_method must be 'ssh' or 'file'."
        }), 400

    if not isinstance(access_ports, list) or not all(isinstance(p, str) for p in access_ports):
        return jsonify({"error": "access_ports must be a list of strings."}), 400

    if not isinstance(trunk_ports, list) or not all(isinstance(p, str) for p in trunk_ports):
        return jsonify({"error": "trunk_ports must be a list of strings."}), 400

    access_ports = [p.strip() for p in access_ports if p.strip()]
    trunk_ports = [p.strip() for p in trunk_ports if p.strip()]

    if collection_method == "ssh" and (not host or not username or not password):
        return jsonify({
            "error": "host, username, and password are required when collection_method is 'ssh'."
        }), 400

    config_path = f"data/configurations/{name}.txt"

    with DEVICES_FILE_LOCK:
        yaml = _ryaml()

        with DEVICES_YAML_PATH.open("r", encoding="utf-8") as f:
            devices_doc = yaml.load(f)

        existing_names = {
            entry["name"].lower() for entry in devices_doc["devices"]
        }
        if name.lower() in existing_names:
            return jsonify({
                "error": f"A device named '{name}' already exists."
            }), 400

        new_entry = CommentedMap()
        new_entry["name"] = name
        new_entry["type"] = "cisco_ios"
        new_entry["collection_method"] = collection_method
        new_entry["host"] = host
        new_entry["username"] = username
        new_entry["password"] = password
        new_entry["config"] = config_path

        devices_list = devices_doc["devices"]
        devices_list.append(new_entry)
        devices_list.yaml_set_comment_before_after_key(
            len(devices_list) - 1, before="\n"
        )

        with DEVICES_YAML_PATH.open("w", encoding="utf-8") as f:
            yaml.dump(devices_doc, f)

        if access_ports or trunk_ports:
            with BASELINE_YAML_PATH.open("r", encoding="utf-8") as f:
                baseline_doc = yaml.load(f)

            switching = baseline_doc["baseline"]["switching"]

            if access_ports:
                if switching.get("access_ports") is None:
                    switching["access_ports"] = CommentedMap()
                switching["access_ports"][name] = access_ports

            if trunk_ports:
                if switching.get("trunk_ports") is None:
                    switching["trunk_ports"] = CommentedMap()
                switching["trunk_ports"][name] = trunk_ports

            # Re-assert the blank-line separators between switching's
            # sub-blocks: inserting a new key into access_ports/
            # trunk_ports can otherwise disturb the trailing blank
            # line that used to separate them from their next sibling
            # key (ruamel ties that whitespace to the token stream,
            # not to the block itself).
            if "trunk_ports" in switching:
                switching.yaml_set_comment_before_after_key("trunk_ports", before="\n")
            baseline_doc["baseline"].yaml_set_comment_before_after_key(
                "management", before="\n"
            )

            with BASELINE_YAML_PATH.open("w", encoding="utf-8") as f:
                yaml.dump(baseline_doc, f)

    warning = None
    if collection_method == "file" and not Path(config_path).exists():
        warning = (
            "config file does not exist yet — this device cannot be "
            f"scanned until {config_path} is created."
        )

    response = {"devices": _build_device_states()}
    if warning:
        response["warning"] = warning

    return jsonify(response)


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
