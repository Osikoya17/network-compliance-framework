"""
Runs the full detect -> remediate -> verify cycle against a LIVE device
over real SSH (Netmiko). This makes actual, saved configuration changes
to the device -- it is not a simulation.

Usage:
    python3 live_remediation_cycle.py <DEVICE-NAME>

Example:
    python3 live_remediation_cycle.py SW1-ACCESS

The device must have collection_method: ssh in config/devices.yaml.
"""
import sys
import yaml

from parser.config_parser import CiscoConfigParser, load_config
from compliance.engine import ComplianceEngine
from collectors.configuration_collector import ConfigurationCollector
from remediation.generator import RemediationGenerator
from remediation.live_applier import LiveRemediationApplier
from webreport.report_generator import generate_remediation_report


def load_baseline():
    with open("config/baseline.yaml", "r", encoding="utf-8") as file:
        return yaml.safe_load(file)["baseline"]


def load_device(device_name):
    with open("config/devices.yaml", "r", encoding="utf-8") as file:
        devices = yaml.safe_load(file)["devices"]

    for device in devices:
        if device["name"] == device_name:
            return device

    raise ValueError(
        f"Device '{device_name}' not found in config/devices.yaml"
    )


def scan_live(device, baseline):

    collector = ConfigurationCollector(device)
    configuration = collector.collect()
    collector.save_configuration(configuration)

    config_text = load_config(device["config"])
    parser = CiscoConfigParser(config_text)
    parsed_config = parser.get_full_report()

    engine = ComplianceEngine(
        parsed_config=parsed_config,
        baseline=baseline
    )

    results = engine.run_all_checks(
        expected_hostname=device["name"],
        device_name=device["name"]
    )

    return results, engine.get_score()


def main():

    if len(sys.argv) < 2:
        print("Usage: python3 live_remediation_cycle.py <DEVICE-NAME>")
        return

    device_name = sys.argv[1]
    baseline = load_baseline()
    device = load_device(device_name)

    if device.get("collection_method") != "ssh":
        print(
            f"'{device_name}' is not set to collection_method: ssh "
            f"in devices.yaml."
        )
        print("Live remediation requires live SSH access. Aborting.")
        return

    print("\n" + "=" * 60)
    print("LIVE REMEDIATION CYCLE")
    print(f"Device: {device_name} ({device['host']})")
    print("=" * 60)
    print(
        "\nThis will make REAL configuration changes to the live "
        "device and save them to its startup-config."
    )

    before_results, before_score = scan_live(device, baseline)

    print(f"\nBEFORE remediation — {device_name} score: {before_score}%")

    violations = [r for r in before_results if r.status == "FAIL"]

    if not violations:
        print("\nNo violations found — device is already compliant.")
        return

    print(f"{len(violations)} violation(s) found:")

    for v in violations:
        interface = f" [{v.interface}]" if v.interface else ""
        print(f"  ✗ {v.rule}{interface}")

    confirm = input(
        f"\nApply live remediation to {device_name} "
        f"({device['host']}) now? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("Aborted. No changes were made.")
        return

    generator = RemediationGenerator()
    applier = LiveRemediationApplier(device)

    print("\nApplying remediation:")

    for v in violations:

        remediation = generator.generate_for_violation(v)

        interface = f" [{v.interface}]" if v.interface else ""

        if remediation is None:
            print(f"  (no template for '{v.rule}'{interface} — skipped)")
            continue

        applier.apply(remediation)
        print(f"  ✓ remediated: {v.rule}{interface}")

    print("\nRe-collecting live configuration to verify...")

    after_results, after_score = scan_live(device, baseline)

    print(f"\nAFTER remediation — {device_name} score: {after_score}%")

    for result in after_results:
        symbol = "✓" if result.status == "PASS" else "✗"
        interface = f" [{result.interface}]" if result.interface else ""
        print(f"{symbol} {result.rule}{interface}: {result.status}")

    print("\n" + "-" * 60)
    print(f"BEFORE: {before_score}%   →   AFTER: {after_score}%")
    print("-" * 60)

    generate_remediation_report(
        device_name=device_name,
        before_results=before_results,
        before_score=before_score,
        after_results=after_results,
        after_score=after_score,
        method="live SSH (Netmiko)",
    )


if __name__ == "__main__":
    main()
