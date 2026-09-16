import yaml

from webreport.report_generator import generate_report
from parser.config_parser import CiscoConfigParser, load_config
from compliance.engine import ComplianceEngine


def load_baseline():
    with open(
        "config/baseline.yaml",
        "r",
        encoding="utf-8"
    ) as file:
        return yaml.safe_load(file)["baseline"]


def load_devices():

    with open(
        "config/devices.yaml",
        "r",
        encoding="utf-8"
    ) as file:
        return yaml.safe_load(file)["devices"]


def scan_device(device, baseline):

    name = device["name"]
    config_file = device["config"]

    print("\n" + "=" * 60)
    print(f"SCANNING DEVICE: {name}")
    print("=" * 60)

    config_text = load_config(config_file)

    parser = CiscoConfigParser(config_text)

    parsed_config = parser.get_full_report()

    engine = ComplianceEngine(
        parsed_config=parsed_config,
        baseline=baseline
    )

    results = engine.run_all_checks(
        expected_hostname=name,
        device_name=name
    )

    for result in results:

        symbol = (
            "✓"
            if result.status == "PASS"
            else "✗"
        )

        interface = ""

        if result.interface:
            interface = f" [{result.interface}]"

        print(
            f"{symbol} "
            f"{result.rule}"
            f"{interface}: "
            f"{result.status}"
        )

        print(
            f"    Expected: {result.expected}"
        )

        print(
            f"    Actual:   {result.actual}"
        )

        print(
            f"    Severity: {result.severity}"
        )

    score = engine.get_score()

    print("\n" + "-" * 60)
    print(f"{name} COMPLIANCE SCORE: {score}%")
    print("-" * 60)

    return {
        "device": name,
        "score": score,
        "results": results
    }


def main():

    baseline = load_baseline()
    devices = load_devices()

    all_results = []

    for device in devices:

        result = scan_device(
            device,
            baseline
        )

        all_results.append(result)

    print("\n")
    print("=" * 60)
    print("OVERALL NETWORK COMPLIANCE REPORT")
    print("=" * 60)

    total_score = 0

    for result in all_results:

        print(
            f"{result['device']}: "
            f"{result['score']}%"
        )

        total_score += result["score"]

    if all_results:

        overall_score = round(
            total_score / len(all_results),
            2
        )

    else:

        overall_score = 0

    print("-" * 60)

    print(
        f"OVERALL NETWORK SCORE: "
        f"{overall_score}%"
    )

    print("=" * 60)
    generate_report(
        all_results,
        collection_summary="live SSH (Netmiko) for R1-CORE, SW1-ACCESS, SW2-ACCESS; file-based for R2-ISP",
    )


if __name__ == "__main__":
    main()