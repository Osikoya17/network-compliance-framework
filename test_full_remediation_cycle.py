import shutil
import yaml

from pathlib import Path

from parser.config_parser import CiscoConfigParser, load_config
from compliance.engine import ComplianceEngine
from remediation.generator import RemediationGenerator
from remediation.applier import RemediationApplier
from remediation.verifier import RemediationVerifier


DEVICE_NAME = "SW1-ACCESS"
LIVE_CONFIG = Path("data/configurations/SW1-ACCESS.txt")
TEST_CONFIG = Path("data/test_configurations/SW1-ACCESS.txt")


def load_baseline():
    with open("config/baseline.yaml", "r", encoding="utf-8") as file:
        return yaml.safe_load(file)["baseline"]


def scan(config_path, baseline):
    config_text = load_config(config_path)
    parser = CiscoConfigParser(config_text)
    parsed_config = parser.get_full_report()

    engine = ComplianceEngine(
        parsed_config=parsed_config,
        baseline=baseline
    )

    results = engine.run_all_checks(
        expected_hostname=DEVICE_NAME,
        device_name=DEVICE_NAME
    )

    return results, engine.get_score()


def main():

    baseline = load_baseline()

    print("\n" + "=" * 60)
    print("STAGE 10 — FULL REMEDIATION CYCLE")
    print(f"Device: {DEVICE_NAME}")
    print("=" * 60)

    # Always start from a fresh copy of the real, live-collected
    # configuration. Never touch the original or the live device.
    TEST_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(LIVE_CONFIG, TEST_CONFIG)
    print(f"\nFresh test copy created: {TEST_CONFIG}")

    before_results, before_score = scan(TEST_CONFIG, baseline)

    print(f"\nBEFORE remediation — {DEVICE_NAME} score: {before_score}%")

    violations = [r for r in before_results if r.status == "FAIL"]

    print(f"{len(violations)} violation(s) found:")
    for v in violations:
        interface = f" [{v.interface}]" if v.interface else ""
        print(f"  ✗ {v.rule}{interface}")

    if not violations:
        print("\nNothing to remediate — device is already compliant.")
        return

    generator = RemediationGenerator()
    applier = RemediationApplier(TEST_CONFIG)

    print("\nApplying remediation:")

    for v in violations:
        remediation = generator.generate_for_violation(v)

        interface = f" [{v.interface}]" if v.interface else ""

        if remediation is None:
            print(f"  (no template for '{v.rule}'{interface} — skipped)")
            continue

        applier.apply(remediation)
        print(f"  ✓ remediated: {v.rule}{interface}")

    verifier = RemediationVerifier(baseline)
    after_results = verifier.verify(
        device_name=DEVICE_NAME,
        config_path=TEST_CONFIG
    )

    after_score = round(
        (sum(1 for r in after_results if r.status == "PASS") / len(after_results)) * 100,
        2
    )

    print("\n" + "-" * 60)
    print(f"BEFORE: {before_score}%   →   AFTER: {after_score}%")
    print("-" * 60)


if __name__ == "__main__":
    main()