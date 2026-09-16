from parser.config_parser import CiscoConfigParser, load_config
from compliance.engine import ComplianceEngine


class RemediationVerifier:

    def __init__(self, baseline):
        self.baseline = baseline

    def verify(self, device_name, config_path):

        print("\n" + "=" * 60)
        print("REMEDIATION VERIFICATION")
        print("=" * 60)

        config_text = load_config(config_path)

        parser = CiscoConfigParser(config_text)

        parsed_config = parser.get_full_report()

        engine = ComplianceEngine(
            parsed_config=parsed_config,
            baseline=self.baseline
        )

        results = engine.run_all_checks(
            expected_hostname=device_name,
            device_name=device_name
        )

        score = engine.get_score()

        print(
            f"\n{device_name} "
            f"COMPLIANCE SCORE: {score}%"
        )

        print("\nVerification results:")

        for result in results:

            symbol = (
                "✓"
                if result.status == "PASS"
                else "✗"
            )

            interface = (
                f" [{result.interface}]"
                if result.interface
                else ""
            )

            print(
                f"{symbol} "
                f"{result.rule}"
                f"{interface}: "
                f"{result.status}"
            )

        return results