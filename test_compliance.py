import yaml

from parser.config_parser import CiscoConfigParser, load_config
from compliance.engine import ComplianceEngine


CONFIG_FILE = "data/configurations/SW1-ACCESS.txt"

EXPECTED_HOSTNAME = "SW1-ACCESS"


def main():
    with open("config/baseline.yaml", "r", encoding="utf-8") as file:
        baseline = yaml.safe_load(file)["baseline"]

    config_text = load_config(CONFIG_FILE)

    parser = CiscoConfigParser(config_text)

    parsed_config = parser.get_full_report()

    engine = ComplianceEngine(
        parsed_config=parsed_config,
        baseline=baseline,
    )

    results = engine.run_all_checks(
    expected_hostname=EXPECTED_HOSTNAME,
    device_name=EXPECTED_HOSTNAME
)

    print("\n========================================")
    print("NETWORK COMPLIANCE REPORT")
    print("========================================")

    for result in results:

      symbol = "✓" if result.status == "PASS" else "✗"

      interface = ""

      if result.interface:
          interface = f" [{result.interface}]"

      print(
          f"{symbol} {result.rule}{interface}: "
          f"{result.status}"
      )

      print(f"  Expected: {result.expected}")
      print(f"  Actual:   {result.actual}")
      print(f"  Severity: {result.severity}")
      print()

    print("========================================")
    print(f"Compliance Score: {engine.get_score()}%")
    print("========================================")


if __name__ == "__main__":
    main()