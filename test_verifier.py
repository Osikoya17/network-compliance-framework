import yaml

from remediation.verifier import (
    RemediationVerifier
)


def load_baseline():

    with open(
        "config/baseline.yaml",
        "r",
        encoding="utf-8"
    ) as file:

        return yaml.safe_load(file)["baseline"]


def main():

    baseline = load_baseline()

    verifier = RemediationVerifier(
        baseline
    )

    verifier.verify(
        device_name="SW1-ACCESS",
        config_path=(
            "data/test_configurations/"
            "SW1-ACCESS.txt"
        )
    )


if __name__ == "__main__":
    main()