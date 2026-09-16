from pathlib import Path


class RemediationApplier:

    def __init__(self, config_path):
        self.config_path = Path(config_path)

    def apply(self, remediation):

        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: "
                f"{self.config_path}"
            )

        configuration = self.config_path.read_text(
            encoding="utf-8"
        )

        configuration = configuration.rstrip() + "\n"

        configuration += "\n"
        configuration += "!\n"
        configuration += "! AUTOMATED REMEDIATION\n"
        configuration += "!\n"
        configuration += remediation.rstrip() + "\n"

        self.config_path.write_text(
            configuration,
            encoding="utf-8"
        )

        print(
            f"Remediation applied to "
            f"{self.config_path}"
        )

        return configuration