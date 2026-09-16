from pathlib import Path
from netmiko import ConnectHandler


class ConfigurationCollector:

    def __init__(self, device):
        self.device = device

    def collect(self):
        """
        Collect configuration from a network device.

        Packet Tracer:
            Reads the configuration from the configured file.

        Real/virtual Cisco device:
            Uses Netmiko over SSH.
        """

        collection_method = self.device.get(
            "collection_method",
            "file"
        )

        if collection_method == "file":
            return self.collect_from_file()

        if collection_method == "ssh":
            return self.collect_from_ssh()

        raise ValueError(
            f"Unsupported collection method: "
            f"{collection_method}"
        )

    def collect_from_file(self):
        """Collect configuration from a saved Packet Tracer config."""

        config_path = Path(self.device["config"])

        print(
            f"\nReading configuration for "
            f"{self.device['name']}..."
        )

        if not config_path.exists():
            raise FileNotFoundError(
                f"Configuration file not found: "
                f"{config_path}"
            )

        configuration = config_path.read_text(
            encoding="utf-8"
        )

        print("Configuration loaded successfully.")

        return configuration

    def collect_from_ssh(self):
        """Collect configuration using Netmiko SSH."""

        connection_parameters = {
            "device_type": self.device["type"],
            "host": self.device["host"],
            "username": self.device["username"],
            "password": self.device["password"],
        }

        print(
            f"\nConnecting to "
            f"{self.device['name']} "
            f"({self.device['host']})..."
        )

        connection = None

        try:
            connection = ConnectHandler(
                **connection_parameters
            )

            print("SSH connection established.")

            configuration = connection.send_command(
                "show running-config"
            )

            return configuration

        finally:
            if connection:
                connection.disconnect()

                print(
                    f"Disconnected from "
                    f"{self.device['name']}."
                )

    def save_configuration(self, configuration):
        """Save collected configuration."""

        output_path = Path(
            self.device["config"]
        )

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        output_path.write_text(
            configuration,
            encoding="utf-8"
        )

        print(
            f"Configuration saved to "
            f"{output_path}"
        )