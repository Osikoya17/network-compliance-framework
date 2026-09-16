from netmiko import ConnectHandler


class LiveRemediationApplier:
    """
    Applies remediation commands directly to a live device over SSH,
    using the same connection style as the collector. Unlike
    RemediationApplier (which appends text to a file), this makes a
    REAL configuration change to the running device and saves it.

    device: one entry from config/devices.yaml (needs type/host/
    username/password; collection_method is not used here).
    """

    def __init__(self, device):
        self.device = device

    def apply(self, remediation_text):

        commands = [
            line.rstrip()
            for line in remediation_text.strip().splitlines()
            if line.strip()
        ]

        connection_parameters = {
            "device_type": self.device["type"],
            "host": self.device["host"],
            "username": self.device["username"],
            "password": self.device["password"],
        }

        print(
            f"\nConnecting to {self.device['name']} "
            f"({self.device['host']}) to apply remediation..."
        )

        connection = None

        try:
            connection = ConnectHandler(**connection_parameters)

            output = connection.send_config_set(
                commands,
                read_timeout=60
            )

            print(output)

            print("Saving configuration to startup-config...")
            connection.save_config()

            return output

        finally:
            if connection:
                connection.disconnect()
                print(f"Disconnected from {self.device['name']}.")
