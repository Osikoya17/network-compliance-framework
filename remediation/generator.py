from pathlib import Path

from jinja2 import Environment, FileSystemLoader


class RemediationGenerator:

    def __init__(self, template_directory="templates"):

        self.template_directory = Path(
            template_directory
        )

        self.environment = Environment(
            loader=FileSystemLoader(
                self.template_directory
            ),
            trim_blocks=True,
            lstrip_blocks=True
        )

    def generate(self, template_name, variables=None):

        if variables is None:
            variables = {}

        template = self.environment.get_template(
            template_name
        )

        return template.render(**variables)

    def save(self, configuration, output_path):

        output_path = Path(output_path)

        output_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        output_path.write_text(
            configuration,
            encoding="utf-8"
        )

        print(
            f"Remediation saved to "
            f"{output_path}"
        )

    def generate_for_violation(self, result):

        rule = result.rule
        interface = result.interface

        if rule == "Telnet disabled":
            return self.generate(
                "disable_telnet.j2"
            )

        if rule == "Port security enabled":
            return self.generate(
                "enable_port_security.j2",
                {
                    "interface": interface,
                    "maximum_mac": 1
                }
            )

        if rule == "Unused ports shutdown":
            return self.generate(
                "shutdown_unused_port.j2",
                {
                    "interface": interface
                }
            )

        if rule == "VLAN 1 not used on user port":
            return self.generate(
                "remove_vlan1.j2",
                {
                    "interface": interface
                }
            )

        if rule == "NTP configured":
            return self.generate(
                "restore_ntp.j2",
                {
                    "ntp_server": "10.0.0.2"
                }
            )

        return None