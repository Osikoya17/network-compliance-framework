import re
from pathlib import Path


class CiscoConfigParser:
    def __init__(self, config_text: str):
        self.config = config_text

    # ---------------------------------------------------------
    # BASIC DEVICE CONFIGURATION
    # ---------------------------------------------------------

    def get_hostname(self):
        match = re.search(
            r"^hostname\s+(\S+)",
            self.config,
            re.MULTILINE
        )
        return match.group(1) if match else None

    def ssh_enabled(self):
        return "ip ssh version 2" in self.config

    def telnet_allowed(self):
        return bool(
            re.search(
                r"transport input.*telnet",
                self.config,
                re.IGNORECASE
            )
        )

    def password_encryption_enabled(self):
        return "service password-encryption" in self.config

    def local_admin_exists(self):
        return bool(
            re.search(
                r"^username\s+\S+\s+privilege\s+15\s+secret",
                self.config,
                re.MULTILINE
            )
        )

    def ntp_configured(self):
        return bool(
            re.search(
                r"^ntp server\s+\S+",
                self.config,
                re.MULTILINE
            )
        )

    def logging_configured(self):
        return bool(
            re.search(
                r"^logging\s+\S+",
                self.config,
                re.MULTILINE
            )
        )

    # ---------------------------------------------------------
    # VLAN PARSER
    # ---------------------------------------------------------

    def get_vlans(self):
        vlans = {}

        for match in re.finditer(
            r"^vlan\s+(\d+)\n(?: description\s+(.+)\n)?",
            self.config,
            re.MULTILINE
        ):
            vlan_id = int(match.group(1))
            description = match.group(2) or ""

            vlans[vlan_id] = {
                "name": description.strip()
            }

        return vlans

    # ---------------------------------------------------------
    # INTERFACE PARSER
    # ---------------------------------------------------------

    def get_interfaces(self):
        interfaces = {}

        # Find every interface block
        blocks = re.split(
            r"(?=^interface\s+)",
            self.config,
            flags=re.MULTILINE
        )

        for block in blocks:

            if not block.startswith("interface "):
                continue

            lines = block.splitlines()

            interface_name = lines[0].replace(
                "interface ",
                "",
                1
            ).strip()

            interface = {
                "name": interface_name,
                "mode": None,
                "access_vlan": None,
                "native_vlan": None,
                "allowed_vlans": [],
                "shutdown": False,
                "port_security": False,
                "maximum_mac": None,
                "sticky_mac": False,
                "violation_mode": None,
                "routed": False,
            }

            for line in lines[1:]:

                line = line.strip()

                # ---------------------------------------------
                # SWITCHPORT MODE
                # ---------------------------------------------

                if line == "switchport mode access":
                    interface["mode"] = "access"

                elif line == "switchport mode trunk":
                    interface["mode"] = "trunk"

                # ---------------------------------------------
                # ACCESS VLAN
                # ---------------------------------------------

                match = re.match(
                    r"switchport access vlan\s+(\d+)",
                    line
                )

                if match:
                    interface["access_vlan"] = int(
                        match.group(1)
                    )

                # ---------------------------------------------
                # NATIVE VLAN
                # ---------------------------------------------

                match = re.match(
                    r"switchport trunk native vlan\s+(\d+)",
                    line
                )

                if match:
                    interface["native_vlan"] = int(
                        match.group(1)
                    )

                # ---------------------------------------------
                # ALLOWED VLANS
                # ---------------------------------------------

                match = re.match(
                    r"switchport trunk allowed vlan\s+(.+)",
                    line
                )

                if match:

                    vlan_string = match.group(1)

                    allowed = []

                    for vlan in vlan_string.split(","):

                        vlan = vlan.strip()

                        if vlan.isdigit():
                            allowed.append(int(vlan))

                    interface["allowed_vlans"] = allowed

                # ---------------------------------------------
                # SHUTDOWN
                # ---------------------------------------------

                if line == "shutdown":
                    interface["shutdown"] = True

                # ---------------------------------------------
                # ROUTED INTERFACE (carries an IP address)
                # ---------------------------------------------

                if re.match(r"ip address\s+\S+", line):
                    interface["routed"] = True

                # ---------------------------------------------
                # PORT SECURITY
                # ---------------------------------------------

                if line == "switchport port-security":
                    interface["port_security"] = True

                # ---------------------------------------------
                # MAXIMUM MAC
                # ---------------------------------------------

                match = re.match(
                    r"switchport port-security maximum\s+(\d+)",
                    line
                )

                if match:
                    interface["maximum_mac"] = int(
                        match.group(1)
                    )

                # ---------------------------------------------
                # STICKY MAC
                # ---------------------------------------------

                if line == "switchport port-security mac-address sticky":
                    interface["sticky_mac"] = True

                # ---------------------------------------------
                # VIOLATION MODE
                # ---------------------------------------------

                match = re.match(
                    r"switchport port-security violation\s+(\S+)",
                    line
                )

                if match:
                    interface["violation_mode"] = match.group(1)

            interfaces[interface_name] = interface

        return interfaces

    # ---------------------------------------------------------
    # FULL REPORT
    # ---------------------------------------------------------

    def get_full_report(self):

        return {
            "hostname": self.get_hostname(),
            "ssh_enabled": self.ssh_enabled(),
            "telnet_allowed": self.telnet_allowed(),
            "password_encryption": self.password_encryption_enabled(),
            "local_admin": self.local_admin_exists(),
            "ntp_configured": self.ntp_configured(),
            "logging_configured": self.logging_configured(),
            "vlans": self.get_vlans(),
            "interfaces": self.get_interfaces(),
        }


# -------------------------------------------------------------
# CONFIGURATION FILE LOADER
# -------------------------------------------------------------

def load_config(file_path):

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Configuration file not found: {file_path}"
        )

    return path.read_text(
        encoding="utf-8"
    )


# -------------------------------------------------------------
# TEST
# -------------------------------------------------------------

if __name__ == "__main__":

    config_path = "data/configurations/SW2-ACCESS.txt"

    config = load_config(config_path)

    parser = CiscoConfigParser(config)

    report = parser.get_full_report()

    print("\n========================================")
    print("CISCO CONFIGURATION PARSER")
    print("========================================")

    print("\nHostname:")
    print(report["hostname"])

    print("\nInterfaces:")

    for name, interface in report["interfaces"].items():

        print(f"\n{name}")

        print(f"  Mode: {interface['mode']}")
        print(f"  Access VLAN: {interface['access_vlan']}")
        print(f"  Native VLAN: {interface['native_vlan']}")
        print(f"  Allowed VLANs: {interface['allowed_vlans']}")
        print(f"  Shutdown: {interface['shutdown']}")
        print(f"  Port Security: {interface['port_security']}")
        print(f"  Maximum MAC: {interface['maximum_mac']}")
        print(f"  Sticky MAC: {interface['sticky_mac']}")
        print(f"  Violation Mode: {interface['violation_mode']}")