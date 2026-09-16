class ComplianceResult:
    def __init__(
        self,
        rule,
        status,
        expected,
        actual,
        severity="HIGH",
        interface=None,
    ):
        self.rule = rule
        self.status = status
        self.expected = expected
        self.actual = actual
        self.severity = severity
        self.interface = interface

    def to_dict(self):
        return {
            "rule": self.rule,
            "status": self.status,
            "expected": self.expected,
            "actual": self.actual,
            "severity": self.severity,
            "interface": self.interface,
        }


class ComplianceEngine:

    def __init__(self, parsed_config, baseline):
        self.config = parsed_config
        self.baseline = baseline
        self.results = []

    # =========================================================
    # BASIC SECURITY RULES
    # =========================================================

    def check_hostname(self, expected_hostname):

        actual = self.config.get("hostname")

        self.results.append(
            ComplianceResult(
                rule="Hostname",
                status="PASS" if actual == expected_hostname else "FAIL",
                expected=expected_hostname,
                actual=actual,
                severity="HIGH",
            )
        )

    def check_ssh(self):

        expected = self.baseline["security"]["ssh_required"]
        actual = self.config.get("ssh_enabled", False)

        self.results.append(
            ComplianceResult(
                rule="SSH enabled",
                status="PASS" if actual == expected else "FAIL",
                expected=expected,
                actual=actual,
                severity="HIGH",
            )
        )

    def check_telnet(self):

        expected = self.baseline["security"]["telnet_allowed"]
        actual = self.config.get("telnet_allowed", True)

        self.results.append(
            ComplianceResult(
                rule="Telnet disabled",
                status="PASS" if actual == expected else "FAIL",
                expected=expected,
                actual=actual,
                severity="CRITICAL",
            )
        )

    def check_password_encryption(self):

        expected = self.baseline["security"]["password_encryption"]
        actual = self.config.get("password_encryption", False)

        self.results.append(
            ComplianceResult(
                rule="Password encryption",
                status="PASS" if actual == expected else "FAIL",
                expected=expected,
                actual=actual,
                severity="HIGH",
            )
        )

    def check_local_admin(self):

        expected = self.baseline["security"]["local_admin_required"]
        actual = self.config.get("local_admin", False)

        self.results.append(
            ComplianceResult(
                rule="Privileged local administrator",
                status="PASS" if actual == expected else "FAIL",
                expected=expected,
                actual=actual,
                severity="HIGH",
            )
        )

    def check_ntp(self):

        expected = self.baseline["management"]["ntp_required"]
        actual = self.config.get("ntp_configured", False)

        self.results.append(
            ComplianceResult(
                rule="NTP configured",
                status="PASS" if actual == expected else "FAIL",
                expected=expected,
                actual=actual,
                severity="MEDIUM",
            )
        )

    def check_logging(self):

        expected = self.baseline["management"]["logging_required"]
        actual = self.config.get("logging_configured", False)

        self.results.append(
            ComplianceResult(
                rule="Logging configured",
                status="PASS" if actual == expected else "FAIL",
                expected=expected,
                actual=actual,
                severity="MEDIUM",
            )
        )

    # =========================================================
    # INTERFACE RULES
    # =========================================================

    def check_vlan1_user_ports(self):

        interfaces = self.config.get("interfaces", {})

        for name, interface in interfaces.items():

            if interface["mode"] != "access":
                continue

            vlan = interface["access_vlan"]

            if vlan == 1:

                self.results.append(
                    ComplianceResult(
                        rule="VLAN 1 not used on user port",
                        status="FAIL",
                        expected="VLAN other than 1",
                        actual=f"VLAN {vlan}",
                        severity="HIGH",
                        interface=name,
                    )
                )

            else:

                self.results.append(
                    ComplianceResult(
                        rule="VLAN 1 not used on user port",
                        status="PASS",
                        expected="VLAN other than 1",
                        actual=f"VLAN {vlan}",
                        severity="HIGH",
                        interface=name,
                    )
                )

    # ---------------------------------------------------------
    # PORT SECURITY
    # ---------------------------------------------------------

    def check_port_security(self):

        interfaces = self.config.get("interfaces", {})

        for name, interface in interfaces.items():

            if interface["mode"] != "access":
                continue

            port_security = interface["port_security"]

            if port_security:

                self.results.append(
                    ComplianceResult(
                        rule="Port security enabled",
                        status="PASS",
                        expected=True,
                        actual=True,
                        severity="HIGH",
                        interface=name,
                    )
                )

            else:

                self.results.append(
                    ComplianceResult(
                        rule="Port security enabled",
                        status="FAIL",
                        expected=True,
                        actual=False,
                        severity="HIGH",
                        interface=name,
                    )
                )

    # ---------------------------------------------------------
    # MAXIMUM MAC ADDRESSES
    # ---------------------------------------------------------

    def check_maximum_mac(self):

        interfaces = self.config.get("interfaces", {})

        expected = self.baseline["switching"]["maximum_mac_addresses"]

        for name, interface in interfaces.items():

            if interface["mode"] != "access":
                continue

            actual = interface["maximum_mac"]

            if actual == expected:

                status = "PASS"

            else:

                status = "FAIL"

            self.results.append(
                ComplianceResult(
                    rule="Maximum MAC addresses",
                    status=status,
                    expected=expected,
                    actual=actual,
                    severity="MEDIUM",
                    interface=name,
                )
            )

    # ---------------------------------------------------------
    # UNUSED PORTS
    # ---------------------------------------------------------

    def check_unused_ports(self, device_name):

        interfaces = self.config.get("interfaces", {})

        expected_access_ports = (
            self.baseline["switching"]
            .get("access_ports", {})
            .get(device_name, [])
        )

        for name, interface in interfaces.items():

            # Ignore trunk interfaces
            if interface["mode"] == "trunk":
                continue

            # Ignore interfaces we expect to use
            if name in expected_access_ports:
                continue

            # If an unexpected interface is active,
            # it violates the baseline.

            if not interface["shutdown"]:

                self.results.append(
                    ComplianceResult(
                        rule="Unused ports shutdown",
                        status="FAIL",
                        expected="shutdown",
                        actual="active",
                        severity="HIGH",
                        interface=name,
                    )
                )

            else:

                self.results.append(
                    ComplianceResult(
                        rule="Unused ports shutdown",
                        status="PASS",
                        expected="shutdown",
                        actual="shutdown",
                        severity="HIGH",
                        interface=name,
                    )
                )

    # ---------------------------------------------------------
    # TRUNK NATIVE VLAN
    # ---------------------------------------------------------

    def check_native_vlan(self):

        interfaces = self.config.get("interfaces", {})

        expected = self.baseline["switching"]["native_vlan"]

        for name, interface in interfaces.items():

            if interface["mode"] != "trunk":
                continue

            actual = interface["native_vlan"]

            self.results.append(
                ComplianceResult(
                    rule="Trunk native VLAN",
                    status="PASS" if actual == expected else "FAIL",
                    expected=expected,
                    actual=actual,
                    severity="HIGH",
                    interface=name,
                )
            )

    # ---------------------------------------------------------
    # APPROVED TRUNK VLANS
    # ---------------------------------------------------------

    def check_allowed_vlans(self):

        interfaces = self.config.get("interfaces", {})

        approved = set(
            self.baseline["network"]["approved_vlans"]
        )

        for name, interface in interfaces.items():

            if interface["mode"] != "trunk":
                continue

            actual = set(interface["allowed_vlans"])

            unexpected = actual - approved

            if unexpected:

                self.results.append(
                    ComplianceResult(
                        rule="Approved trunk VLANs",
                        status="FAIL",
                        expected=sorted(approved),
                        actual=sorted(actual),
                        severity="HIGH",
                        interface=name,
                    )
                )

            else:

                self.results.append(
                    ComplianceResult(
                        rule="Approved trunk VLANs",
                        status="PASS",
                        expected=sorted(approved),
                        actual=sorted(actual),
                        severity="HIGH",
                        interface=name,
                    )
                )

    # =========================================================
    # RUN ALL CHECKS
    # =========================================================

    def run_all_checks(self, expected_hostname, device_name=None):

        self.check_hostname(expected_hostname)
        self.check_ssh()
        self.check_telnet()
        self.check_password_encryption()
        self.check_local_admin()
        self.check_ntp()
        self.check_logging()

        # Interface checks
        self.check_vlan1_user_ports()
        self.check_port_security()
        self.check_maximum_mac()
        self.check_native_vlan()
        self.check_allowed_vlans()

        if device_name:
            self.check_unused_ports(device_name)

        return self.results

    # =========================================================
    # SCORE
    # =========================================================

    def get_score(self):

        if not self.results:
            return 0

        passed = sum(
            1
            for result in self.results
            if result.status == "PASS"
        )

        return round(
            (passed / len(self.results)) * 100,
            2
        )