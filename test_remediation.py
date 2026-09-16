from remediation.generator import (
    RemediationGenerator
)


def main():

    generator = RemediationGenerator()

    print("\n" + "=" * 60)
    print("JINJA2 REMEDIATION TEST")
    print("=" * 60)

    print("\n1. Disable Telnet")
    print("-" * 60)

    telnet_config = generator.generate(
        "disable_telnet.j2"
    )

    print(telnet_config)

    print("\n2. Enable Port Security")
    print("-" * 60)

    port_security_config = generator.generate(
        "enable_port_security.j2",
        {
            "interface": "FastEthernet0/1",
            "maximum_mac": 1
        }
    )

    print(port_security_config)

    print("\n3. Shutdown Unused Port")
    print("-" * 60)

    shutdown_config = generator.generate(
        "shutdown_unused_port.j2",
        {
            "interface": "FastEthernet0/10"
        }
    )

    print(shutdown_config)

    print("\n4. Restore NTP")
    print("-" * 60)

    ntp_config = generator.generate(
        "restore_ntp.j2",
        {
            "ntp_server": "10.0.0.2"
        }
    )

    print(ntp_config)

    print("\n" + "=" * 60)
    print("REMEDIATION GENERATION SUCCESSFUL")
    print("=" * 60)


if __name__ == "__main__":
    main()