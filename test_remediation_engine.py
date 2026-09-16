from types import SimpleNamespace

from remediation.generator import (
    RemediationGenerator
)


def main():

    generator = RemediationGenerator()

    violations = [

        SimpleNamespace(
            rule="Telnet disabled",
            interface=None
        ),

        SimpleNamespace(
            rule="Port security enabled",
            interface="FastEthernet0/1"
        ),

        SimpleNamespace(
            rule="Unused ports shutdown",
            interface="FastEthernet0/10"
        ),

        SimpleNamespace(
            rule="VLAN 1 not used on user port",
            interface="FastEthernet0/10"
        ),

        SimpleNamespace(
            rule="NTP configured",
            interface=None
        ),
    ]

    print("\n" + "=" * 60)
    print("AUTOMATED REMEDIATION ENGINE TEST")
    print("=" * 60)

    for violation in violations:

        print("\n" + "-" * 60)
        print(f"Violation: {violation.rule}")

        if violation.interface:
            print(
                f"Interface: "
                f"{violation.interface}"
            )

        remediation = (
            generator.generate_for_violation(
                violation
            )
        )

        if remediation:
            print("\nGenerated remediation:")
            print(remediation)

        else:
            print(
                "\nNo remediation template "
                "available."
            )

    print("\n" + "=" * 60)
    print("AUTOMATED REMEDIATION TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
    