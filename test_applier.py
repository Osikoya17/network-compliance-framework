from remediation.applier import RemediationApplier


def main():

    config_path = (
    "data/test_configurations/SW1-ACCESS.txt"
)

    remediation = """interface FastEthernet0/10
 shutdown
exit"""

    applier = RemediationApplier(
        config_path
    )

    applier.apply(remediation)

    print(
        "\nRemediation application test "
        "completed successfully."
    )


if __name__ == "__main__":
    main()