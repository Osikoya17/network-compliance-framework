import yaml

from collectors.configuration_collector import (
    ConfigurationCollector
)


def main():

    with open(
        "config/devices.yaml",
        "r",
        encoding="utf-8"
    ) as file:

        devices = yaml.safe_load(file)["devices"]

    print("\n" + "=" * 60)
    print("AUTOMATED CONFIGURATION COLLECTION")
    print("=" * 60)

    successful = 0
    failed = 0

    for device in devices:

        try:
            collector = ConfigurationCollector(device)

            configuration = collector.collect()

            collector.save_configuration(configuration)

            successful += 1

        except Exception as error:

            failed += 1

            print(
                f"\nCollection failed for "
                f"{device['name']}: {error}"
            )

    print("\n" + "=" * 60)
    print("COLLECTION SUMMARY")
    print("=" * 60)

    print(f"Successful: {successful}")
    print(f"Failed:     {failed}")
    print("=" * 60)


if __name__ == "__main__":
    main()