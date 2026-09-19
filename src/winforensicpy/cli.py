"""
Command-line interface for WinForensicPy.

Provides an interactive menu for forensic artifact collection.
"""

from winforensicpy.collector_runner import CollectorRunner


def display_menu() -> None:
    """Display the WinForensicPy main menu."""

    print()
    print("=" * 60)
    print("WinForensicPy")
    print("Windows Forensic Artifact Collection Tool")
    print("=" * 60)

    print("1. Collect System Information")
    print("2. Collect Registry Run Keys")
    print("3. Collect USB Storage Devices")
    print("4. Collect Security Event Logs")
    print("5. Collect PowerShell Event Logs")
    print("6. Collect Network Connections")
    print("7. Collect Running Processes")
    print("8. Collect Chrome History")
    print("9. Collect Sysmon Event Logs")
    print("10. Exit")

    print("=" * 60)


def run_cli() -> None:
    """Start the interactive WinForensicPy CLI."""

    runner = CollectorRunner()

    while True:

        display_menu()

        choice = input(
            "Enter your choice: "
        ).strip()

        try:

            if choice == "1":

                result = runner.run_system_info()

                print("\nSystem information collected.")
                print(result)

            elif choice == "2":

                result = runner.run_registry()

                print("\nRegistry Run Keys collected.")
                print(result)

            elif choice == "3":

                result = runner.run_usb()

                print("\nUSB storage information collected.")
                print(result)

            elif choice == "4":

                result = runner.run_security_events(
                    max_records=100
                )

                print("\nSecurity Event Logs collected.")
                print(result)

            elif choice == "5":

                result = runner.run_powershell_events(
                    max_records=100
                )

                print("\nPowerShell Event Logs collected.")
                print(result)

            elif choice == "6":

                result = runner.run_network()

                print("\nNetwork connections collected.")
                print(result)

            elif choice == "7":

                result = runner.run_processes()

                print("\nRunning processes collected.")
                print(result)

            elif choice == "8":

                result = runner.run_chrome_history(
                    max_records=100
                )

                print("\nChrome history collected.")
                print(result)

            elif choice == "9":

                result = runner.run_sysmon_events(
                    max_records=100
                )

                print("\nSysmon Event Logs collected.")
                print(result)

            elif choice == "10":

                print("\nExiting WinForensicPy.")
                break

            else:

                print(
                    "\nInvalid choice. "
                    "Please select an option from 1 to 10."
                )

        except PermissionError as error:

            print("\nPermission Error:")
            print(error)

        except FileNotFoundError as error:

            print("\nArtifact Not Available:")
            print(error)

        except Exception as error:

            print("\nCollection Error:")
            print(error)


if __name__ == "__main__":
    run_cli()