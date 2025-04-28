import psutil
import socket

def get_interfaces():
    """Retrieves and returns a dictionary of network interfaces and their IPv4 addresses."""
    interfaces = psutil.net_if_addrs()
    interface_details = {}
    for name, addrs in interfaces.items():
        for addr in addrs:
            # Check for IPv4 addresses
            if addr.family == socket.AF_INET:
                interface_details[name] = addr.address
                break # Get the first IPv4 address found for the interface
    return interface_details

def choose_interface(interface_details):
    """Displays interfaces and prompts the user to choose one."""
    if not interface_details:
        print("No network interfaces with IPv4 found.")
        return None

    print("Available Network Interfaces:")
    interface_list = list(interface_details.items())
    for i, (name, ip) in enumerate(interface_list):
        print(f"[{i}] {name}: {ip}")

    while True:
        try:
            choice = int(input("Select the interface number to use: "))
            if 0 <= choice < len(interface_list):
                selected_interface_name = interface_list[choice][0]
                print(f"\nYou selected: {selected_interface_name} ({interface_details[selected_interface_name]})")
                return selected_interface_name
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nSelection cancelled.")
            return None

if __name__ == "__main__":
    available_interfaces = get_interfaces()
    selected_interface = choose_interface(available_interfaces)

    if selected_interface:
        print(f"\nProceeding with interface: {selected_interface}")
        # Future steps will use the 'selected_interface'
    else:
        print("\nNo interface selected. Exiting.")