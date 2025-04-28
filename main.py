import psutil
import socket
import ipaddress # Added for network calculation
import sys

# Attempt to import scapy, provide guidance if missing
try:
    from scapy.all import ARP, Ether, srp, conf
    scapy_imported = True
except ImportError:
    scapy_imported = False
    print("Warning: Scapy library not found. Network scanning feature will be disabled.", file=sys.stderr)
    print("Please install it using: pip install scapy", file=sys.stderr)


def get_interfaces():
    """Retrieves and returns a dictionary of network interfaces with their IPv4 address and netmask."""
    interface_details = {}
    try:
        interfaces = psutil.net_if_addrs()
        for name, addrs in interfaces.items():
            for addr in addrs:
                # Check for valid IPv4 addresses with IP and Netmask
                if addr.family == socket.AF_INET and addr.address and addr.netmask:
                    # Basic validation of address format
                    try:
                        ipaddress.ip_address(addr.address)
                        ipaddress.ip_address(addr.netmask) # Technically masks aren't IPs, but this checks format
                        interface_details[name] = {'ip': addr.address, 'netmask': addr.netmask}
                        break # Get the first valid IPv4 address found for the interface
                    except ValueError:
                        continue # Skip malformed address/netmask
    except Exception as e:
        print(f"Error retrieving interface details: {e}", file=sys.stderr)
    return interface_details

def choose_interface(interface_details):
    """Displays interfaces and prompts the user to choose one."""
    if not interface_details:
        print("No suitable network interfaces with IPv4 found.")
        return None, None

    print("\nAvailable Network Interfaces:")
    interface_list = list(interface_details.keys())
    for i, name in enumerate(interface_list):
        details = interface_details[name]
        print(f"  [{i}] {name}: IP={details['ip']}, Mask={details['netmask']}")

    while True:
        try:
            choice = int(input("\nSelect the interface number to use: "))
            if 0 <= choice < len(interface_list):
                selected_interface_name = interface_list[choice]
                selected_details = interface_details[selected_interface_name]
                print(f"\nYou selected: {selected_interface_name} (IP: {selected_details['ip']}, Mask: {selected_details['netmask']})")
                return selected_interface_name, selected_details
            else:
                print("Invalid choice. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\nSelection cancelled.")
            return None, None

# --- Network Scanning Function ---
def scan_network(network_cidr, interface_name):
    """Performs an ARP scan on the network to discover devices."""
    if not scapy_imported:
        print("Scapy is not available. Cannot perform network scan.", file=sys.stderr)
        return []

    print(f"\nScanning network {network_cidr} on interface {interface_name}...")
    clients = []
    try:
        # Ensure the correct interface is used by scapy
        # Note: Interface names might differ slightly between psutil and scapy on Windows
        # If scan fails, might need to adjust interface name format or selection
        conf.iface = interface_name

        # Create ARP request packet
        arp_request = ARP(pdst=network_cidr)
        # Create Ethernet frame
        # ff:ff:ff:ff:ff:ff is the broadcast MAC address
        broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine frame and request
        arp_request_broadcast = broadcast_frame / arp_request

        # Send packets and capture responses
        # srp() sends and receives packets at layer 2
        # timeout=1 : wait 1 second for responses
        # verbose=False : suppress scapy's default output
        answered_list = srp(arp_request_broadcast, timeout=1, iface=interface_name, verbose=False)[0]

        # Process responses
        for sent, received in answered_list:
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        print(f"Scan complete. Found {len(clients)} device(s).")

    except OSError as e:
        # Common error on Windows if Npcap/WinPcap is not installed or running
        # Or if the script lacks administrator privileges
        if "Npcap" in str(e) or "WinPcap" in str(e):
             print(f"\nError: Scapy dependency Npcap/WinPcap might be missing or not running.", file=sys.stderr)
             print("Please install Npcap (recommended) from https://npcap.com/#download", file=sys.stderr)
             print("Make sure to check the 'WinPcap API-compatible Mode' during installation.", file=sys.stderr)
        elif "privileges" in str(e) or "permitted" in str(e):
            print("\nError: Insufficient privileges. Please run this script as an administrator.", file=sys.stderr)
        else:
            print(f"\nError during scan (Network/Permissions related): {e}", file=sys.stderr)
    except Exception as e:
        print(f"\nAn unexpected error occurred during scanning: {e}", file=sys.stderr)

    return clients

# --- Main Execution Block ---
if __name__ == "__main__":
    available_interfaces = get_interfaces()
    selected_interface_name, selected_interface_details = choose_interface(available_interfaces)

    if selected_interface_name and selected_interface_details:
        print(f"\nProceeding with interface: {selected_interface_name}")

        # Calculate network range (CIDR notation)
        network_cidr = None
        try:
            ip_addr = selected_interface_details.get('ip')
            netmask = selected_interface_details.get('netmask')
            if ip_addr and netmask:
                host_ip = ipaddress.ip_interface(f"{ip_addr}/{netmask}")
                network_cidr = str(host_ip.network) # Get CIDR string like '192.168.1.0/24'
                print(f"Target network: {network_cidr}")
            else:
                 print("Error: Could not retrieve valid IP/Netmask for the selected interface.", file=sys.stderr)

        except ValueError as e:
            print(f"Error calculating network range (invalid IP/Mask?): {e}", file=sys.stderr)
        except Exception as e:
             print(f"An unexpected error occurred calculating network: {e}", file=sys.stderr)

        # Perform the scan only if network calculation was successful
        if network_cidr and scapy_imported:
            # IMPORTANT: Run this script with administrator privileges for scapy
            print("\nAttempting network scan (requires Npcap/WinPcap and administrator privileges)...")
            discovered_devices = scan_network(network_cidr, selected_interface_name)

            if discovered_devices:
                print("\n--- Discovered Devices ---")
                for device in discovered_devices:
                    print(f"  IP: {device['ip']:<15} MAC: {device['mac']}")
                print("--------------------------")
            else:
                # Message already printed in scan_network on error or if none found
                pass # Avoid printing "No devices found" if an error message was already shown

    else:
        print("\nNo interface selected or error retrieving details. Exiting.")
