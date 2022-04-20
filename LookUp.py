import csv
import scapy.error
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
import subprocess
from termcolor import colored
from os import name

if name == "posix":
    euid = os.geteuid()
    if euid != 0:
        print(colored("Run this script as root or sudo or administrator\n", 'red', attrs=["bold"]))
        exit()


def os_check():
    if name == "nt":
        subprocess.call('cls', shell=True)
    else:
        subprocess.call('clear', shell=True)
os_check()


print(colored(""" _                _    _   _       
| |    ___   ___ | | _| | | |_ __  
| |   / _ \ / _ \| |/ / | | | '_ \ 
| |__| (_) | (_) |   <| |_| | |_) |
|_____\___/ \___/|_|\_\\___/| .__/ 
                            |_|    
""", 'green', attrs=['bold']))
print(colored("""0. Exit\n1. Host Discovery\n2. Port Scanner.\n3. Packet Sniffer""", 'red', attrs=['bold']))

print(colored("Enter the number: ", 'blue', attrs=["bold"]), end="")
number = input()

device = []
vendors = {}


def discovery(network):
    arp_frame = ARP(pdst=network)
    ether_frame = Ether(dst='ff:ff:ff:ff:ff:ff')
    frame = ether_frame / arp_frame  # combining frame
    response = srp(frame, timeout=1, verbose=False)[0]

    for i in range(len(response)):
        result = {"ip": response[i][1].psrc,
                  "mac": response[i][1].hwsrc}
        device.append(result)
    device.append({"ip": get_if_addr(conf.iface), "mac": get_if_hwaddr(conf.iface)})


def vendor():
    with open('vendor.csv', encoding="utf-8") as f:
        read = csv.DictReader(f)
        for row in read:
            vendors[row['oui']] = row['companyName']
        for i in range(len(device)):
            if device[i]['mac'][:8].upper() in vendors.keys():
                device[i]['vendor'] = vendors.get(device[i]['mac'][:8].upper())
            else:
                device[i]['vendor'] = "Unknown"


def display():
    print(colored(f"Total number of device: {len(device)}", 'green', attrs=["bold"]))
    print("IP address\tMAC address\t\tVendor")
    for i in device:
        print(f"{i['ip']}\t{i['mac']}\t{i['vendor']}")


def port_scanner(target, start_port, end_port):
    ports = {}
    for port in range(start_port, end_port + 1):
        pac = IP(dst=target) / TCP(dport=port, flags='S')

        response = sr1(pac, timeout=0.2, verbose=False)
        if str(type(response)) == "<class 'NoneType'>":
            pass
        elif response.sprintf("%TCP.flags%") == "SA":
            ports[port] = response.sprintf("%TCP.sport%")

    print("Port\tService")
    for i in ports:
        print(f"{i}\t{ports.get(i).upper()}")
    print(colored("Scanning Finished", 'red', attrs=['bold']))


def sniffer(filters='tcp', interface=get_working_if()):
    with open(file, 'w') as f:
        pass
    sniffed = sniff(iface=interface, filter=filters, count=count)
    wrpcap(file, sniffed)


def summary():
    counts = {}
    packets = rdpcap(file)
    for pac in packets:
        if pac.sprintf("%IP.src% and %IP.dst%") in counts:
            counts[pac.sprintf("%IP.src% and %IP.dst%")] += 1
        else:
            counts[pac.sprintf("%IP.src% and %IP.dst%")] = 1
    for counted in counts:
        print(f"{counted} exchange packet {counts[counted]} times.")

try:
    if number == "1":
        os_check()
        print(colored(""" _               _   ____  _                             
| |__   ___  ___| |_|  _ \(_)___  ___ _____   _____ _ __ 
| '_ \ / _ \/ __| __| | | | / __|/ __/ _ \ \ / / _ \ '__|
| | | | (_) \__ \ |_| |_| | \__ \ (_| (_) \ V /  __/ |   
|_| |_|\___/|___/\__|____/|_|___/\___\___/ \_/ \___|_|   """, 'red', attrs=['bold']))
        print(colored("Enter 'ctrl + c' to exit ", 'green', attrs=["bold"]))
        print(colored("Enter the network to discover host: ", 'yellow', attrs=["bold"]), end="")
        net = input()
        print(colored(f"{'-' * 30}SCANNING{'-' * 30}", 'blue', attrs=['bold']))
        discovery(net)
        vendor()
        display()
        print(colored(f"{'-' * 30}FINISHED{'-' * 30}", 'blue', attrs=['bold']))

    elif number == "2":
        os_check()
        print(colored("""                      __  _____                                 
    ____  ____  _____/ /_/ ___/_________ _____  ____  ___  _____
   / __ \/ __ \/ ___/ __/\__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
  / /_/ / /_/ / /  / /_ ___/ / /__/ /_/ / / / / / / /  __/ /    
 / .___/\____/_/   \__//____/\___/\__,_/_/ /_/_/ /_/\___/_/     
/_/                                                             
""", 'red', attrs=['bold']))
        print(colored("Enter 'ctrl + c' to exit ", 'green', attrs=["bold"]))
        print(colored("Enter the target to find open port: ", 'cyan', attrs=["bold"]), end="")
        tar = input()
        print(colored("Enter the starting port: ", 'cyan', attrs=["bold"]), end="")
        start = int(input())
        print(colored("Enter the ending port: ", 'cyan', attrs=["bold"]), end="")
        end = int(input())
        print(colored("Scanning may take some time...........\n", 'yellow', attrs=["bold"]), end="")

        port_scanner(tar, start, end)

    elif number == '3':
        os_check()
        print(colored("""   _____       _ ________         
  / ___/____  (_) __/ __/__  _____
  \__ \/ __ \/ / /_/ /_/ _ \/ ___/
 ___/ / / / / / __/ __/  __/ /    
/____/_/ /_/_/_/ /_/  \___/_/     
                                 """, 'red', attrs=['bold']))
        print(colored("Enter 'ctrl + c' to exit ", 'green', attrs=["bold"]))
        print(colored("Enter the number of packet you want to capture: ", 'cyan', attrs=['bold']), end="")
        count = int(input())
        print(colored("Enter the file name (with extension .pcap): ", 'cyan', attrs=["bold"]), end="")
        file = input()
        print(
            colored("""Enter the type of filer you want to sniff.\nExample: tcp, icmp, port 80 (tcp is default): """,
                    'cyan', attrs=['bold']),
            end="")
        filtered = input()
        print(colored("********  You have following interface  *********", 'blue', attrs=["bold"]))
        for index, iface in enumerate(get_if_list()):
            print(f"{index}. {iface}")
        print(
            colored("Choose one of the active interface name (leave blank if you don't know):", 'blue', attrs=["bold"]),
            end="")
        interface = input()
        print(colored(f"-----------------------Sniffing started----------------------", 'green', attrs=["bold"]))
        sniffer(filtered)

        print(colored(f"\n-----------------------Sniffed-------------------------", 'red', attrs=["bold"]))
        print(colored(f"{file} is saved into your current directory.\n", 'yellow', attrs=["bold"]))
        print()
        print(colored("\nDo you want to show summary of the sniffed packet?\nEnter yes or no: ", 'cyan', attrs=["bold"]),end="")
        yes_or_no = input()
        if yes_or_no.lower() == 'yes' or yes_or_no.lower() == 'y':
            summary()
        elif yes_or_no.lower() == 'no' or yes_or_no.lower() == 'n' or yes_or_no == '':
            print(colored("Exiting.....", 'red', attrs=["bold"]))
            exit()

    elif number == "0":
        print(colored("\nExiting", 'blue', attrs=["bold"]), end="")
        sys.exit()
    else:
        print(colored("\nYou have either entered the wrong number or forget to enter the number", 'green', attrs=["bold"]))
        print(colored("\nExiting", 'green', attrs=["bold"]))


except KeyboardInterrupt:
    print(colored("\nExiting", 'blue', attrs=["bold"]))
    sys.exit()

except socket.gaierror:
    print(colored("\nOps! You forgot to enter network id or target.\nExiting", 'red', attrs=["bold"]))

except ValueError:
    print(colored("\nOps! You forgot to enter the number.\nExiting", 'red', attrs=["bold"]))

except FileNotFoundError:
    print(colored("\nOps! You forgot to give file name.\nExiting", 'red', attrs=["bold"]))

except scapy.error.Scapy_Exception:
    print(colored("\nOps! You entered wrong filtered method. Try some from given examples.\nExiting", 'red', attrs=["bold"]))
