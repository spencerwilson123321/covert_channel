from scapy.all import sniff

def write_info(pkt):
    with open("log.txt", "a") as f:
        f.write(f"{chr(int(pkt.id / 255))}")

if __name__ == "__main__":
    sniff(filter="tcp and src host 192.168.0.12 and not port 22", prn=write_info)