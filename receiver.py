from scapy.all import sniff, packet

def write_info(pkt):
    with open("log.txt", "a") as f:
        f.write(f"{chr(int(pkt.id / 255))}")
        # print(pkt.show())
        # print(pkt)

if __name__ == "__main__":
    sniff(filter="tcp and src host 10.0.0.159", prn=write_info)