from scapy.all import sniff, packet

def write_info(pkt):
    with open("log.txt", "a") as f:
        f.write(f"{chr(int(pkt.id / 255))}")

if __name__ == "__main__":
    try:
        sniff(filter="tcp and src host 10.0.0.159", prn=write_info)
    except KeyboardInterrupt:
        with open("log.txt", "a") as f:
            f.write("\n")
        print("Data written to ./log.txt")