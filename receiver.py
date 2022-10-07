from scapy.all import sniff, packet

pkt_counter = 0

def write_info(pkt):
    pkt_counter += 1
    with open("log.txt", "a") as f:
        f.write(f"{chr(int(pkt.id / 255))}")

if __name__ == "__main__":
    try:
        sniff(filter="tcp and src host 10.0.0.159", prn=write_info)
    except KeyboardInterrupt:
        print(f"Packets Received: {pkt_counter}")
        print("Data written to ./log.txt")