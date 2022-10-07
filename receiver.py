from scapy.all import sniff

def display_packet(x):
    #x.sprintf(("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
    x.show()

if __name__ == "__main__":
    sniff(filter="", prn=display_packet)
