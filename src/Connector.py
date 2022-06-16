from ctypes import sizeof
from scapy.all import raw
from isakmp import *
from scapy.layers.l2 import Ether
import socket

class Connector:
    def __init__(self, dest_ip, dest_port, local_port):
        self._dest = (dest_ip, 500)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_address = ("10.0.2.2", 500)
        self._sock.bind(server_address)

    def __del__(self):
        self._sock.close()

    # takes a Scapy packet as data
    # TODO: error handling
    def send_recv_data(self, data):
        self._sock.sendto(self.scapy_isakmp_to_bytes(data), self._dest)
        data, address = self._sock.recvfrom(1200)
        print(f"Received {len(data)} bytes from {address}")
        return self.bytes_to_scapy_isakmp(data)

    def send_recv_raw_data(self, data):
        self._sock.sendto(self.scapy_isakmp_to_bytes(data), self._dest)
        data, address = self._sock.recvfrom(1200)
        print(f"Received {len(data)} bytes from {address}")
        return data

    def scapy_isakmp_to_bytes(self, p : Packet):  
        return raw(p)

    def bytes_to_scapy_isakmp(self, b):
        return Ether()/IP()/UDP()/ISAKMP(bytes(b))