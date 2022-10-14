from scapy.all import raw
from isakmp import *
from scapy.layers.l2 import Ether
import socket

# Too low timeouts might fail, 0.5 is already pushing it, to be certain, increase by a bit
class Connector:
    def __init__(self, dest_ip, dest_port, local_port, timeout=0.5):
        self._dest = (dest_ip, 500)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(timeout)
        server_address = ("10.0.2.2", 500)
        self._sock.bind(server_address)

    def __del__(self):
        self._sock.close()

    # takes a Scapy packet as data
    # TODO: error handling
    def send_recv_data(self, data):
        try:
            self._sock.sendto(self.scapy_isakmp_to_bytes(data), self._dest)
            data, address = self._sock.recvfrom(1200)
            print(f"Received {len(data)} bytes from {address}")
            return self.bytes_to_scapy_isakmp(data)
        except:
            return None



    def send_recv_raw_data(self, data):
        self._sock.sendto(self.scapy_isakmp_to_bytes(data), self._dest)
        data, address = self._sock.recvfrom(1200)
        #print(f"Received {len(data)} bytes from {address}")
        return data

    def scapy_isakmp_to_bytes(self, p : Packet):  
        return raw(p)

    def bytes_to_scapy_isakmp(self, b):
        return Ether()/IP()/UDP()/ISAKMP(bytes(b))

    def recv_data(self):
        try:
            data, address = self._sock.recvfrom(1200)
            #print(f"Received {len(data)} bytes from {address}")
            return self.bytes_to_scapy_isakmp(data)
        except:
            return None

    def send_data(self, data):
        self._sock.sendto(self.scapy_isakmp_to_bytes(data), self._dest)