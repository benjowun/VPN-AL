from scapy.all import raw
from isakmp import *
from scapy.layers.l2 import Ether
import socket
import time
import utils
if utils.libre:
    from paramiko import SSHClient, AutoAddPolicy

# Too low timeouts might fail, 0.5 is already pushing it, to be certain, increase by a bit
class Connector:
    def __init__(self, dest_ip, dest_port, local_port, timeout=0.5):
        self._dest = (dest_ip, 500)

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(timeout)
        server_address = ("10.0.2.2", 500)
        self._sock.bind(server_address)

        if utils.libre:
            self._ssh = SSHClient()
            self._ssh.set_missing_host_key_policy(AutoAddPolicy())
            self._ssh.load_system_host_keys()
            self._ssh.connect("10.0.3.1", username="benjamin", password="nimajneb")

    def __del__(self, libre = utils.libre):
        self._sock.close()
        if libre:
            self._ssh.close()

    # takes a Scapy packet as data
    # TODO: error handling
    def send_recv_data(self, data):
        try:
            self._sock.sendto(self.scapy_isakmp_to_bytes(data), self._dest)
            data, address = self._sock.recvfrom(1200)
            print(f"   Received {len(data)} bytes from {address}")
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

    def ssh_reset(self):
        if utils.libre:
            print("connecting ssh...")
            command = 'sudo ipsec auto --down vm1tovm2'
            stdin, stdout, stderr = self._ssh.exec_command(command, get_pty=True)
            stdin.write('nimajneb\n')
            stdin.flush()
            stdout.channel.recv_exit_status() # block till exectued
            output = stdout.read().decode()
            print(f"     SSH: {output}")
            time.sleep(2) # wait for server to restart
        else:
            print("ERROR: ENABLE LIBRESWAN SUPPORT IN UTILS!")
            exit(-1)