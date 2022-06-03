from scapy.layers.inet import IP, UDP, ICMP
from scapy.layers.isakmp import *
from scapy.utils import randstring
from scapy.all import sr1, send, raw
from scapy.supersocket import StreamSocket
import socket
from Connector import Connector


state = 'DISCONNECTED'
src_ip = "10.0.2.2"  # initiator
dst_ip = "10.0.2.1"  # responder

def scapy_isakmp_to_bytes(p : Packet):  
    return raw(p)

# Scapy to build our packets

p = IP(flags=["DF"], src=src_ip, dst=dst_ip)/UDP(sport=46115, dport=500)/ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

policy_neg = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
policy_neg_vendors = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

# manual test
MESSAGE = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37\x00\x00\x00\x00\x00\x00\x00\x00" \
b"\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x0d\x00\x00\x38" \
b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x2c\x01\x01\x00\x01" \
b"\x00\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x07\x80\x0e\x01\x00" \
b"\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\x00\x01\x80\x0b\x00\x01" \
b"\x80\x0c\x70\x80\x0d\x00\x00\x0c\x09\x00\x26\x89\xdf\xd6\xb7\x12" \
b"\x0d\x00\x00\x14\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc" \
b"\x77\x57\x01\x00\x0d\x00\x00\x18\x40\x48\xb7\xd5\x6e\xbc\xe8\x85" \
b"\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00\x0d\x00\x00\x14" \
b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f" \
b"\x00\x00\x00\x14\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5" \
b"\xec\x42\x7b\x1f"


MESSAGE2 = b"\x02\x95\xcd\x6c\xe4\xb6\xc5\xbd\x00\x00\x00\x00\x00\x00\x00\x00" \
b"\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\xb4\x0d\x00\x00\x38" \
b"\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x2c\x01\x01\x00\x01" \
b"\x00\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x07\x80\x0e\x01\x00" \
b"\x80\x02\x00\x02\x80\x04\x00\x02\x80\x03\x00\x01\x80\x0b\x00\x01" \
b"\x80\x0c\x70\x80\x0d\x00\x00\x0c\x09\x00\x26\x89\xdf\xd6\xb7\x12" \
b"\x0d\x00\x00\x14\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc" \
b"\x77\x57\x01\x00\x0d\x00\x00\x18\x40\x48\xb7\xd5\x6e\xbc\xe8\x85" \
b"\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00\x0d\x00\x00\x14" \
b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f" \
b"\x00\x00\x00\x14\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5" \
b"\xec\x42\x7b\x1f"



msg = scapy_isakmp_to_bytes(policy_neg_vendors)

conn = Connector(dst_ip, 500, 500)
res = conn.send_recv_data(msg)
print(res)
