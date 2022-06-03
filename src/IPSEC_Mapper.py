# TODO: in here, implement the actual calls to the server, that the high level abstraction maps to
# start with good known basic values and later build up to randomly chosen possible values and finally actual fuzzing

# TODO: decrypt the wireshark ikev1 dumps using key from logs

# Possible states for client: DISCONNECTED --> P1_SA --> P1_DH --> P1_AUTH --> P2_SA --> CONNECTED
from scapy.layers.inet import IP, UDP
from scapy.layers.isakmp import ISAKMP, ISAKMP_payload_SA, ISAKMP_payload_Transform
from scapy.utils import randstring
from scapy.all import sr1


class IPSEC_Mapper:
    def __init__(self):
        self.state = 'DISCONNECTED'
        self.src_ip = "10.0.2.2"  # initiator
        self.dst_ip = "10.0.2.1"  # responder

    def sa_main(self):
        # attempt to agree on security params.
        # Send suggestion --> parse response: agree -> P1_SA, else -> DISCONNECTED
        # create an ISAKMP packet with scapy:
        p = IP(src=self.src_ip, dst=self.dst_ip)/UDP(sport=500, dport=500)/ISAKMP(init_cookie=b"\xa2\xee\x50\xbb\x20\xdf\x2d\xfd", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Transform(
            transforms=[('Encryption', 'AES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('KeyLength', 256), ('LifeType', 'Seconds'), ('LifeDuration', 28800)]))
        p.show()
        response = sr1(p)
        print(response)
        
        self.state = 'P1_SA'
        return self.state

    def key_ex_main(self):
        self.state = 'P1_DH'
        return self.state

    def authenticate(self):
        self.state = 'P1_AUTH'
        return self.state

    def sa_quick(self):
        self.state = 'P2_SA'
        return self.state

    def ack_quick(self):
        self.state = 'CONNECTED'
        return self.state

    def informational(self):
        self.state = 'CONNECTED'
        return self.state


ipsm = IPSEC_Mapper()
ipsm.sa_main()
