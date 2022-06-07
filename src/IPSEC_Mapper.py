# Possible states for client: DISCONNECTED --> P1_SA --> P1_KE --> P1_AUTH --> P2_SA --> CONNECTED
from isakmp import *
from Connector import Connector
from utils import get_transform_value

# TODO: additional options --> NAT-D if supported: https://datatracker.ietf.org/doc/html/rfc3947


class IPSEC_Mapper:
    def __init__(self):
        self._state = 'DISCONNECTED'
        self._src_ip = "10.0.2.2"  # initiator
        self._dst_ip = "10.0.2.1"  # responder
        self._port = 500
        self._conn = Connector(self._dst_ip, self._port, self._port)
        self._resp = ISAKMP()

    def sa_main(self):
        # attempt to agree on security params.
        # Send suggestion --> parse response: agree -> P1_SA, else -> DISCONNECTED
        # create an ISAKMP packet with scapy:
        policy_neg = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
        policy_neg_vendors = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

        self._resp = self._conn.send_recv_data(policy_neg_vendors)
        # check that response contains transform
        try:
            agreed_transform = self._resp[ISAKMP_payload_SA].trans
            print(f"Agreed upon transform: {agreed_transform}")
            self.state = 'P1_SA'
        except: # some sort of error: TODO: better error handling
            self.state = 'DISCONNECTED'

        return self.state

    def key_ex_main(self):
        # DH-Key exchange
        # Send key and nonce --> valid response: agree -> P1_KE, else -> P1_SA as it appears to stay here (TODO: test when it dies fully)
        # Public key (TODO: generate one / fuzz one?): 
        p_key = b"\x5e\xc6\x34\x7d\x6b\x9e\xea\xbe\x0d\xf9\x8d\xe3\xbf\x53\x1b\x24\x8d\x2e\x5e\x2c\x4b\xb8\xdc\x7b\xd4\xb2\xf0\xad\x6b\xd5\x86\x28\xd1\x25\x88\xb3\x46\x0e\xeb\x58\xa8\x2f\xac\x1d\xb7\xf3\x1b\x61\xcc\x7c\x84\xfc\x2e\xb5\x2c\x02\xd1\xc6\x38\x8d\x12\x38\x01\xb0\xba\x8b\x58\xc5\x5a\x99\xe0\xe8\x64\xaa\x67\x51\x5f\x3e\x57\x8c\xf4\xc0\xd1\xc3\x74\x1f\x82\x59\x5b\x26\x29\x0a\xd1\x66\xc2\xd3\xe4\x00\x4f\xa2\x51\x9b\x66\xae\x6d\xb2\x5f\x41\x1d\x59\xc3\xb5\x1f\x26\x2f\x78\xf4\x60\xa6\xd4\x2c\xad\xa3\x4a\xe4\x25\x70\xbd"
        # Nonce (TODO: generate one / fuzz one?):
        nonce = b"\x12\x16\x3c\xdf\x99\x2a\xad\x47\x31\x8c\xbb\x8a\x76\x84\xb4\x44\xee\x47\x48\xa6\x87\xc6\x02\x9a\x99\x5d\x08\xbf\x70\x4e\x56\x2b"

        key_ex = ISAKMP(init_cookie=self._resp[ISAKMP].init_cookie, resp_cookie=self._resp[ISAKMP].resp_cookie, next_payload=1, exch_type=2)/ISAKMP_payload_KE(load=p_key)/ISAKMP_payload_Nonce(load=nonce) #/ISAKMP_payload_NAT_D()
        resp_key_ex = self._conn.send_recv_data(key_ex)
        try:
            target_key = self._resp[ISAKMP_payload_KE].load
            target_nonce = self._resp[ISAKMP_payload_Nonce].load
            print(f"Target Key: {target_key}")
            print(f"Target Nonce: {target_nonce}")
            self.state = 'P1_KE'
        except: # some sort of error: TODO: better error handling TODO: maybe stay in P1_SA?
            self.state = 'P1_SA'

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