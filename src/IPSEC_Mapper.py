# Possible states for client: DISCONNECTED --> P1_SA --> P1_KE --> P1_AUTH --> P2_SA --> CONNECTED
from isakmp import *
from Connector import Connector
from utils import get_transform_value
from diffiehellman import DiffieHellman

# TODO: additional options --> NAT-D if supported: https://datatracker.ietf.org/doc/html/rfc3947


class IPSEC_Mapper:
    def __init__(self):
        self._state = 'DISCONNECTED'
        self._src_ip = "10.0.2.2"  # initiator
        self._dst_ip = "10.0.2.1"  # responder
        self._port = 500
        self._conn = Connector(self._dst_ip, self._port, self._port)
        self._resp = ISAKMP()
        # TODO: create a key-class / dict
        self._seed_key = 0
        self._nonce_client = 0
        self._nonce_server = 0
        self._skey_d = 0
        self._skey_a = 0
        self._skey_e = 0

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
        except: # some sort of error: TODO: better error handling --> stay or parse informational
            self.state = 'DISCONNECTED'

        return self.state

    def key_ex_main(self):
        # DH-Key exchange
        # Send key and nonce --> valid response: agree -> P1_KE, else -> P1_SA as it appears to stay here (TODO: test when it dies fully)
        # Public key (TODO: generate one / fuzz one?): 
        # private key and public key

        # TODO: have bitlength and group be variable
        dh = DiffieHellman(group=2, key_bits=256)
        public_key = dh.get_public_key()

        # Nonce (TODO: generate one / fuzz one?):
        self._nonce_client = b"\x12\x16\x3c\xdf\x99\x2a\xad\x47\x31\x8c\xbb\x8a\x76\x84\xb4\x44\xee\x47\x48\xa6\x87\xc6\x02\x9a\x99\x5d\x08\xbf\x70\x4e\x56\x2b"

        key_ex = ISAKMP(init_cookie=self._resp[ISAKMP].init_cookie, resp_cookie=self._resp[ISAKMP].resp_cookie, next_payload=1, exch_type=2)/ISAKMP_payload_KE(load=public_key)/ISAKMP_payload_Nonce(load=self._nonce_client) #/ISAKMP_payload_NAT_D()
        resp_key_ex = self._conn.send_recv_data(key_ex)
        try:
            target_key = self._resp[ISAKMP_payload_KE].load
            self._nonce_server = self._resp[ISAKMP_payload_Nonce].load
            self._seed_key = dh.generate_shared_key(target_key)

            # generate further keys
            
            self.state = 'P1_KE'
        except: # some sort of error: TODO: better error handling
            # TODO: chance to stay, chance to return to base?
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