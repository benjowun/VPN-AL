from scapy.layers.inet import IP, UDP
from isakmp import *
from utils import get_transform_value
from diffiehellman import DiffieHellman
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
from base64 import b64encode
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA1

from Connector import Connector
from Keys import *

state = 'DISCONNECTED'
src_ip = "10.0.2.2"  # initiator
dst_ip = "10.0.2.1"  # responder

full = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'informational']
test = ['sa_main']

# Connector
conn = Connector(dst_ip, 500, 500)

# Keys
keys = Keys()
cookie_r = b""

# function to parse response
def parse_resp(scapy_packet):
    try:
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("Notification"): # Informational message
            notification = resp[ISAKMP_payload_Notification].not_type
            print(f"Info resp: Notification: {ISAKMP_notification_types[notification]}")
            return ISAKMP_notification_types[notification] # TODO: is this an ok return type?
        # check if it contains transforms
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("SA") and ISAKMP_payload_Proposal in resp and ISAKMP_payload_Transform in resp:
            agreed_transform = resp[ISAKMP_payload_Transform].transforms
            print(f"Agreed upon transforms: {agreed_transform}")
            print(f"Auth: {get_transform_value(agreed_transform, 'Authentication')}")
            return agreed_transform # TODO: what to return?

        print(f"Unimplemented Payload type: {resp[ISAKMP].next_payload}")
        return None
        # TODO: other cases
    except:
        print("Error, package type not implemented yet.")
        return None

# Scapy to build our packets
# p = IP(flags=["DF"], src=src_ip, dst=dst_ip)/UDP(sport=46115, dport=500)/ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

if 'sa_main' in test:
    # Policy negotiation
    cookie_i = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37"
    policy_neg = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg_no_match = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', '3DES-CBC'), ('KeyLength', 192), ('Hash', 'MD5'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg_vendors = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

    msg = policy_neg
    resp = conn.send_recv_data(msg)

    resp.show()
    print(f"exch type: {resp[ISAKMP].exch_type}")
    # example parse resp
    cookie_r = resp[ISAKMP].resp_cookie
    parse_resp(resp)

if 'key_ex_main' in test:
    # Public key (TODO: generate one / fuzz one?): 
    dh = DiffieHellman(group=2, key_bits=256)
    private_key = dh.get_private_key()
    public_key = dh.get_public_key()

    print(f"pub key len: {len(public_key)}")

    # Nonce (TODO: generate one / fuzz one?):
    nonce = b"\x12\x16\x3c\xdf\x99\x2a\xad\x47\x31\x8c\xbb\x8a\x76\x84\xb4\x44\xee\x47\x48\xa6\x87\xc6\x02\x9a\x99\x5d\x08\xbf\x70\x4e\x56\x2b"

    #key_ex_faulty = ISAKMP(init_cookie=resp[ISAKMP].init_cookie, resp_cookie=resp[ISAKMP].resp_cookie, next_payload=4, exch_type=2)/ISAKMP_payload_KE(next_payload=10)/ISAKMP_payload_Nonce() #/ISAKMP_payload_NAT_D()
    key_ex = ISAKMP(init_cookie=resp[ISAKMP].init_cookie, resp_cookie=resp[ISAKMP].resp_cookie, next_payload=4, exch_type=2)/ISAKMP_payload_KE(next_payload=10,load=public_key)/ISAKMP_payload_Nonce(load=nonce) #/ISAKMP_payload_NAT_D()
    #resp = conn.send_recv_data(key_ex_faulty)
    resp = conn.send_recv_data(key_ex)
    #resp.show()
    public_key_server = resp[ISAKMP_payload_KE].load
    nonce_server = resp[ISAKMP_payload_Nonce].load
    print(f"pub server len: {len(public_key_server)}")
    shared_key = dh.generate_shared_key(public_key_server) # TODO: test this

    SKEYID = HKDF(shared_key, 32, nonce + nonce_server, SHA1, 1)
    print(f"SKEYID len: {len(SKEYID)}")

    SKEYID_d = HKDF(SKEYID, 32, shared_key + cookie_i + cookie_r + bytes(0), SHA1, 1) 
    SKEYID_a = HKDF(SKEYID, 32, SKEYID_d + shared_key + cookie_i + cookie_r + bytes(1), SHA1, 1)
    SKEYID_e = HKDF(SKEYID, 32, SKEYID_a + shared_key + cookie_i + cookie_r + bytes(2), SHA1, 1)

    print(f"SKEYI_d: {len(SKEYID_d)}")
    print(f"SKEYID_a: {len(SKEYID_a)}")
    print(f"SKEYID_e: {len(SKEYID_e)}")

    cur_key_dict = make_key_dict(pub_client=public_key, pub_serv=public_key_server, shared=shared_key, SKEYID_d=SKEYID_d, SKEYID_a=SKEYID_a, SKEYID_e=SKEYID_e)
    keys.new_key(cur_key_dict)

if 'authenticate' in test:
    cur_key_dict = keys.get_latest_key()    
    h = SHA1.new()
    h.update(cur_key_dict["pub_client"] + cur_key_dict["pub_serv"])
    iv = h.digest()[:16] #trim to needed length
    print(f"iv: {len(iv)}")

    cipher = AES.new(cur_key_dict["SKEYID_e"], AES.MODE_CBC, iv)
    test_data = b"test" #TODO this
    enc_data = cipher.encrypt(pad(test_data, AES.block_size))
    cipher = AES.new(cur_key_dict["SKEYID_e"], AES.MODE_CBC, iv)
    print(f"decrypt test: {unpad(cipher.decrypt(enc_data), AES.block_size)}")