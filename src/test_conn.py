from re import I
from scapy.layers.inet import IP, UDP
from isakmp import *
from utils import get_transform_value
from diffiehellman import DiffieHellman
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
from base64 import b64encode
from Crypto.Hash import HMAC, SHA1
from socket import inet_aton
from Connector import Connector
from Keys import *
from scapy.all import raw
from scapy.packet import Raw

state = 'DISCONNECTED'
src_ip = "10.0.2.2"  # initiator
dst_ip = "10.0.2.1"  # responder

full = ['sa_main', 'key_ex_main', 'authenticate', 'sa_quick', 'ack_quick', 'informational']
test = ['sa_main', 'key_ex_main', 'authenticate']

# Connector
conn = Connector(dst_ip, 500, 500)

# Keys
PSK = b"AahBd2cTvEyGevxO08J7w2SqRGbnIeBc"
keys = Keys()
cookie_r = b""
cookie_i = b""
sa_body_init = b""

# function to parse packet for the server state TODO: expand on
# returns True if notification parsing was successful
def parse_notification(scapy_packet):
    try:
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("Notification"): # Informational message
            notification = resp[ISAKMP_payload_Notification].not_type
            print(f"Info resp: Notification: {ISAKMP_notification_types[notification]}")
            return True
        else:
            print(f"Error: encountered unexpected Payload type: {resp[ISAKMP].next_payload}")
            return False
    except:
        print("Error, package type not implemented yet.")
        return False

# Scapy to build our packets
# p = IP(flags=["DF"], src=src_ip, dst=dst_ip)/UDP(sport=46115, dport=500)/ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

if 'sa_main' in test:
    # Policy negotiation
    cookie_i = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37"
    sa_body_init = ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/sa_body_init
    policy_neg_no_match = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', '3DES-CBC'), ('KeyLength', 192), ('Hash', 'MD5'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg_vendors = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

    msg = policy_neg
    resp = conn.send_recv_data(msg)

    resp.show()
    print(f"exch type: {resp[ISAKMP].exch_type}")

    # example parse resp
    cookie_r = resp[ISAKMP].resp_cookie
    if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("SA") and ISAKMP_payload_Proposal in resp and ISAKMP_payload_Transform in resp:
        agreed_transform = resp[ISAKMP_payload_Transform].transforms
        print(f"Agreed upon transforms: {agreed_transform}")
        print(f"Auth: {get_transform_value(agreed_transform, 'Authentication')}")
        # TODO: store agreed transforms somewhere?
        # return 'CONNECTING'
    elif parse_notification(resp):
        # return 'DISCONNECTED' # TODO: is this an ok return type?
        pass
    else:
        print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
        # return 'DISCONNECTED' # ? Probably?

if 'key_ex_main' in test:
    # Public key generation
    dh = DiffieHellman(group=2, key_bits=256)
    private_key = dh.get_private_key()
    public_key = dh.get_public_key()

    print(f"pub key len: {len(public_key)}")

    # Nonce (TODO: generate one / fuzz one?):
    nonce = b"\x12\x16\x3c\xdf\x99\x2a\xad\x47\x31\x8c\xbb\x8a\x76\x84\xb4\x44\xee\x47\x48\xa6\x87\xc6\x02\x9a\x99\x5d\x08\xbf\x70\x4e\x56\x2b"

    key_ex_faulty = ISAKMP(init_cookie=resp[ISAKMP].init_cookie, resp_cookie=resp[ISAKMP].resp_cookie, next_payload=4, exch_type=2)/ISAKMP_payload_KE(next_payload=10)/ISAKMP_payload_Nonce() #/ISAKMP_payload_NAT_D()
    key_ex = ISAKMP(init_cookie=resp[ISAKMP].init_cookie, resp_cookie=resp[ISAKMP].resp_cookie, next_payload=4, exch_type=2)/ISAKMP_payload_KE(next_payload=10,load=public_key)/ISAKMP_payload_Nonce(load=nonce) #/ISAKMP_payload_NAT_D()
    msg = key_ex
    resp = conn.send_recv_data(msg)
    resp.show()

    if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("KE") and ISAKMP_payload_Nonce in resp:
        public_key_server = resp[ISAKMP_payload_KE].load
        nonce_server = resp[ISAKMP_payload_Nonce].load
        shared_key = dh.generate_shared_key(public_key_server) # Is correct
        print(f"SK len: {len(shared_key)}")
        print(f"SK: {shared_key}\n")

        prf_SKEYID = HMAC.new(PSK, nonce + nonce_server, SHA1) # nonces used for added security
        SKEYID = prf_SKEYID.digest()
        print(f"SKEYID len: {len(SKEYID)}")
        print(f"SKEYID: {SKEYID}\n")

        prf_SKEYID_d = HMAC.new(SKEYID, shared_key + cookie_i + cookie_r + b"\x00", SHA1) # an authenticated key is generated (cookies used to identify specific ISAKMP exchanges later)
        SKEYID_d = prf_SKEYID_d.digest() 
        prf_SKEYID_a = HMAC.new(SKEYID, SKEYID_d + shared_key + cookie_i + cookie_r + b"\x01", SHA1)
        SKEYID_a = prf_SKEYID_a.digest()
        prf_SKEYID_e = HMAC.new(SKEYID, SKEYID_a + shared_key + cookie_i + cookie_r + b"\x02", SHA1)
        SKEYID_e = prf_SKEYID_e.digest()


        print(f"SKEYI_d len: {len(SKEYID_d)}")
        print(f"SKEYI_d: {SKEYID_d}\n")
        print(f"SKEYID_a len: {len(SKEYID_a)}")
        print(f"SKEYID_a: {SKEYID_a}\n")
        print(f"SKEYID_e len: {len(SKEYID_e)}")
        print(f"SKEYID_e: {SKEYID_e}\n")

        cur_key_dict = make_key_dict(psk=PSK, pub_client=public_key, pub_serv=public_key_server, shared=shared_key, SKEYID=SKEYID, SKEYID_d=SKEYID_d, SKEYID_a=SKEYID_a, SKEYID_e=SKEYID_e)
        keys.new_key(cur_key_dict)
        # return 'CONNECTING_KEYED'
    elif parse_notification(resp):
        # return 'CONNECTING' # TODO: is this an ok return type?
        pass
    else:
        print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
        # return 'DISCONNECTED' # ? Probably?
    

if 'authenticate' in test:
    cur_key_dict = keys.get_latest_key()    
    # enc key is conc of e key multiple times and then trimmed to needed length
    # Note that notification data is hashed with SKEYID_a once keys are established --> TODO: parsing those

    # generate aes key from SKEY_ID_e as we need 32B, not 20B for AES-CBC-256
    prf_AES = HMAC.new(cur_key_dict["SKEYID_e"], b"\x00", SHA1) 
    tmp = prf_AES.digest()
    prf_AES = HMAC.new(cur_key_dict["SKEYID_e"], tmp, SHA1)
    tmp2 = prf_AES.digest()
    aes_key = (tmp + tmp2)[0:32]
    print(f"AES-Key len: {len(aes_key)}")
    print(f"AES-Key: {aes_key}")

    # generate initial IV from pub keys (subsequent messages use previous CBC encrypted block as IV)
    h = SHA1.new(cur_key_dict["pub_client"] + cur_key_dict["pub_serv"])
    iv = h.digest()
    print(f"iv nat len: {len(iv)}")
    iv = iv[:16] #trim to needed length
    print(f"iv len: {len(iv)}")
    print(f"iv: {iv}")

    # create unencrypted id packet
    id_plain = ISAKMP_payload_ID(load=inet_aton(src_ip))

    # create unencrypted hash packet
    # HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
    # SAi_b is the entire body of the SA payload (minus the ISAKMP
    # generic header)-- i.e. the DOI, situation, all proposals and all
    # transforms offered by the Initiator.
    # ISii_b is generic ID payload including ID type, port and protocol
    SAi_b = raw(sa_body_init)
    ISii_b = raw(id_plain)
    prf_HASH_i = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_client"] + cur_key_dict["pub_serv"] + cookie_i + cookie_r + SAi_b + ISii_b, SHA1)
    hash_data = prf_HASH_i.digest()
    print(f"HASH_i len: {len(hash_data)}")
    print(f"HASH_i: {hash_data}")

    payload_plain = id_plain/ISAKMP_payload_Hash(load=hash_data) # /ISAKMP_payload_Notification(initial contact)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))

    # TODO: set encrpytion flag, set length
    auth_mes = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=5, exch_type=2, flags=["encryption"])/Raw(load=payload_enc)
    auth_mes.show()
    msg = auth_mes
    resp = conn.send_recv_data(msg)
    resp.show()

    # cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    # print(f"decrypt test: {unpad(cipher.decrypt(enc_data), AES.block_size)}")