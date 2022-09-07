from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from isakmp import *
from utils import *
from diffiehellman import DiffieHellman
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA1
from Connector import Connector
from Keys import *
from scapy.all import raw
from scapy.packet import Raw
import random

state = 'DISCONNECTED'
src_ip = "10.0.2.2"  # initiator
dst_ip = "10.0.2.1"  # responder

# Connector
conn = Connector(dst_ip, 500, 500)

# Keys
keys = Keys()
cookie_r = b""
cookie_i = b""
sa_body_init = b""
aes_key = b""
resp = None
ivs = {} # keep ivs (and technically also enc key, but for now only iv) per m_id  
m_id = b""
nonce_i = b"" # without payload header
nonce_r = b""
id_list = [] # to keep track of all active ids
active_spi_quick = b""
authenticated = False
# TODO: make some nice structure / class to hold all the needed infos

# function to parse packet for the server state
# returns True if notification parsing was successful
def parse_notification(resp):
    try:
        if resp[ISAKMP].exch_type != ISAKMP_exchange_type.index("info"): #not an info message
            print(f"Error, package type {ISAKMP_exchange_type[resp[ISAKMP].exch_type]} not implemented yet.")
            return False
        if is_encypted(resp): # TODO: restructure this to not need this case
            resp = decrypt_info()
            return True
        current = resp[ISAKMP]
        while current.next_payload != ISAKMP_payload_type.index("None"):
            if current.next_payload == ISAKMP_payload_type.index("Notification"): # Notification payload
                current = resp[ISAKMP_payload_Notification]
                notification = current.not_type
                print(f"Info resp: Notification: {ISAKMP_notification_types[notification]}")
            elif current.next_payload == ISAKMP_payload_type.index("Hash"): # Hash payload (happens for later payloads)
                current = resp[ISAKMP_payload_Hash]
                print(f"Info resp: Hash")
            elif current.next_payload == ISAKMP_payload_type.index("Delete"): # Delete payload
                current = resp[ISAKMP_payload_Delete]
                print(f"Info resp: Delete SPI: {current.SPI}")
            else:
                print(f"Error: encountered unexpected Payload type: {resp[ISAKMP].next_payload}")
                return False
        return True # Packet fully parsed
    except BaseException as e:
        print("Error, package type not implemented yet / Error parsing - maybe encryption faulty?")
        print(e)
        return False

# return True if payload is encrypted
def is_encypted(packet):
    print(f"Flags: {packet[ISAKMP].flags}")
    return packet[ISAKMP].flags == 1 # TODO: ensure it also works for other combinations (bit set)

# Scapy to build our packets
# p = IP(flags=["DF"], src=src_ip, dst=dst_ip)/UDP(sport=46115, dport=500)/ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

def sa_main():
    global resp
    global cookie_i
    global cookie_r
    global sa_body_init
    
    # Policy negotiation, ID must be 0 here
    cookie_i = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37"
    sa_body_init = ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/sa_body_init
    policy_neg_no_match = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', '3DES-CBC'), ('KeyLength', 192), ('Hash', 'MD5'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg_vendors = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

    msg = policy_neg
    resp = conn.send_recv_data(msg)

    show(resp)
    print(f"exch type: {resp[ISAKMP].exch_type}")

    # save SA_body for later use (the important fields)
    sa_body_init = raw(sa_body_init)[4:]

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

# does not affect state
def sa_main_fail(): 
    # Policy negotiation, ID must be 0 here
    cookie_i = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37"
    sa_body_init = ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/sa_body_init
    policy_neg_no_match = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', '3DES-CBC'), ('KeyLength', 192), ('Hash', 'MD5'), ('GroupDesc', '2048MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
    policy_neg_vendors = ISAKMP(init_cookie=b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37", next_payload=1, exch_type=2)/ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))/ISAKMP_payload_VendorID(next_payload=13, load=b"\x09\x00\x26\x89\xdf\xd6\xb7\x12")/ISAKMP_payload_VendorID(next_payload=13, load=b"\xaf\xca\xd7\x13\x68\xa1\xf1\xc9\x6b\x86\x96\xfc\x77\x57\x01\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x40\x48\xb7\xd5\x6e\xbc\xe8\x85\x25\xe7\xde\x7f\x00\xd6\xc2\xd3\x80\x00\x00\x00")/ISAKMP_payload_VendorID(next_payload=13, load=b"\x4a\x13\x1c\x81\x07\x03\x58\x45\x5c\x57\x28\xf2\x0e\x95\x45\x2f")/ISAKMP_payload_VendorID(load=b"\x90\xcb\x80\x91\x3e\xbb\x69\x6e\x08\x63\x81\xb5\xec\x42\x7b\x1f")

    msg = policy_neg_no_match
    temp = conn.send_recv_data(msg)

def key_ex_main():
    global resp
    global keys
    global aes_key
    global ivs

    # Public key generation
    PSK = b"AahBd2cTvEyGevxO08J7w2SqRGbnIeBc"
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
    show(resp)

    if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("KE") and ISAKMP_payload_Nonce in resp:
        public_key_server = resp[ISAKMP_payload_KE].load
        nonce_server = resp[ISAKMP_payload_Nonce].load
        shared_key = dh.generate_shared_key(public_key_server) # Is correct
        print(f"SK len: {len(shared_key)}")
        #print(f"SK: {shared_key}\n")

        prf_SKEYID = HMAC.new(PSK, nonce + nonce_server, SHA1) # nonces used for added security
        SKEYID = prf_SKEYID.digest()
        print(f"SKEYID len: {len(SKEYID)}")
        #print(f"SKEYID: {SKEYID}\n")

        prf_SKEYID_d = HMAC.new(SKEYID, shared_key + cookie_i + cookie_r + b"\x00", SHA1) # an authenticated key is generated (cookies used to identify specific ISAKMP exchanges later)
        SKEYID_d = prf_SKEYID_d.digest() 
        prf_SKEYID_a = HMAC.new(SKEYID, SKEYID_d + shared_key + cookie_i + cookie_r + b"\x01", SHA1)
        SKEYID_a = prf_SKEYID_a.digest()
        prf_SKEYID_e = HMAC.new(SKEYID, SKEYID_a + shared_key + cookie_i + cookie_r + b"\x02", SHA1)
        SKEYID_e = prf_SKEYID_e.digest()


        print(f"SKEYI_d len: {len(SKEYID_d)}")
        #print(f"SKEYI_d: {SKEYID_d}\n")
        print(f"SKEYID_a len: {len(SKEYID_a)}")
        #print(f"SKEYID_a: {SKEYID_a}\n")
        print(f"SKEYID_e len: {len(SKEYID_e)}")
        #print(f"SKEYID_e: {SKEYID_e}\n")
        
        # enc key is conc of e key multiple times and then trimmed to needed length
        # Note that notification data is hashed with SKEYID_a once keys are established --> TODO: parsing those

        # generate aes key from SKEY_ID_e as we need 32B, not 20B for AES-CBC-256 TODO: extra class to handle updating this and ivs
        prf_AES = HMAC.new(SKEYID_e, b"\x00", SHA1) 
        tmp = prf_AES.digest()
        prf_AES = HMAC.new(SKEYID_e, tmp, SHA1)
        tmp2 = prf_AES.digest()
        aes_key = (tmp + tmp2)[0:32]
        print(f"AES-Key len: {len(aes_key)}")
        #print(f"AES-Key: {aes_key}")

        # generate initial IV from pub keys (subsequent messages use previous CBC encrypted block as IV)
        h = SHA1.new(public_key + public_key_server)
        ivs[0] = h.digest()
        print(f"iv nat len: {len(ivs[0])}")
        ivs[0] = ivs[0][:16] #trim to needed length
        print(f"iv len: {len(ivs[0])}")
        print(f"iv: {ivs[0]}")

        cur_key_dict = make_key_dict(psk=PSK, pub_client=public_key, pub_serv=public_key_server, shared=shared_key, SKEYID=SKEYID, SKEYID_d=SKEYID_d, SKEYID_a=SKEYID_a, SKEYID_e=SKEYID_e, key=aes_key)
        keys.new_key(cur_key_dict)
        # return 'CONNECTING_KEYED'
    elif parse_notification(resp):
        # return 'CONNECTING' # TODO: is this an ok return type?
        pass
    else:
        print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
        # return 'DISCONNECTED' # ? Probably?
    

def authenticate():
    global resp
    global ivs
    global authenticated

    # keys
    cur_key_dict = keys.get_latest_key()

    # create unencrypted id packet
    id_plain = ISAKMP_payload_ID(IdentData=src_ip)

    # create unencrypted hash packet
    # HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
    #   SAi_b is the entire body of the SA payload (minus the ISAKMP
    #   generic header)-- i.e. the DOI, situation, all proposals and all
    #   transforms offered by the Initiator.
    # ISii_b is generic ID payload including ID type, port and protocol (only important fields)
    SAi_b = raw(sa_body_init)
    IDii_b = raw(id_plain)[4:] # only need fields after length
    prf_HASH_i = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_client"] + cur_key_dict["pub_serv"] + cookie_i + cookie_r + SAi_b + IDii_b, SHA1)
    hash_data = prf_HASH_i.digest() 
    hash_data = hash_data + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    print(f"HASH_i len: {len(hash_data)}")
    print(f"HASH_i: {hexify(hash_data)}")

    # TODO: why is it 24 Bytes here? Just for some padding purposes?
    payload_plain = id_plain/ISAKMP_payload_Hash(length=24, load=hash_data) # /ISAKMP_payload_Notification(initial contact)

    show(payload_plain)

    cipher = AES.new(aes_key, AES.MODE_CBC, ivs[0])
    payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
    print(f"payload len: {len(payload_enc)}")
    print(f"payload: {hexify(payload_enc)}")

    ivs[0] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(ivs[0])}")
    print(f"iv_new: {hexify(ivs[0])}")

    auth_mes = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=5, exch_type=2, flags=["encryption"])/Raw(load=payload_enc)
    show(auth_mes)
    msg = auth_mes
    resp = conn.send_recv_data(msg)
    print("Encrypted resp:")
    show(resp)
    print("Decrypted resp:")
    cipher = AES.new(aes_key, AES.MODE_CBC, ivs[0])
    ivs[0] = (raw(resp[Raw])[-AES.block_size:])
    print(f"iv new: {ivs[0]}")
    decrypted = cipher.decrypt(raw(resp[Raw]))

    print(f"data: {hexify(decrypted)}")

    p = ISAKMP_payload_ID(bytes(decrypted[:12]))/ISAKMP_payload_Hash(bytes(decrypted[12:]))
    show(p)
    print(f"Verifiying resceived hash of len: {len(p[ISAKMP_payload_Hash].load)}...")
    # HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
    id_plain = ISAKMP_payload_ID(IdentData=dst_ip)
    SAr_b = SAi_b
    IDir_b = raw(id_plain)[4:] # only need fields after length
    prf_HASH_r = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_serv"] + cur_key_dict["pub_client"] + cookie_r + cookie_i + SAr_b + IDir_b, SHA1)
    hash_data = prf_HASH_r.digest()
    if hash_data == p[ISAKMP_payload_Hash].load:
        print("OK")
        authenticated = True
    else:
        print(f"recved: {p[ISAKMP_payload_Hash].load}\nshould be: {hash_data}")

def auth_wrong():
    global resp
    global ivs
    global authenticated

    # keys
    cur_key_dict = keys.get_latest_key()

    # create unencrypted id packet
    id_plain = ISAKMP_payload_ID(IdentData=src_ip)

    # create unencrypted hash packet
    # HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
    #   SAi_b is the entire body of the SA payload (minus the ISAKMP
    #   generic header)-- i.e. the DOI, situation, all proposals and all
    #   transforms offered by the Initiator.
    # ISii_b is generic ID payload including ID type, port and protocol (only important fields)
    SAi_b = raw(sa_body_init)
    IDii_b = raw(id_plain)[4:] # only need fields after length
    prf_HASH_i = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_client"] + cur_key_dict["pub_serv"] + b"\x11" + cookie_i + cookie_r + SAi_b + IDii_b, SHA1)
    hash_data = prf_HASH_i.digest() 
    hash_data = hash_data + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    print(f"HASH_i len: {len(hash_data)}")
    print(f"HASH_i: {hexify(hash_data)}")

    payload_plain = id_plain/ISAKMP_payload_Hash(length=24, load=hash_data) # /ISAKMP_payload_Notification(initial contact)

    show(payload_plain)

    cipher = AES.new(aes_key, AES.MODE_CBC, ivs[0])
    payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
    print(f"payload len: {len(payload_enc)}")
    print(f"payload: {hexify(payload_enc)}")

    ivs[0] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(ivs[0])}")
    print(f"iv_new: {hexify(ivs[0])}")

    auth_mes = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=5, exch_type=2, flags=["encryption"])/Raw(load=payload_enc)
    show(auth_mes)
    msg = auth_mes
    resp = conn.send_data(msg)

# TODO: check for INVALID-ID-INFORMATION notifications on invalid IDs
def sa_quick():
    global ivs
    global m_id
    global nonce_i
    global nonce_r
    global active_spi_quick

    # keys
    cur_key_dict = keys.get_latest_key()

    # generate unique message ID randomly:
    while True:
        r = random.randint(0, 4294967295)
        if r not in id_list:
            m_id = (r).to_bytes(4, 'big')
            id_list.append(r)
            break

    spi = (random.randint(0, 4294967295)).to_bytes(4, 'big')
    active_spi_quick = spi

    # esp attributes --> works now, spi must be fully filled. length 40 is needed, so that padding is correct
    # TODO: check that spi is correct and can really be chosen freely --> try out creating multiple SAs using different SPI!!!!
    sa_body_quick = ISAKMP_payload_SA(next_payload=10, length=52, prop=ISAKMP_payload_Proposal(length=40, proto=3, SPIsize=4, trans_nb=1, SPI=spi, trans=ISAKMP_payload_Transform(length=28, num=1, id=12, transforms=[('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)])))

    # Nonce (TODO: generate one / fuzz one?):
    nonce = b"\x55\x0d\xff\x82\xf4\xa7\x7c\x27\x2a\x94\x96\x2d\x1a\x5b\xff\x35\xe4\x4a\x6c\xfd\xc2\x57\xf8\xcb\xe4\x0b\xd8\xb2\x14\xba\xbb\xe0"
    nonce_quick = ISAKMP_payload_Nonce(next_payload=5, length=36, load=nonce)

    # generate identifications
    # should both be (10.0.2.0)
    address = "10.0.2.0"
    mask = b"\xff\xff\xff\x00" # 255.255.255.0
    id_src_quick = ISAKMP_payload_ID(next_payload=5, length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=address, load=mask)
    id_dst_quick = ISAKMP_payload_ID(length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=address, load=mask)


    # generate hash (for now without KE):
    # HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(sa_body_quick) + raw(nonce_quick) + raw(id_src_quick) + raw(id_dst_quick), SHA1)
    hash_data = prf_HASH.digest()
    print(f"hash quick: {hexify(hash_data)}")
    hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

    # unencrypted but authenticated packet
    policy_neg_quick_raw = hash_quick/sa_body_quick/nonce_quick/id_src_quick/id_dst_quick
    show(policy_neg_quick_raw)

    # calc IV (hash of last block and id)
    print(f"last block {hexify(ivs[0])}")
    print(f"m_id: {m_id}")
    h = SHA1.new(ivs[0] + m_id)
    iv_new = h.digest()[:16]
    print(f"iv quick: {hexify(iv_new)}")

    # encrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
    payload_quick_enc = cipher.encrypt(pad(raw(policy_neg_quick_raw), AES.block_size))
    print(f"payload len: {len(payload_quick_enc)}")
    print(f"payload: {hexify(payload_quick_enc)}")
    print(f"payload plain: {hexify(raw(policy_neg_quick_raw))}")

    ivs[int.from_bytes(m_id, 'big')] = payload_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(ivs[int.from_bytes(m_id, 'big')])}")
    print(f"iv_new: {hexify(ivs[int.from_bytes(m_id, 'big')])}")

    msg = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=188)/Raw(load=payload_quick_enc)

    resp = conn.send_recv_data(msg)
    print("Encrypted resp:")
    show(resp)

    # TODO: error handling

    print("Decrypted resp:")
    cipher = AES.new(aes_key, AES.MODE_CBC, ivs[int.from_bytes(m_id, 'big')])
    ivs[int.from_bytes(m_id, 'big')] = (raw(resp[Raw])[-AES.block_size:])
    print(f"iv new: {hexify(ivs[int.from_bytes(m_id, 'big')])}")
    decrypted = cipher.decrypt(raw(resp[Raw]))
    print(f"data: {hexify(decrypted)}")
    SA_recv = ISAKMP_payload_SA(bytes(decrypted[24:76]))
    hash_recv = ISAKMP_payload_Hash(bytes(decrypted[:24]))
    nonce_recv = ISAKMP_payload_Nonce(bytes(decrypted[76:112]))
    id_recv_1 = ISAKMP_payload_ID(bytes(decrypted[112:128]))
    id_recv_2 = ISAKMP_payload_ID(bytes(decrypted[128:144]))

    p = hash_recv/SA_recv/nonce_recv/id_recv_1/id_recv_2
    show(p)

    # parse response
    print(f"Verifiying resceived hash: {hexify(p[ISAKMP_payload_Hash].load)}...")
    # HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr )
    
    print(f"Nonce recv: {hexify(raw(nonce_recv))}")
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(nonce_quick)[4:36] + raw(SA_recv) + raw(nonce_recv) + raw(id_recv_1) + raw(id_recv_2), SHA1)
    hash_data = prf_HASH.digest()
    if hash_data == hash_recv.load:
        print("SA_quick server hash verified - sending ACK")
        nonce_i = raw(nonce_quick)[4:36]
        nonce_r = raw(nonce_recv)[4:36]
    else:
        print(f"hash calculated: {hexify(hash_data)}")

def sa_quick_fail():
    global ivs
    global m_id
    global nonce_i
    global nonce_r
    global active_spi_quick

    # keys
    cur_key_dict = keys.get_latest_key()

    # generate unique message ID randomly:
    while True:
        r = random.randint(0, 4294967295)
        if r not in id_list:
            m_id = (r).to_bytes(4, 'big')
            id_list.append(r)
            break

    spi = (random.randint(0, 4294967295)).to_bytes(4, 'big')
    active_spi_quick = spi

    # esp attributes --> works now, spi must be fully filled. length 40 is needed, so that padding is correct
    # TODO: check that spi is correct and can really be chosen freely --> try out creating multiple SAs using different SPI!!!!
    sa_body_quick = ISAKMP_payload_SA(next_payload=10, length=52, prop=ISAKMP_payload_Proposal(length=40, proto=3, SPIsize=4, trans_nb=1, SPI=spi, trans=ISAKMP_payload_Transform(length=28, num=1, id=12, transforms=[('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)])))

    # Nonce (TODO: generate one / fuzz one?):
    nonce = b"\x55\x0d\xff\x82\xf4\xa7\x7c\x27\x2a\x94\x96\x2d\x1a\x5b\xff\x35\xe4\x4a\x6c\xfd\xc2\x57\xf8\xcb\xe4\x0b\xd8\xb2\x14\xba\xbb\xe0"
    nonce_quick = ISAKMP_payload_Nonce(next_payload=5, length=36, load=nonce)

    # generate identifications
    # should both be (10.0.2.0)
    address = "10.0.2.0"
    mask = b"\xff\xff\xff\x00" # 255.255.255.0
    id_src_quick = ISAKMP_payload_ID(next_payload=5, length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=address, load=mask)
    id_dst_quick = ISAKMP_payload_ID(length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=address, load=mask)


    # generate hash (for now without KE):
    # HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(sa_body_quick) + b"\xff" + raw(nonce_quick) + raw(id_src_quick) + raw(id_dst_quick), SHA1)
    hash_data = prf_HASH.digest() # THIS SHOULD BE AN INVLAID HASH NOW CAUSE OF + xff above
    print(f"hash quick: {hexify(hash_data)}")
    hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

    # unencrypted but authenticated packet
    policy_neg_quick_raw = hash_quick/sa_body_quick/nonce_quick/id_src_quick/id_dst_quick
    show(policy_neg_quick_raw)

    # calc IV (hash of last block and id)
    print(f"last block {hexify(ivs[0])}")
    print(f"m_id: {m_id}")
    h = SHA1.new(ivs[0] + m_id)
    iv_new = h.digest()[:16]
    print(f"iv quick: {hexify(iv_new)}")

    # encrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
    payload_quick_enc = cipher.encrypt(pad(raw(policy_neg_quick_raw), AES.block_size))
    print(f"payload len: {len(payload_quick_enc)}")
    print(f"payload: {hexify(payload_quick_enc)}")
    print(f"payload plain: {hexify(raw(policy_neg_quick_raw))}")

    ivs[int.from_bytes(m_id, 'big')] = payload_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(ivs[int.from_bytes(m_id, 'big')])}")
    print(f"iv_new: {hexify(ivs[int.from_bytes(m_id, 'big')])}")

    msg = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=188)/Raw(load=payload_quick_enc)

    resp = conn.send_recv_data(msg)
    print("Encrypted resp:")
    show(resp)

    # TODO: error handling

    print("Decrypted resp:")
    cipher = AES.new(aes_key, AES.MODE_CBC, ivs[int.from_bytes(m_id, 'big')])
    ivs[int.from_bytes(m_id, 'big')] = (raw(resp[Raw])[-AES.block_size:])
    print(f"iv new: {hexify(ivs[int.from_bytes(m_id, 'big')])}")
    decrypted = cipher.decrypt(raw(resp[Raw]))
    print(f"data: {hexify(decrypted)}")
    SA_recv = ISAKMP_payload_SA(bytes(decrypted[24:76]))
    hash_recv = ISAKMP_payload_Hash(bytes(decrypted[:24]))
    nonce_recv = ISAKMP_payload_Nonce(bytes(decrypted[76:112]))
    id_recv_1 = ISAKMP_payload_ID(bytes(decrypted[112:128]))
    id_recv_2 = ISAKMP_payload_ID(bytes(decrypted[128:144]))

    p = hash_recv/SA_recv/nonce_recv/id_recv_1/id_recv_2
    show(p)

    # parse response
    print(f"Verifiying resceived hash: {hexify(p[ISAKMP_payload_Hash].load)}...")
    # HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr )
    
    print(f"Nonce recv: {hexify(raw(nonce_recv))}")
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(nonce_quick)[4:36] + raw(SA_recv) + raw(nonce_recv) + raw(id_recv_1) + raw(id_recv_2), SHA1)
    hash_data = prf_HASH.digest()
    if hash_data == hash_recv.load:
        print("SA_quick server hash verified - sending ACK")
        nonce_i = raw(nonce_quick)[4:36]
        nonce_r = raw(nonce_recv)[4:36]
    else:
        print(f"hash calculated: {hexify(hash_data)}")

def ack_quick():
    global ivs
    cur_key_dict = keys.get_latest_key()

    # HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], b"\x00" + m_id + nonce_i + nonce_r , SHA1)
    hash_data = prf_HASH.digest()
    print(f"ACK hash quick: {hexify(hash_data)}")
    ack_hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

    # encrypt and send packet
    cipher = AES.new(aes_key, AES.MODE_CBC, ivs[int.from_bytes(m_id, 'big')])
    payload_hash_quick_enc = cipher.encrypt(pad(raw(ack_hash_quick), AES.block_size))
    print(f"payload len: {len(payload_hash_quick_enc)}")
    print(f"payload: {hexify(payload_hash_quick_enc)}")
    print(f"payload plain: {hexify(raw(payload_hash_quick_enc))}")

    ivs[int.from_bytes(m_id, 'big')] = payload_hash_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(ivs[int.from_bytes(m_id, 'big')])}")
    print(f"iv_new: {hexify(ivs[int.from_bytes(m_id, 'big')])}")

    msg = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=60)/Raw(load=payload_hash_quick_enc)

    conn.send_data(msg)
    print("ACK sent, tunnel up")

def informational():
    pass


def decrypt_info():
    global resp
    global ivs

    # should already be in resp from previous
    info_mesg = resp 
    show(info_mesg)
    
    assert(is_encypted(resp))        

    # iv for encryption: HASH(last recved encrypted block | m_id)
    m_id = (info_mesg[ISAKMP].id).to_bytes(4, 'big')

    iv = b""
    if int.from_bytes(m_id, 'big') in ivs:
        iv = ivs[int.from_bytes(m_id, 'big')]
    else:
        iv = ivs[0]

    print(f"m_id: {m_id}")
    print(f"last iv: {hexify(iv)}")
    print(f"aes_key: {hexify(aes_key)}")
    print(f"sa block: {hexify(sa_body_init)}")

    h = SHA1.new(iv + m_id)
    iv_new = h.digest()[:16]

    print(f"new iv len: {len(iv_new)}")
    print(f"new iv: {hexify(iv_new)}")
    ivs[int.from_bytes(m_id, 'big')] = iv_new #update ivs

    # decrypt using iv
    cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
    resp = cipher.decrypt(raw(info_mesg[Raw]))
    print(f"Decrypted: {hexify(resp)}")

    show(info_mesg)
    new_pack = ISAKMP(next_payload=ISAKMP_payload_type.index("Hash"), exch_type=ISAKMP_exchange_type.index("info"))
    
    dec_packet_bytes = raw(new_pack) + resp
    scapy_packet = Ether()/IP()/UDP()/ISAKMP(bytes(dec_packet_bytes))
    show(scapy_packet)
    parse_notification(scapy_packet)

# TODO: if no SA has been established yet, send in plain without hash
def delete():
    global resp
    global ivs
    global keys
    global aes_key

    # create unencrypted delete message --> this will fail on default strongswan apparently
    # check if SA has been established yet:
    if aes_key == b"": # no - send in plain # TODO: does not really seem to work yet
        exit(-1)
        # p = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=12, exch_type=5, id=0)/p_delete1
        # p = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=12, exch_type=5, id=0)/p_delete2
    else: # yes encrypt
        cur_key_dict = keys.get_latest_key()

        if active_spi_quick != b"": # if ipsec conn is up, cleanly delete it as well
            ## first packet: ipsec
            # p = ISAKMP()/ISAKMP_payload_Hash/ISAKMP_payload_Delete
            # keys
            p_delete1 = ISAKMP_payload_Delete(ProtoID=3, SPIsize=4, SPI=[active_spi_quick])
            print(f"delete1 (ipsec): {hexify(raw(p_delete1))}")

            m_id1 = (7777).to_bytes(4, 'big') # random  --> does not really matter that it is reused here, since we clear everything on delete anyways
            print(f"id: {int.from_bytes(m_id1, 'big')}")

            # create unencrypted hash packet
            # HASH(1) = prf(SKEYID_a, M-ID | N/D)
            prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id1 + raw(p_delete1), SHA1)
            hash_data = prf_HASH.digest()
            print(f"hash: {hexify(hash_data)}")

            payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete1

            print(f"payload plain: {hexify(raw(payload_plain))}")
            payload_plain.show()

            # iv for encryption: HASH(last recved encrypted block | m_id)
            iv = b""
            if int.from_bytes(m_id1, 'big') in ivs:
                iv = ivs[int.from_bytes(m_id1, 'big')]
            else:
                iv = ivs[0]
            print(f"last block {hexify(iv)}")
            print(f"m_id1: {m_id1}")
            print(f"iv old: {hexify(iv)}")

            h = SHA1.new(iv + m_id1)
            iv_new = h.digest()[:16]

            print(f"new iv len: {len(iv_new)}")
            print(f"new iv: {hexify(iv_new)}") # correct (if first message)

            cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
            payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
            print(f"payload len: {len(payload_enc)}")
            print(f"payload: {hexify(payload_enc)}")

            ivs[int.from_bytes(m_id1, 'big')] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
            print(f"iv_new len: {len(ivs[int.from_bytes(m_id1, 'big')])}")
            print(f"{hexify(ivs[int.from_bytes(m_id1, 'big')])}")
            p1 = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id1, 'big'), length=76)/Raw(load=payload_enc)
            resp = conn.send_data(p1)


        ## Second packet: isakmp
        p_delete2 = ISAKMP_payload_Delete(SPIsize=16, SPI=[(cookie_i+cookie_r), (cookie_i+cookie_r)])
        print(f"delete2 (isakmp): {hexify(raw(p_delete2))}")

        m_id2 = (8888).to_bytes(4, 'big') # random  --> does not really matter that it is reused here, since we clear everything on delete anyways
        print(f"id2: {int.from_bytes(m_id2, 'big')}")

        # create unencrypted hash packet
        # HASH(1) = prf(SKEYID_a, M-ID | N/D)
        prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id2 + raw(p_delete2), SHA1)
        hash_data = prf_HASH.digest()
        print(f"hash: {hexify(hash_data)}")

        payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete2

        print(f"payload plain: {hexify(raw(payload_plain))}")
        payload_plain.show()

        # iv for encryption: HASH(last recved encrypted block | m_id)
        iv = b""
        if int.from_bytes(m_id2, 'big') in ivs:
            iv = ivs[int.from_bytes(m_id2, 'big')]
        else:
            iv = ivs[0]
        print(f"last block {hexify(iv)}")
        print(f"m_id2: {m_id2}")
        print(f"iv old: {hexify(iv)}")

        h = SHA1.new(iv + m_id2)
        iv_new = h.digest()[:16]

        print(f"new iv len: {len(iv_new)}")
        print(f"new iv: {hexify(iv_new)}") # correct (if first message)

        cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
        payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
        print(f"payload len: {len(payload_enc)}")
        print(f"payload: {hexify(payload_enc)}")

        ivs[int.from_bytes(m_id2, 'big')] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
        print(f"iv_new len: {len(ivs[int.from_bytes(m_id2, 'big')])}")
        print(f"{hexify(ivs[int.from_bytes(m_id2, 'big')])}")
        p2 = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id2, 'big'), length=92)/Raw(load=payload_enc)


    # Since we requested delete --> delete our local ivs. Note: this is an advisary to the server that SAs were deleted, 
    # client does not care if server ignores it, communication will simply fail in that case
    # TODO: a seperate reset function
    ivs = {}
    keys = Keys()
    aes_key = b""
    
    
    resp = conn.send_data(p2)

# stub to test for received asynchronous serverside delete
def recv_delete():
    global resp

    # test for informational -> manually close connection
    resp = conn.recv_data()
    decrypt_info()

def test_notify():
    p_delete = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, exch_type=5)/ISAKMP_payload_Notification(not_type=11)
    resp = conn.send_data(p_delete)

# qick mode rekey
def rekey():
    if aes_key == b"" or not authenticated: # TODO: should only work on established sa
        pass # we do not rekey in main mode (TODO: maybe try this later, but definetly does not work on strongswan)
    else:
        print("REKEY - sa")
        sa_quick()
        print("REKEY - ack")
        ack_quick()
    
# Testcases
all = [sa_main, sa_main_fail, key_ex_main, authenticate, recv_delete, sa_quick, ack_quick, delete]
tc1 = [sa_main, sa_main, sa_main, sa_main, sa_main] # each considered a retransmission as the id and cookies are the same (id must be 0)
tc2 = [sa_main, sa_main_fail, sa_main, key_ex_main, decrypt_info] # key_ex must follow an established transform or it will fail
tc3 = [sa_main, key_ex_main, sa_main, decrypt_info] # shows that the packets must arrive in the expected order here, or there will be an error and the server resets
tc4 = [sa_main, key_ex_main, authenticate, sa_main] # sa_main is ignored if connection is already established 
tc4 = [sa_main, key_ex_main, authenticate, key_ex_main] # once connection is established, no phase 1 messages seem to have an effect
tc5 = [sa_main, key_ex_main, authenticate, authenticate] # once connection is established, no phase 1 messages seem to have an effect
tc6 = [sa_main, key_ex_main, authenticate, delete] # works
tc7 = [sa_main, key_ex_main, authenticate, delete, sa_main] # works
tc8 = [sa_main, key_ex_main, authenticate, sa_quick] # works
tc9 = [sa_main, key_ex_main, authenticate, delete, sa_main, delete] # works
tc10 = [sa_main, key_ex_main, authenticate, "recv_delete", sa_quick, delete] # works
tc11 = [sa_main, key_ex_main, authenticate, "recv_delete", sa_quick, ack_quick, delete] # works
tc12 = [sa_main, key_ex_main, authenticate, recv_delete, sa_main] # check if recv delete still works after iv handling changes
tc13 = [sa_main, key_ex_main, authenticate, delete, sa_main, key_ex_main, authenticate, delete, sa_main, delete] # multiple deletes
tc14 = [sa_main, key_ex_main, authenticate, sa_quick, ack_quick, rekey, delete] # resending sa_quick triggers a rekeying
tc15 = [sa_main, key_ex_main, key_ex_main] # does not accept second key_ex as it is waiting for an encrypted auth message
tc16 = [sa_main, key_ex_main, authenticate, sa_quick, sa_quick, sa_quick, sa_quick, ack_quick, delete] # one open and one established
tc17 = [sa_main, key_ex_main, authenticate, sa_quick, ack_quick, sa_quick, ack_quick, sa_quick, sa_quick, ack_quick, delete] # rekeyed
tc18 = [sa_main, key_ex_main, rekey, sa_quick, rekey, ack_quick, rekey]
tc19 = [sa_main, key_ex_main, authenticate, rekey, sa_quick, rekey, ack_quick, rekey, delete]
tc20 = [sa_main, key_ex_main, authenticate, sa_quick_fail]

full = [sa_main, key_ex_main, authenticate, "recv_delete", sa_quick, ack_quick, rekey, delete]
test = [sa_main, key_ex_main, authenticate, sa_quick, sa_quick_fail]

for t in test:
    if type(t) is str:
        continue
    print(f"*************************************************************")
    print(f"\n\nTestcase: {t.__name__}\n***************************************************************")
    t()

print("Testcases completed")

## Info - notify

# Frame 43: 118 bytes on wire (944 bits), 118 bytes captured (944 bits) on interface enp0s3, id 0
# Ethernet II, Src: PcsCompu_ce:f9:90 (08:00:27:ce:f9:90), Dst: PcsCompu_85:73:fe (08:00:27:85:73:fe)
# Internet Protocol Version 4, Src: 10.0.2.2, Dst: 10.0.2.1
# User Datagram Protocol, Src Port: 500, Dst Port: 500
# Internet Security Association and Key Management Protocol
#     Initiator SPI: 1d17959fd26f26e6
#     Responder SPI: 860c4e02b00509bc
#     Next payload: Identification (5)
#     Version: 1.0
#     Exchange type: Identity Protection (Main Mode) (2)
#     Flags: 0x01
#     Message ID: 0x00000000
#     Length: 76
#     Encrypted Data (48 bytes)
#         Payload: Identification (5)
#             Next payload: Hash (8)
#             Reserved: 00
#             Payload length: 12
#             ID type: IPV4_ADDR (1)
#             Protocol ID: Unused
#             Port: Unused
#             Identification Data:10.0.2.2
#                 ID_IPV4_ADDR: 10.0.2.2
#         Payload: Hash (8)
#             Next payload: NONE / No Next Payload  (0)
#             Reserved: 00
#             Payload length: 24
#             Hash DATA: 932fb35c557a7ce86edd397dd18477ebb8159502
#         Extra data: 000000000000000000000000

## Info - delete
# Frame 12: 134 bytes on wire (1072 bits), 134 bytes captured (1072 bits) on interface enp0s3, id 0
# Ethernet II, Src: PcsCompu_85:73:fe (08:00:27:85:73:fe), Dst: PcsCompu_ce:f9:90 (08:00:27:ce:f9:90)
# Internet Protocol Version 4, Src: 10.0.2.1, Dst: 10.0.2.2
# User Datagram Protocol, Src Port: 500, Dst Port: 500
# Internet Security Association and Key Management Protocol
#     Initiator SPI: 9dd2ecf3ea8a4737
#     Responder SPI: 17e82eb671f70ae2
#     Next payload: Hash (8)
#     Version: 1.0
#     Exchange type: Informational (5)
#     Flags: 0x01
#     Message ID: 0x9833f560
#     Length: 92
#     Encrypted Data (64 bytes)
#         Payload: Hash (8)
#             Next payload: Delete (12)
#             Reserved: 00
#             Payload length: 24
#             Hash DATA: b10db0a236b8a21ad3808d5ec2306885b066cf8d
#         Payload: Delete (12)
#             Next payload: NONE / No Next Payload  (0)
#             Reserved: 00
#             Payload length: 28
#             Domain of interpretation: IPSEC (1)
#             Protocol ID: ISAKMP (1)
#             SPI Size: 16
#             Number of SPIs: 1
#             Delete SPI: 9dd2ecf3ea8a473717e82eb671f70ae2
#         Extra data: 000000000000000000000000
