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
iv = b""

# function to parse packet for the server state
# returns True if notification parsing was successful
def parse_notification(resp):
    try:
        if resp[ISAKMP].exch_type != ISAKMP_exchange_type.index("info"): #not an info message
            print(f"Error, package type {ISAKMP_exchange_type[resp[ISAKMP].exch_type]} not implemented yet.")
            return False
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
                print(f"Info resp: Delete SPI: {hexify(current.SPI)}")
                print(f"In delete: next payload: {current.next_payload}")
            else:
                print(f"Error: encountered unexpected Payload type: {resp[ISAKMP].next_payload}")
                return False
        return True # Packet fully parsed
    except:
        print("Error, package type not implemented yet / Error parsing - maybe encryption faulty?")
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


def sa_main_fail():
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

    msg = policy_neg_no_match
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

def key_ex_main():
    global resp
    global keys
    global aes_key
    global iv

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
        iv = h.digest()
        print(f"iv nat len: {len(iv)}")
        iv = iv[:16] #trim to needed length
        print(f"iv len: {len(iv)}")
        print(f"iv: {iv}")

        cur_key_dict = make_key_dict(psk=PSK, pub_client=public_key, pub_serv=public_key_server, shared=shared_key, SKEYID=SKEYID, SKEYID_d=SKEYID_d, SKEYID_a=SKEYID_a, SKEYID_e=SKEYID_e, iv=iv, key=aes_key)
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
    global iv

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

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
    print(f"payload len: {len(payload_enc)}")
    print(f"payload: {hexify(payload_enc)}")

    iv = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(iv)}")
    print(f"iv_new: {hexify(iv)}")

    auth_mes = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=5, exch_type=2, flags=["encryption"])/Raw(load=payload_enc)
    show(auth_mes)
    msg = auth_mes
    resp = conn.send_recv_data(msg)
    print("Encrypted resp:")
    show(resp)
    print("Decrypted resp:")
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    iv = (raw(resp[Raw])[-AES.block_size:])
    print(f"iv new: {iv}")
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
    else:
        print(f"recved: {p[ISAKMP_payload_Hash].load}\nshould be: {hash_data}")

# TODO: check for INVALID-ID-INFORMATION notifications on invalid IDs
def sa_quick():
    global iv
    # keys
    cur_key_dict = keys.get_latest_key()

    # TODO: generate message ID randomly:
    m_id = (3244232844).to_bytes(4, 'big')

    # esp attributes --> works now, spi must be fully filled. length 40 is needed, so that padding is correct
    # TODO: check that spi is correct and can really be chosen freely
    sa_body_quick = ISAKMP_payload_SA(next_payload=10, length=52, prop=ISAKMP_payload_Proposal(length=40, proto=3, SPIsize=4, trans_nb=1, SPI=b"\xcf\x64\x5a\x13", trans=ISAKMP_payload_Transform(length=28, num=1, id=12, transforms=[('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)])))

    # Nonce (TODO: generate one / fuzz one?):
    nonce = b"\x55\x0d\xff\x82\xf4\xa7\x7c\x27\x2a\x94\x96\x2d\x1a\x5b\xff\x35\xe4\x4a\x6c\xfd\xc2\x57\xf8\xcb\xe4\x0b\xd8\xb2\x14\xba\xbb\xe0"
    nonce_quick = ISAKMP_payload_Nonce(next_payload=5, load=nonce)

    # generate identifications
    # current (10.0.2.2)
    mask = b"\xff\xff\xff\x00" # 255.255.255.0
    id_src_quick = ISAKMP_payload_ID(next_payload=5, length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=src_ip, load=mask)
    id_dst_quick = ISAKMP_payload_ID(length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=dst_ip, load=mask)


    # generate hash (for now without KE):
    # HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(sa_body_quick) + raw(nonce_quick) + raw(id_src_quick) + raw(id_dst_quick), SHA1)
    hash_data = prf_HASH.digest()
    print(f"hash quick: {hexify(hash_data)}")
    hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

    # unencrypted but authenticated packet
    policy_neg_quick_raw = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, exch_type=32, id=int.from_bytes(m_id, 'big'))/hash_quick/sa_body_quick/nonce_quick/id_src_quick/id_dst_quick


    # calc IV (hash of last block and id)
    print(f"last block {iv}")
    print(f"m_id: {m_id}")
    h = SHA1.new(iv + m_id)
    iv_new = h.digest()[:16]
    print(f"iv quick: {hexify(iv_new)}")

    # encrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, iv_new) # TODO: check?
    payload_quick_enc = cipher.encrypt(pad(raw(policy_neg_quick_raw), AES.block_size))
    print(f"payload len: {len(payload_quick_enc)}")
    print(f"payload: {hexify(payload_quick_enc)}")
    print(f"payload plain: {hexify(raw(policy_neg_quick_raw))}")

    iv = payload_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(iv)}")
    print(f"iv_new: {hexify(iv)}")

    msg = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=188)/Raw(load=payload_quick_enc)

    resp = conn.send_recv_data(msg)
    resp.show()

def ack_quick():
    pass

def informational():
    pass

def decrypt_info():
    global resp

    print(f"aes_key: {hexify(aes_key)}")
    print(f"iv: {hexify(iv)}")
    print(f"sa block: {hexify(sa_body_init)}")

    assert(is_encypted(resp))

    # should already be in resp from previous
    info_mesg = resp 
    show(info_mesg)

    # iv for encryption: HASH(last recved encrypted block | m_id)
    m_id = (info_mesg[ISAKMP].id).to_bytes(4, 'big')

    print(f"last block {iv}")
    print(f"m_id: {m_id}")

    h = SHA1.new(iv + m_id)
    iv_new = h.digest()[:16]

    print(f"new iv len: {len(iv_new)}")
    print(f"new iv: {hexify(iv_new)}") # correct (if first message)

    # decrypt using iv
    cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
    resp = cipher.decrypt(raw(info_mesg[Raw]))
    print(f"Decrypted: {resp}")

    show(info_mesg)
    new_pack = ISAKMP(next_payload=ISAKMP_payload_type.index("Hash"), exch_type=ISAKMP_exchange_type.index("info"))
    

    dec_packet_bytes = raw(new_pack) + resp
    scapy_packet = Ether()/IP()/UDP()/ISAKMP(bytes(dec_packet_bytes))
    show(scapy_packet)
    parse_notification(scapy_packet)
    
    # TODO: create a crypto class that handles the IV updates for me

# TODO: this will need better IV / crypto handeling
# TODO: if no SA has been established yet, send in plain without hash
def delete():
    global resp
    global iv
    # p = ISAKMP()/ISAKMP_payload_Hash/ISAKMP_payload_Delete
    # keys
    cur_key_dict = keys.get_latest_key()
    m_id = (7777).to_bytes(4, 'big') # random id
    print(f"id: {int.from_bytes(m_id, 'big')}")

    # create unencrypted delete message
    p_delete = ISAKMP_payload_Delete(SPIsize=16, SPI=[(cookie_i+cookie_r), (cookie_i+cookie_r)])

    print(f"delete: {hexify(raw(p_delete))}")

    # create unencrypted hash packet
    # HASH(1) = prf(SKEYID_a, M-ID | N/D)
    prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(p_delete), SHA1)
    hash_data = prf_HASH.digest()
    print(f"hash: {hexify(hash_data)}")

    payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete

    print(f"payload plain: {hexify(raw(payload_plain))}")
    payload_plain.show()

    # iv for encryption: HASH(last recved encrypted block | m_id)
    print(f"last block {iv}")
    print(f"m_id: {m_id}")

    h = SHA1.new(iv + m_id)
    iv_new = h.digest()[:16]

    print(f"new iv len: {len(iv_new)}")
    print(f"new iv: {hexify(iv_new)}") # correct (if first message)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv_new)
    payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
    print(f"payload len: {len(payload_enc)}")
    print(f"payload: {hexify(payload_enc)}")

    iv = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
    print(f"iv_new len: {len(iv)}")
    print(f"iv_new: {hexify(iv)}")

    p = ISAKMP(init_cookie=cookie_i, resp_cookie=cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=92)/Raw(load=payload_enc)
    resp = conn.send_data(p)

def recv_delete():
    global resp

    print(f"aes_key: {hexify(aes_key)}")
    print(f"iv: {hexify(iv)}")
    print(f"sa block: {hexify(sa_body_init)}")


    # test for informational -> manually close connection
    resp = conn.send_recv_data(b"test")
    decrypt_info()
    
# Testcases
all = [sa_main, sa_main_fail, key_ex_main, authenticate, recv_delete, sa_quick, ack_quick, informational]
tc1 = [sa_main, sa_main, sa_main, sa_main, sa_main] # each considered a retransmission as the id and cookies are the same (id must be 0)
tc2 = [sa_main, sa_main_fail, sa_main, key_ex_main, decrypt_info] # key_ex must follow an established transform or it will fail
tc3 = [sa_main, key_ex_main, sa_main, decrypt_info] # shows that the packets must arrive in the expected order here, or there will be an error and the server resets
tc4 = [sa_main, key_ex_main, authenticate, sa_main] # sa_main is ignored if connection is already established 
tc4 = [sa_main, key_ex_main, authenticate, key_ex_main] # once connection is established, no phase 1 messages seem to have an effect
tc5 = [sa_main, key_ex_main, authenticate, authenticate] # once connection is established, no phase 1 messages seem to have an effect
tc6 = [sa_main, key_ex_main, authenticate, delete, sa_main]
tc7 = [sa_main, key_ex_main, authenticate, sa_quick]
full = [sa_main, key_ex_main, authenticate, "recv_delete", sa_quick, ack_quick, informational]
test = tc7

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


#                         0a 00 00 34 00 00 00 01 
# 00 00 00 01 0a 00 00 28 01 03 04 01 cf 64 5a 13 # the 01 0a appears to be incorrect?
# 00 00 00 1c 01 0c 00 00 80 06 01 00 80 05 00 02 
# 80 04 00 01 80 01 00 01 80 02 0e 10 05 00 00 24 
# 55 0d ff 82 f4 a7 7c 27 2a 94 96 2d 1a 5b ff 35 
# e4 4a 6c fd c2 57 f8 cb e4 0b d8 b2 14 ba bb e0 
# 05 00 00 10 04 00 00 00 0a 00 02 02 ff ff ff 00 
# 00 00 00 10 04 00 00 00 0a 00 02 01 ff ff ff 00