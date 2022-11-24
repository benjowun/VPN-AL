# Possible states for client: DISCONNECTED --> P1_SA --> P1_KE --> P1_AUTH --> P2_SA --> CONNECTED
from isakmp import *
from Connector import Connector
from Keys import make_key_dict
from utils import *
from diffiehellman import DiffieHellman
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import HMAC, SHA1
from scapy.all import raw
from scapy.packet import Raw, NoPayload
from scapy.layers.l2 import Ether
import random
from time import sleep

# TODO: additional options --> NAT-D if supported: https://datatracker.ietf.org/doc/html/rfc3947

class spi_container:
    def __init__(self):
        self._spi = b""
        self._mid = b""
        self._up = False # indicates the conenction has been acknowledged        

class IPSEC_Mapper:
    def __init__(self, timeout):
        self._domain = "10.0.2.0"  # might have to change mask as well if this is edited
        self._src_ip = "10.0.2.2"  # initiator
        self._dst_ip = "10.0.2.1"  # responder
        self._port = 500
        self._conn = Connector(self._dst_ip, self._port, self._port, timeout) # Can add timeout param
        self._cookie_i = b""
        self._cookie_r = b""
        self._nonce_i = b""
        self._nonce_r = b""
        self._sa_body_init = b""
        self._ivs = {0: b""} # dict to handle per m_id SA iv info
        self._keys = {}
        self._spis = []
        self._keyed = False # Flag to indicate active connection is keyed
        self._ids = {} # For detecting retransmits, stores the return values per m_id

    # helper methods
    def print_info(self):
        dprint("INFO:")
        dprint(str(vars(self)))

    def get_latest_mid(self):
        for bundle in reversed(self._spis):
            if bundle._mid:
                return bundle
        return None

    def get_possible_spis(self):
        spis = []
        for bundle in self._spis:
            if bundle._spi:
                spis.append(bundle._spi)
        return spis

    def get_up_spis(self):
        spis = []
        for bundle in self._spis:
            if bundle._spi and bundle._up:
                spis.append(bundle._spi)
        return spis

    def get_retransmission(self, packet):
        id = packet[ISAKMP].id
        print("ID: " + str(id))
        if id == 0:
            return None
        elif id in self._ids:
            print("retransmission")
            #return self._ids[id] # TODO: change this back if this breaks something, but should increase determinism of machines
            return "RET"
        else:
            return None

    # tries to decrypt an informational packet
    def decrypt_info(self, resp):
        # should already be in resp from previous
        info_mesg = resp

        # get corresponding latest iv and keys from SA corresponding to m_id
        m_id = (info_mesg[ISAKMP].id).to_bytes(4, 'big')

        iv = b""
        if m_id in self._ivs:
            iv = self._ivs[m_id]
        else:
            iv = self._ivs[0]

        # iv for encryption: HASH(last recved encrypted block | m_id)
        h = SHA1.new(iv + m_id)
        iv_new = h.digest()[:16]
        # update latest iv for SA
        self._ivs[m_id] = iv_new 

        dprint(f"Decrypting with {iv_new}")
        # decrypt using iv
        cipher = AES.new(self._keys["key"], AES.MODE_CBC, iv_new)
        resp = cipher.decrypt(raw(info_mesg[Raw]))

        new_pack = ISAKMP(next_payload=ISAKMP_payload_type.index("Hash"), exch_type=ISAKMP_exchange_type.index("info"))
        
        dec_packet_bytes = raw(new_pack) + resp
        scapy_packet = Ether()/IP()/UDP()/ISAKMP(bytes(dec_packet_bytes)) # TODO: is this needed?
        scapy_packet.show()
        return scapy_packet

    # function to parse packet for the server state
    # returns True if notification parsing was successful
    def parse_notification(self, resp):
        try:
            ret = None
            current = resp[ISAKMP]
            if is_encypted(current):
                dprint("Decrypted")
                current = self.decrypt_info(resp)

            current = current[ISAKMP] # ensure we are starting at ISAKMP layer
            
            while not isinstance(current.payload,NoPayload):
                current = current.payload
                #current.show()
                #print(f"Current payload type: {type(current)}")
                if isinstance(current,ISAKMP_payload_Notification): # Notification payload
                    notification = current.not_type
                    print(f"Info resp: Notification: {ISAKMP_notification_types[notification]}")
                    if notification in [26, 27, 16384, 36136, 36137]: # potentially interesting non-error notificatins
                        ret = ISAKMP_notification_types[notification]
                    else:
                        ret = "ERROR_NOTIFICATION"
                elif isinstance(current,ISAKMP_payload_Hash): # Hash payload (happens for later payloads)
                    print(f"Info resp: Hash")
                elif isinstance(current,ISAKMP_payload_Delete): # Delete payload
                    print(f"Info resp: Delete SPI: {current.SPI}")
                    ret = "DELETE"
                elif isinstance(current,Raw):
                    print("Found raw data, considering as part of previous packet") # ret stays unchanged
                else:
                    print(f"Error: encountered unexpected Payload type, returning None")
                    return None
            return ret
        except Exception as e:
            print(f"Exception: {e}")
            print("Error, package type not implemented yet / Error parsing - maybe encryption faulty? Returning None")
            return None

    ############################################################################################################################
    # actual methods
    def sa_main(self):
        # attempt to agree on security params.
        # Send suggestion --> parse response: agree -> P1_SA, else -> DISCONNECTED
        # create an ISAKMP packet with scapy:
        
        # hardcoded cookie for now
        cookie_i = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37"
        # split because we need the body for later calculations
        sa_body_init = ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
        policy_neg = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/sa_body_init

        resp = self._conn.send_recv_data(policy_neg)
        if resp == None: # should never happen
            # exit(-1)
            return None
        
        if (ret := self.get_retransmission(resp)): # retransmission handling
            if ret == "RET":
                return None
            return ret

        cookie_r = resp[ISAKMP].resp_cookie
        sa_body_init = raw(sa_body_init)[4:] # only need interesting bytes of packet

        # response contains transform --> good --> update internal data structs if we think the server also did so
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("SA") and ISAKMP_payload_Proposal in resp and ISAKMP_payload_Transform in resp:
            agreed_transform = resp[ISAKMP_payload_Transform].transforms
            # print(f"Auth: {get_transform_value(agreed_transform, 'Authentication')}")
            self._sa_body_init = sa_body_init
            self._cookie_i = cookie_i
            self._cookie_r = cookie_r
            return 'ISAKMP_SA'

        # is a valid notify or delete --> means something went wrong --> server probably closed connection
        else:
            notification = self.parse_notification(resp)
            if notification:
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = notification
                #self.reset() # in this state, any error, returns us to start
                return notification
            else:
                print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = None
                exit(-1) 
                return None # ? Probably?

    def key_ex_main(self):
        if self._cookie_i == b"" or self._cookie_r == b"":
            print(" - skipped (no cookies known")
            return None
        
        # DH-Key exchange
        # pre-shared-key is known
        PSK = b"AahBd2cTvEyGevxO08J7w2SqRGbnIeBc" 

        # public / private key pair
        dh = DiffieHellman(group=2, key_bits=256)
        private_key = dh.get_private_key()
        public_key = dh.get_public_key()
        while len(private_key) < 40 or len(public_key) < 128: # DH sometimes outputs key that requires one less byte for encoding, since we don't want to worry about different padding schemes, we do not use those
            dh = DiffieHellman(group=2, key_bits=256) # create new key pair and hope its length is valid (chance is very high)
            private_key = dh.get_private_key()
            dprint(f"len of private: {len(private_key)}")
            public_key = dh.get_public_key()
            dprint(" - refreshsed DH keys")
        assert(len(public_key) == 128)

        # Nonce: for now hardcoded: # TODO: generate one / fuzz it
        nonce_client = b"\x12\x16\x3c\xdf\x99\x2a\xad\x47\x31\x8c\xbb\x8a\x76\x84\xb4\x44\xee\x47\x48\xa6\x87\xc6\x02\x9a\x99\x5d\x08\xbf\x70\x4e\x56\x2b"
        
        key_ex = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=4, exch_type=2, length=196)/ISAKMP_payload_KE(length=132, load=public_key)/ISAKMP_payload_Nonce(length=36, load=nonce_client) #/ISAKMP_payload_NAT_D()
        resp = self._conn.send_recv_data(key_ex)
        if resp == None:
            return None

        if (ret := self.get_retransmission(resp)): # retransmission handling
            if ret == "RET":
                return None
            return ret

        # got a good valid response
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("KE") and ISAKMP_payload_Nonce in resp:
            public_key_server = resp[ISAKMP_payload_KE].load
            nonce_server = resp[ISAKMP_payload_Nonce].load
            shared_key = dh.generate_shared_key(public_key_server)
            if len(shared_key) == 127:
                shared_key = b"\x00" + shared_key
            dprint(f"Shared key length: {len(shared_key)}")

            prf_SKEYID = HMAC.new(PSK, nonce_client + nonce_server, SHA1) # nonces used for added security
            SKEYID = prf_SKEYID.digest()

            # an authenticated key is generated (cookies used to identify specific ISAKMP exchanges later)
            prf_SKEYID_d = HMAC.new(SKEYID, shared_key + self._cookie_i + self._cookie_r + b"\x00", SHA1) 
            SKEYID_d = prf_SKEYID_d.digest() 
            prf_SKEYID_a = HMAC.new(SKEYID, SKEYID_d + shared_key + self._cookie_i + self._cookie_r + b"\x01", SHA1)
            SKEYID_a = prf_SKEYID_a.digest()
            prf_SKEYID_e = HMAC.new(SKEYID, SKEYID_a + shared_key + self._cookie_i + self._cookie_r + b"\x02", SHA1)
            SKEYID_e = prf_SKEYID_e.digest()

            # generate aes key from SKEY_ID_e as we need 32B, not 20B for AES-CBC-256 TODO: extra class to handle updating this and ivs
            prf_AES = HMAC.new(SKEYID_e, b"\x00", SHA1) 
            tmp = prf_AES.digest()
            prf_AES = HMAC.new(SKEYID_e, tmp, SHA1)
            tmp2 = prf_AES.digest()
            aes_key = (tmp + tmp2)[0:32]

            # generate initial IV from pub keys (subsequent messages use previous CBC encrypted block as IV)
            # TODO: THIS IS PROBABLY THE PROBLAMATIC SECTION --> LOOK INTO HOW TO HANDLE MULTIPLE REPEATED KE?
            h = SHA1.new(public_key + public_key_server)
            iv = h.digest()
            iv = iv[:16] #trim to needed length
            self._ivs[0] = iv

            dprint(f"IV: {hexify(iv)}")
            dprint(f"DH_key: {hexify(shared_key)}")
            dprint(f"aes key: {hexify(aes_key)}")
            dprint(f"SKEYID: {hexify(SKEYID)}")
            dprint(f"SKEYID_d: {hexify(SKEYID_d)}")
            dprint(f"SKEYID_e: {hexify(SKEYID_e)}")
            dprint(f"SKEYID_a: {hexify(SKEYID_a)}")

            self._keys = make_key_dict(psk=PSK, pub_client=public_key, pub_serv=public_key_server, shared=shared_key, SKEYID=SKEYID, SKEYID_d=SKEYID_d, SKEYID_a=SKEYID_a, SKEYID_e=SKEYID_e, key=aes_key)

            return 'ISAKMP_KEY_EX'
        else:
            notification = self.parse_notification(resp)
            if notification:
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = notification
                return notification
            else:
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = None
                print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                exit(-1)
                return None # ? Probably?

    def authenticate(self):
        # keys
        cur_key_dict = self._keys
        if not cur_key_dict:
            print(" - skipped (no keys available)")
            return None

        # create unencrypted id packet
        id_plain = ISAKMP_payload_ID(IdentData=self._src_ip)

        # create unencrypted hash packet
        # HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b )
        #   SAi_b is the entire body of the SA payload (minus the ISAKMP
        #   generic header)-- i.e. the DOI, situation, all proposals and all
        #   transforms offered by the Initiator.
        # ISii_b is generic ID payload including ID type, port and protocol (only important fields)
        SAi_b = raw(self._sa_body_init)
        IDii_b = raw(id_plain)[4:] # only need fields after length
        prf_HASH_i = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_client"] + cur_key_dict["pub_serv"] + self._cookie_i + self._cookie_r + SAi_b + IDii_b, SHA1)
        hash_data = prf_HASH_i.digest() 
        hash_data = hash_data + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" # padding up to 32b

        # TODO: why is it 24 Bytes here? Just for some padding purposes?
        payload_plain = id_plain/ISAKMP_payload_Hash(length=24, load=hash_data) # /ISAKMP_payload_Notification(initial contact)

        dprint(f"payload plain: {hexify(raw(payload_plain))}")
        show(payload_plain)

        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, self._ivs[0])
        payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
        assert(len(payload_enc) == 64)

        auth_mes = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=5, exch_type=2, flags=["encryption"])/Raw(load=payload_enc)
        resp = self._conn.send_recv_data(auth_mes)
        if resp == None: # Probably already in an established state, could catch this at start of method, but better to actually send stuff where possible
            return None

        if (ret := self.get_retransmission(resp)): # retransmission handling
            if ret == "RET":
                return None
            return ret

        dprint(f"IV before sending: {hexify(self._ivs[0])}")
        iv = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload, update only if payload is accepted
        self._ivs[0] = iv # updates class iv because dict is mutable
        dprint(f"IV after sending: {hexify(self._ivs[0])}")

        # check that the next payload is correct and that it is encrypted
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("ID") and Raw in resp: # Raw means that its encrypted (or extra data was sent)
            # decrypt resp body
            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv)
            iv = (raw(resp[Raw])[-AES.block_size:])
            self._ivs[0] = iv

            decrypted = cipher.decrypt(raw(resp[Raw]))

            p = ISAKMP_payload_ID(bytes(decrypted[:12]))/ISAKMP_payload_Hash(bytes(decrypted[12:]))

            # HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
            id_plain = ISAKMP_payload_ID(IdentData=self._dst_ip)
            SAr_b = SAi_b
            IDir_b = raw(id_plain)[4:] # only need fields after length
            prf_HASH_r = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_serv"] + cur_key_dict["pub_client"] + self._cookie_r + self._cookie_i + SAr_b + IDir_b, SHA1)
            hash_data = prf_HASH_r.digest()
            if hash_data == p[ISAKMP_payload_Hash].load: # Server response hash could be verified, everything ok
                self._keyed = True # mark SA established
                return "ISAKMP_AUTH"
            else: # We probably messed up somewhere / packets got mixed up, hash could not be verified --> this is a strange case as it shouldnt happen. Either a server bug or in our implementation. Either way, have to restart the connection.
                #self.reset() # TODO: is this reset needed??
                print(f"Error, hash mismatch: {hexify(hash_data)} : {hexify(p[ISAKMP_payload_Hash].load)}")
                exit(-1) 
        else:
            notification = self.parse_notification(resp)
            if notification:
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = notification
                #self.reset() # TODO: is this reset needed?? --> yes, but unlikely to happen with valid values, but needed e.g. once we start fuzzing as on error, the SA is killed
                return notification
            else:
                print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = None
                exit(-1)
                return None # ? Probably?

    def sa_quick(self):
        if not self._keyed:
            print(" - skipped")
            return None
        cur_key_dict = self._keys

        # generate unique message ID randomly:
        new_spi = spi_container()
        m_id = b""
        while True:
            r = random.randint(1, 4294967295)
            if r not in self._ivs:
                m_id = (r).to_bytes(4, 'big')
                break
        new_spi._mid = m_id

        while True:
            r = random.randint(1, 4294967295).to_bytes(4, 'big')
            if r not in self.get_possible_spis():
                break
        spi = r # makes rekeying easier
        new_spi._spi = spi

        # SPI TODO: check that spi is correct and can really be chosen freely --> try out creating multiple SAs using different SPI!!!!
        sa_body_quick = ISAKMP_payload_SA(next_payload=10, length=52, prop=ISAKMP_payload_Proposal(length=40, proto=3, SPIsize=4, trans_nb=1, SPI=spi, trans=ISAKMP_payload_Transform(length=28, num=1, id=12, transforms=[('KeyLengthESP', 256), ('AuthenticationESP', 'HMAC-SHA'), ('EncapsulationESP', 'Tunnel'), ('LifeTypeESP', 'Seconds'), ('LifeDurationESP', 3600)])))

        # Nonce (TODO: generate one / fuzz one?):
        nonce = b"\x55\x0d\xff\x82\xf4\xa7\x7c\x27\x2a\x94\x96\x2d\x1a\x5b\xff\x35\xe4\x4a\x6c\xfd\xc2\x57\xf8\xcb\xe4\x0b\xd8\xb2\x14\xba\xbb\xe0"
        nonce_quick = ISAKMP_payload_Nonce(next_payload=5, length=36, load=nonce)

        # generate identifications
        # should both be (10.0.2.0) --> see ipsec configuration
        address = self._domain
        mask = b"\xff\xff\xff\x00" # 255.255.255.0
        id_src_quick = ISAKMP_payload_ID(next_payload=5, length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=address, load=mask)
        id_dst_quick = ISAKMP_payload_ID(length=16, IDtype="IPv4_ADDR_SUBNET", IdentData=address, load=mask)

        # generate hash (for now without KE):
        # HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr )
        prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(sa_body_quick) + raw(nonce_quick) + raw(id_src_quick) + raw(id_dst_quick), SHA1)
        hash_data = prf_HASH.digest()
        #print(f"hash quick: {hexify(hash_data)}")
        hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

        # unencrypted but authenticated packet
        policy_neg_quick_raw = hash_quick/sa_body_quick/nonce_quick/id_src_quick/id_dst_quick
        #show(policy_neg_quick_raw)

        # calc IV (hash of last block and id)
        #print(f"last block {hexify(self._ivs[0])}")
        #print(f"m_id: {m_id}")
        h = SHA1.new(self._ivs[0] + m_id)
        iv_new = h.digest()[:16]
        #print(f"iv quick: {hexify(iv_new)}")

        # encrypt
        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv_new)
        payload_quick_enc = cipher.encrypt(pad(raw(policy_neg_quick_raw), AES.block_size))
        #print(f"payload len: {len(payload_quick_enc)}")
        #print(f"payload: {hexify(payload_quick_enc)}")
        #print(f"payload plain: {hexify(raw(policy_neg_quick_raw))}")

        msg = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=188)/Raw(load=payload_quick_enc)
        resp = self._conn.send_recv_data(msg)
        if resp == None:
            return None
        
        if (ret := self.get_retransmission(resp)): # retransmission handling
            if ret == "RET":
                return None
            return ret

        self._spis.append(new_spi)
        self._ivs[int.from_bytes(m_id, 'big')] = payload_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload, update after successful packet transmission
        #print(f"iv_new len: {len(self._ivs[int.from_bytes(m_id, 'big')])}")
        #print(f"iv_new: {hexify(self._ivs[int.from_bytes(m_id, 'big')])}")


        # check that the next payload is correct and that it is encrypted
        if resp[ISAKMP].exch_type == 32 and Raw in resp: # Raw means that its encrypted (or extra data was sent)
            # decrypt resp body
            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, self._ivs[int.from_bytes(m_id, 'big')])
            self._ivs[int.from_bytes(m_id, 'big')] = (raw(resp[Raw])[-AES.block_size:]) # keep iv updated
            #print(f"iv new: {hexify(self._ivs[int.from_bytes(m_id, 'big')])}")
            
            decrypted = cipher.decrypt(raw(resp[Raw]))
            #print(f"data: {hexify(decrypted)}")

            SA_recv = ISAKMP_payload_SA(bytes(decrypted[24:76]))
            hash_recv = ISAKMP_payload_Hash(bytes(decrypted[:24]))
            nonce_recv = ISAKMP_payload_Nonce(bytes(decrypted[76:112]))
            id_recv_1 = ISAKMP_payload_ID(bytes(decrypted[112:128]))
            id_recv_2 = ISAKMP_payload_ID(bytes(decrypted[128:144]))

            p = hash_recv/SA_recv/nonce_recv/id_recv_1/id_recv_2
            #show(p)

            # parse response
            #print(f"Verifiying resceived hash: {hexify(p[ISAKMP_payload_Hash].load)}...")
            # HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr )
            
            #print(f"Nonce recv: {hexify(raw(nonce_recv))}")
            prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id + raw(nonce_quick)[4:36] + raw(SA_recv) + raw(nonce_recv) + raw(id_recv_1) + raw(id_recv_2), SHA1)
            hash_data = prf_HASH.digest()
            if hash_data == hash_recv.load:
                #print("SA_quick server hash verified - sending ACK")
                self._nonce_i = raw(nonce_quick)[4:36]
                self._nonce_r = raw(nonce_recv)[4:36]
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = "IPSEC_SA"
                return "IPSEC_SA"
            else:
                print(f"hash mismatch: {hexify(hash_data)}")
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = "IPSEC_SA_INVALID"
                #self.reset()
                return "IPSEC_SA_INVALID" 
        else:
            notification = self.parse_notification(resp)
            if notification:
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = notification
                ##self.reset()
                return notification
            else:
                print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = None
                exit(-1)
                return None # ? Probably?

    def ack_quick(self):
        if not self._keyed:
            print(" - skipped, not keyed")
            return None
        if not self.get_latest_mid():
            print(" - skipped, nothing to ack")
            return None
        cur_key_dict = self._keys
        bundle : spi_container = self.get_latest_mid()
        print(f"Bundle: {bundle}")

        # HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
        prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], b"\x00" + bundle._mid + self._nonce_i + self._nonce_r , SHA1)
        hash_data = prf_HASH.digest()
        dprint(f"ACK hash quick: {hexify(hash_data)}")
        ack_hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

        # encrypt and send packet
        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, self._ivs[int.from_bytes(bundle._mid, 'big')])
        payload_hash_quick_enc = cipher.encrypt(pad(raw(ack_hash_quick), AES.block_size))
        dprint(f"payload len: {len(payload_hash_quick_enc)}")
        dprint(f"payload: {hexify(payload_hash_quick_enc)}")
        dprint(f"payload plain: {hexify(raw(payload_hash_quick_enc))}")

        msg = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(bundle._mid, 'big'), length=60)/Raw(load=payload_hash_quick_enc)

        resp = self._conn.send_recv_data(msg)
        if resp != None:
            if (ret := self.get_retransmission(resp)): # retransmission handling
                if ret == "RET":
                    return None
                return ret
            notification = self.parse_notification(resp)
            if notification:
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = notification
                return notification
            else:
                print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                if resp[ISAKMP].id != 0:
                    self._ids[resp[ISAKMP].id] = None
                exit(-1)
                return None # ? Probably?
        
        # update iv if everything is ok / no resp
        self._ivs[int.from_bytes(bundle._mid, 'big')] = payload_hash_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
        bundle._up = True # TODO: test if up
        assert(self.get_latest_mid()._up)
        #print(f"iv_new len: {len(self._ivs[int.from_bytes(m_id, 'big')])}")
        #print(f"iv_new: {hexify(self._ivs[int.from_bytes(m_id, 'big')])}")


    # sends a delete ISAKMP packet (encrypted if already keyed, else plain)
    def ISAKMP_delete_packet(self):
        if not self._keys:
            # send unencrypted (note: strongswan ignores this)
            p_delete2 = ISAKMP_payload_Delete(SPIsize=16, SPI=[(self._cookie_i+self._cookie_r), (self._cookie_i+self._cookie_r)])
            resp = self._conn.send_recv_data(p_delete2)
            if resp != None:
                if (ret := self.get_retransmission(resp)): # retransmission handling
                    if ret == "RET":
                        return None
                    return ret
                notification = self.parse_notification(resp)
                if notification:
                    if resp[ISAKMP].id != 0:
                        self._ids[resp[ISAKMP].id] = notification
                    return notification
                else:
                    print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                    if resp[ISAKMP].id != 0:
                        self._ids[resp[ISAKMP].id] = None
                    exit(-1)
            return None
        else:
            cur_key_dict = self._keys
             ## packet: isakmp 
            p_delete2 = ISAKMP_payload_Delete(SPIsize=16, SPI=[(self._cookie_i+self._cookie_r), (self._cookie_i+self._cookie_r)])
            #print(f"delete2 (isakmp): {hexify(raw(p_delete2))}")

            m_id2 = (6666).to_bytes(4, 'big') # random  --> does not really matter that it is reused here, since we clear everything on delete anyways
            #print(f"id2: {int.from_bytes(m_id2, 'big')}")

            # We always delete SA after this, so we can simply make new iv from p1 result
            # Still for completeness' sake, we test for other ivs
            if 6666 in self._ivs:
                iv = self._ivs[6666]
            else:
                iv = self._ivs[0]

            # create unencrypted hash packet
            # HASH(1) = prf(SKEYID_a, M-ID | N/D)
            prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id2 + raw(p_delete2), SHA1)
            hash_data = prf_HASH.digest()
            #print(f"hash: {hexify(hash_data)}")

            payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete2

            #print(f"payload plain: {hexify(raw(payload_plain))}")
            #payload_plain.show()

            # iv for encryption: HASH(last recved encrypted block | m_id)
            #print(f"last block {hexify(iv)}")
            #print(f"m_id2: {m_id2}")
            #print(f"iv old: {hexify(iv)}")

            h = SHA1.new(iv + m_id2)
            iv_new = h.digest()[:16]

            #print(f"new iv len: {len(iv_new)}")
            dprint(f"current iv 6666: {hexify(iv_new)}") # correct (if first message)

            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv_new)
            payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
            #print(f"payload len: {len(payload_enc)}")
            #print(f"payload: {hexify(payload_enc)}")

            self._ivs[6666] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
            #print(f"iv_new len: {len(self._ivs[6666])}")
            dprint(f"new iv 6666 {hexify(self._ivs[6666])}")
            p2 = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id2, 'big'), length=92)/Raw(load=payload_enc)

            resp = self._conn.send_recv_data(p2)
            if resp != None:
                if (ret := self.get_retransmission(resp)): # retransmission handling
                    if ret == "RET":
                        return None
                    return ret
                notification = self.parse_notification(resp)
                if notification:
                    if resp[ISAKMP].id != 0:
                        self._ids[resp[ISAKMP].id] = notification
                    return notification
                else:
                    print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                    if resp[ISAKMP].id != 0:
                        self._ids[resp[ISAKMP].id] = None
                    exit(-1)
            return None

    # send delete packet to delete up SPIs (IPSEC SAs)
    def IPSEC_delete_packet(self):
        if not self._keys:
            return None

        # check if SA has been established yet:
        cur_key_dict = self._keys
        if self.get_up_spis(): # try to delete latest spi
            spis_quick_possible = self.get_up_spis()

            ## first packet: ipsec
            # p = ISAKMP()/ISAKMP_payload_Hash/ISAKMP_payload_Delete
            # keys
            # We always delete SA after this, so we can simply make new iv from p1 result
            # Still for completeness' sake, we test for other ivs
            if  5555 in self._ivs:
                iv = self._ivs[5555]
            else:
                iv = self._ivs[0]

            p_delete1 = ISAKMP_payload_Delete(ProtoID=3, SPIsize=4, SPI=spis_quick_possible)
            #p_delete1.show()

            m_id1 = ( 5555).to_bytes(4, 'big') # random
            #print(f"id: {int.from_bytes(m_id1, 'big')}")

            # create unencrypted hash packet
            # HASH(1) = prf(SKEYID_a, M-ID | N/D)
            prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id1 + raw(p_delete1), SHA1)
            hash_data = prf_HASH.digest()
            #print(f"hash: {hexify(hash_data)}")

            payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete1

            #print(f"payload plain: {hexify(raw(payload_plain))}")
            #payload_plain.show()

            # iv for encryption: HASH(last recved encrypted block | m_id)
            #print(f"last block {hexify(iv)}")
            #print(f"m_id1: {m_id1}")
            #print(f"iv old: {hexify(iv)}")

            h = SHA1.new(iv + m_id1)
            iv_new = h.digest()[:16]

            #print(f"new iv len: {len(iv_new)}")
            dprint(f"current iv  5555: {hexify(iv_new)}") # correct (if first message)

            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv_new)
            payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
            #print(f"payload len: {len(payload_enc)}")
            #print(f"payload: {hexify(payload_enc)}")

            self._ivs[5555] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload

            #print(f"iv_new len: {len(self._ivs[ 5555])}")
            dprint(f"new iv  5555 {hexify(self._ivs[ 5555])}")
            p1 = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id1, 'big'), length=76)/Raw(load=payload_enc)
            resp = self._conn.send_recv_data(p1)
            if resp != None:
                if (ret := self.get_retransmission(resp)): # retransmission handling
                    if ret == "RET":
                        return None
                    return ret
                notification = self.parse_notification(resp)
                if notification:
                    if resp[ISAKMP].id != 0:
                        self._ids[resp[ISAKMP].id] = notification
                    return notification
                else:
                    print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
                    if resp[ISAKMP].id != 0:
                        self._ids[resp[ISAKMP].id] = None
                    exit(-1)
            return None

    # send delete messages --> resets server
    # workarounds with notify for p1 - SA pre keying
    def delete(self):
        if not self._keys:
            # cool workaround to delete SAs
            print(" - Delete workaround")
            # ONly need to kill stuff if it has been created, i.e. we have cookies
            if self._cookie_i:
                print("   ...Sent delete ISAKMP message")
                p_delete = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, exch_type=5)/ISAKMP_payload_Notification(not_type=11)
                self._conn.send_data(p_delete)
            return None
        # create unencrypted delete message --> this will fail on default strongswan apparently
        # check if SA has been established yet:
        cur_key_dict = self._keys
        if self.get_possible_spis(): # if a ipsec conn is up, cleanly delete it as well
            # create list of all possibly active spis --> including old ones, since we use a rolling counter!
            spis_quick_possible = []
            for spi in self.get_possible_spis():
                print(f" - Trying to delete spi: {hexify(spi)}")
                spis_quick_possible.append(spi)

            ## first packet: ipsec
            # p = ISAKMP()/ISAKMP_payload_Hash/ISAKMP_payload_Delete
            # keys
            # We always delete SA after this, so we can simply make new iv from p1 result
            # Still for completeness' sake, we test for other ivs
            if 7777 in self._ivs:
                iv = self._ivs[7777]
            else:
                iv = self._ivs[0]

            p_delete1 = ISAKMP_payload_Delete(ProtoID=3, SPIsize=4, SPI=spis_quick_possible)
            #p_delete1.show()
            print(f"   ...delete1 (ipsec): {hexify(raw(p_delete1))}")
            dprint(f"   ...delete1 (ipsec): {len(raw(p_delete1))}")

            m_id1 = (7777).to_bytes(4, 'big') # random  --> does not really matter that it is reused here, since we clear everything on delete anyways
            #print(f"id: {int.from_bytes(m_id1, 'big')}")

            # create unencrypted hash packet
            # HASH(1) = prf(SKEYID_a, M-ID | N/D)
            prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id1 + raw(p_delete1), SHA1)
            hash_data = prf_HASH.digest()
            #print(f"hash: {hexify(hash_data)}")

            payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete1

            #print(f"payload plain: {hexify(raw(payload_plain))}")
            #payload_plain.show()

            # iv for encryption: HASH(last recved encrypted block | m_id)
            #print(f"last block {hexify(iv)}")
            #print(f"m_id1: {m_id1}")
            #print(f"iv old: {hexify(iv)}")

            h = SHA1.new(iv + m_id1)
            iv_new = h.digest()[:16]

            #print(f"new iv len: {len(iv_new)}")
            dprint(f"current iv 7777: {hexify(iv_new)}") # correct (if first message)

            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv_new)
            payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
            #print(f"payload len: {len(payload_enc)}")
            #print(f"payload: {hexify(payload_enc)}")

            self._ivs[7777] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload

            #print(f"iv_new len: {len(self._ivs[7777])}")
            dprint(f"new iv 7777 {hexify(self._ivs[7777])}")
            p1 = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id1, 'big'), length=76)/Raw(load=payload_enc)
            self._conn.send_data(p1)


        ## Second packet: isakmp
        p_delete2 = ISAKMP_payload_Delete(SPIsize=16, SPI=[(self._cookie_i+self._cookie_r), (self._cookie_i+self._cookie_r)])
        #print(f"delete2 (isakmp): {hexify(raw(p_delete2))}")

        m_id2 = (8888).to_bytes(4, 'big') # random  --> does not really matter that it is reused here, since we clear everything on delete anyways
        #print(f"id2: {int.from_bytes(m_id2, 'big')}")

        # We always delete SA after this, so we can simply make new iv from p1 result
        # Still for completeness' sake, we test for other ivs
        if 8888 in self._ivs:
            iv = self._ivs[8888]
        else:
            iv = self._ivs[0]

        # create unencrypted hash packet
        # HASH(1) = prf(SKEYID_a, M-ID | N/D)
        prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], m_id2 + raw(p_delete2), SHA1)
        hash_data = prf_HASH.digest()
        #print(f"hash: {hexify(hash_data)}")

        payload_plain = ISAKMP_payload_Hash(length=24, load=hash_data)/p_delete2

        #print(f"payload plain: {hexify(raw(payload_plain))}")
        #payload_plain.show()

        # iv for encryption: HASH(last recved encrypted block | m_id)
        #print(f"last block {hexify(iv)}")
        #print(f"m_id2: {m_id2}")
        #print(f"iv old: {hexify(iv)}")

        h = SHA1.new(iv + m_id2)
        iv_new = h.digest()[:16]

        #print(f"new iv len: {len(iv_new)}")
        dprint(f"current iv 8888: {hexify(iv_new)}") # correct (if first message)

        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv_new)
        payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))
        #print(f"payload len: {len(payload_enc)}")
        #print(f"payload: {hexify(payload_enc)}")

        self._ivs[8888] = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
        #print(f"iv_new len: {len(self._ivs[8888])}")
        dprint(f"new iv 8888 {hexify(self._ivs[8888])}")
        p2 = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=5, flags=["encryption"], id=int.from_bytes(m_id2, 'big'), length=92)/Raw(load=payload_enc)

        self._conn.send_data(p2)
        
    # utility function called by delete to reset Mapper to base state (server is reset with delete)
    # important -  ivs, self._keyed etc.
    def reset(self):
        self._cookie_i = b""
        self._cookie_r = b""
        self._nonce_i = b""
        self._nonce_r = b""
        self._sa_body_init = b""
        self._ivs = {0: b""}
        self._keys = {}
        self._spis = []
        self._keyed = False
        self._ids = {}
        resp = self._conn.recv_data()
        if resp:
            print("Found leftover data!")
            if (ret := self.get_retransmission(resp)): # retransmission handling
                if ret == "RET":
                    return None
                print(ret)
            else:
                notification = self.parse_notification(resp)
                if notification:
                    notification.show()
                else:
                    print(f"Error: encountered unimplemented Payload type in RESET")
        print(" - RESET!")

    # sanity check, runs all in sequence, should work with no problems
    def run_all(self):
        print("sa_main")
        self.sa_main()
        print("key_ex_main")
        self.key_ex_main()
        print("authenticate")
        self.authenticate()
        print("sa_quick")
        self.sa_quick()
        print("ack_quick")
        self.ack_quick()
        # print("rekey")
        # self.rekey_quick()
        print("delete")
        self.delete()
        self.reset()

    def run_tests(self):
        with open("logs.txt", "r") as f:
            for line in f:
                self.reset()
                cases = line.split(',')
                for case in cases:
                    name = case.strip()
                    if name == "\n" or name == "":
                        continue
                    print(name)
                    if name == "self.sa_main":
                        ret = self.sa_main()
                    elif name == "self.key_ex_main":
                        ret = self.key_ex_main()
                    elif name == "self.authenticate":
                        ret = self.authenticate()
                    elif name == "self.sa_quick":
                        ret = self.sa_quick()
                    elif name == "self.ack_quick":
                        ret = self.ack_quick()
                    else: 
                        exit(-1)

                    print("  --> " + str(ret))
                sleep(2)
                self.delete()
                
                #input("check conn\n")

    # test failing runs from SUL
    def test(self):
        testcase = [self.sa_main, self.key_ex_main, self.authenticate, self.sa_quick, self.ack_quick, self.sa_quick, self.delete_packet, self.delete, self.reset]
        for i in range(1):
            for t in testcase:
                print(f"\n\nL{i} - Testcase: {t.__name__}\n")
                ret = t()
                print(str(ret))


# map = IPSEC_Mapper(2)
# map.test()
# map.run_tests()
# map = IPSEC_Mapper(2)
# map.run_all()
