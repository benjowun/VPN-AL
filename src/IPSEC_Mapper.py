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
from scapy.packet import Raw
from scapy.layers.l2 import Ether
import random

# TODO: additional options --> NAT-D if supported: https://datatracker.ietf.org/doc/html/rfc3947

class IPSEC_Mapper:
    def __init__(self):
        self._state = 'DISCONNECTED'
        self._domain = "10.0.2.0"  # might have to change mask as well if this is edited
        self._src_ip = "10.0.2.2"  # initiator
        self._dst_ip = "10.0.2.1"  # responder
        self._port = 500
        self._conn = Connector(self._dst_ip, self._port, self._port)
        self._resp = ISAKMP()
        self._cookie_i = b""
        self._cookie_r = b""
        self._nonce_i = b""
        self._nonce_r = b""
        self._sa_body_init = b""
        self._sas = {0: {"iv":b"", "keys":{}}} # dict to handle per m_id SA info
        self._curr_m_id = 0 # TODO: maybe use this more

    # helper methods
    # tries to decrypt an informational packet -->  decryption should be generalized in own class
    def decrypt_info(self):

        assert(is_encypted(resp))

        # should already be in resp from previous
        info_mesg = self._resp 

        # get corresponding latest iv and keys from SA corresponding to m_id
        m_id = (info_mesg[ISAKMP].id).to_bytes(4, 'big')

        iv = b""
        keys = {}
        if m_id in self._sas:
            iv = self._sas[m_id]["iv"]
            keys = self._sas[m_id]["keys"]
        else:
            iv = self._sas[0]["iv"]
            keys = self._sas[0]["keys"]

        # iv for encryption: HASH(last recved encrypted block | m_id)
        h = SHA1.new(iv + m_id)
        iv_new = h.digest()[:16]
        # update latest iv for SA
        self._sas[m_id]["iv"] = iv_new 

        # decrypt using iv
        cipher = AES.new(keys["key"], AES.MODE_CBC, iv_new)
        resp = cipher.decrypt(raw(info_mesg[Raw]))

        new_pack = ISAKMP(next_payload=ISAKMP_payload_type.index("Hash"), exch_type=ISAKMP_exchange_type.index("info"))
        
        dec_packet_bytes = raw(new_pack) + resp
        scapy_packet = Ether()/IP()/UDP()/ISAKMP(bytes(dec_packet_bytes))
        return scapy_packet

    # function to parse packet for the server state
    # returns True if notification parsing was successful
    def parse_notification(self, resp):
        try:
            if resp[ISAKMP].exch_type != ISAKMP_exchange_type.index("info"): #not an info message
                print(f"Error, package type {ISAKMP_exchange_type[resp[ISAKMP].exch_type]} not implemented yet.")
                return False

            current = resp[ISAKMP]
            if is_encypted(resp):
                resp = self.decrypt_info(resp)
                current = resp
            
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
        except:
            print("Error, package type not implemented yet / Error parsing - maybe encryption faulty?")
            return False

    ############################################################################################################################
    # actual methods
    def sa_main(self):
        show(self._resp)
        # attempt to agree on security params.
        # Send suggestion --> parse response: agree -> P1_SA, else -> DISCONNECTED
        # create an ISAKMP packet with scapy:
        
        # hardcoded cookie for now
        cookie_i = b"\x9d\xd2\xec\xf3\xea\x8a\x47\x37"
        # split because we need the body for later calculations
        sa_body_init = ISAKMP_payload_SA(prop=ISAKMP_payload_Proposal(trans_nb=1, trans=ISAKMP_payload_Transform(num=1, transforms=[('Encryption', 'AES-CBC'), ('KeyLength', 256), ('Hash', 'SHA'), ('GroupDesc', '1024MODPgr'), ('Authentication', 'PSK'), ('LifeType', 'Seconds'), ('LifeDuration', 28800)])))
        policy_neg = ISAKMP(init_cookie=cookie_i, next_payload=1, exch_type=2)/sa_body_init

        # TODO: handle wait on get_resp due to server ignoring message
        resp = self._conn.send_recv_data(policy_neg)
        self._resp = resp # gets updated in any case

        # TODO None state timeout, for now assume there was a response

        self._cookie_r = resp[ISAKMP].resp_cookie
        sa_body_init = raw(sa_body_init)[4:] # only need interesting bytes of packet

        # response contains transform --> good --> update internal data structs if we think the server also did so
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("SA") and ISAKMP_payload_Proposal in resp and ISAKMP_payload_Transform in resp:
            agreed_transform = resp[ISAKMP_payload_Transform].transforms
            # print(f"Auth: {get_transform_value(agreed_transform, 'Authentication')}")
            self._sa_body_init = sa_body_init
            self._cookie_i = cookie_i
            self._state = 'CONNECTING'   # For now keep track of current state as well
            return 'CONNECTING'

        # is a valid notify or delete --> means something went wrong --> server probably closed connection
        elif self.parse_notification(resp):
            self._sa_body_init = b""
            self._cookie_i = b""
            self._state = 'DISCONNECTED'   # For now keep track of current state as well: TODO: maybe use server resp as state?
            return 'DISCONNECTED'
        else:
            print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
            self._sa_body_init = b""
            self._cookie_i = b""
            self._state = 'DISCONNECTED'   # For now keep track of current state as well
            return 'DISCONNECTED' # ? Probably?

    def key_ex_main(self):
        show(self._resp)
        # DH-Key exchange

        # pre-shared-key is known
        PSK = b"AahBd2cTvEyGevxO08J7w2SqRGbnIeBc" 

        # public / private key pair
        dh = DiffieHellman(group=2, key_bits=256)
        private_key = dh.get_private_key()
        public_key = dh.get_public_key()

        # Nonce: for now hardcoded: # TODO: generate one / fuzz it
        nonce_client = b"\x12\x16\x3c\xdf\x99\x2a\xad\x47\x31\x8c\xbb\x8a\x76\x84\xb4\x44\xee\x47\x48\xa6\x87\xc6\x02\x9a\x99\x5d\x08\xbf\x70\x4e\x56\x2b"
        
        key_ex = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=4, exch_type=2)/ISAKMP_payload_KE(load=public_key)/ISAKMP_payload_Nonce(load=nonce_client) #/ISAKMP_payload_NAT_D()
        
        resp = self._conn.send_recv_data(key_ex)
        self._resp = resp # save for other messages
        
        # got a good valid response
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("KE") and ISAKMP_payload_Nonce in resp:
            public_key_server = resp[ISAKMP_payload_KE].load
            nonce_server = resp[ISAKMP_payload_Nonce].load
            shared_key = dh.generate_shared_key(public_key_server)

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
            h = SHA1.new(public_key + public_key_server)
            iv = h.digest()
            iv = iv[:16] #trim to needed length
            self._sas[0]["iv"] = iv

            self._sas[0]["keys"] = make_key_dict(psk=PSK, pub_client=public_key, pub_serv=public_key_server, shared=shared_key, SKEYID=SKEYID, SKEYID_d=SKEYID_d, SKEYID_a=SKEYID_a, SKEYID_e=SKEYID_e, key=aes_key)

            self._state = 'CONNECTING_KEYED'
            return 'CONNECTING_KEYED'
        elif self.parse_notification(resp): # if a message is returned, there was an error and server reset
            self._state = 'DISCONNECTED'
            return 'DISCONNECTED'
        else:
            print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
            self._state = 'DISCONNECTED'
            return 'DISCONNECTED' # ? Probably?

    # everything is fine up till here
    def authenticate(self):
        show(self._resp)
        # keys
        cur_key_dict = self._sas[0]["keys"]

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

        #print(f"payload plain: {hexify(raw(payload_plain))}")

        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, self._sas[0]["iv"])
        payload_enc = cipher.encrypt(pad(raw(payload_plain), AES.block_size))

        iv = payload_enc[-AES.block_size:] # new iv is last block of last encrypted payload
        self._sas[0]["iv"] = iv # updates class iv because dict is mutable

        # print(f"next iv: {hexify(raw(iv))}")

        auth_mes = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=5, exch_type=2, flags=["encryption"])/Raw(load=payload_enc)
        resp = self._conn.send_recv_data(auth_mes)
        self._resp = resp

        # check that the next payload is correct and that it is encrypted
        if resp[ISAKMP].next_payload == ISAKMP_payload_type.index("ID") and Raw in resp: # Raw means that its encrypted (or extra data was sent)
            # decrypt resp body
            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv)
            iv = (raw(resp[Raw])[-AES.block_size:])
            self._sas[0]["iv"] = iv

            decrypted = cipher.decrypt(raw(resp[Raw]))

            p = ISAKMP_payload_ID(bytes(decrypted[:12]))/ISAKMP_payload_Hash(bytes(decrypted[12:]))

            # HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b )
            id_plain = ISAKMP_payload_ID(IdentData=self._dst_ip)
            SAr_b = SAi_b
            IDir_b = raw(id_plain)[4:] # only need fields after length
            prf_HASH_r = HMAC.new(cur_key_dict["SKEYID"], cur_key_dict["pub_serv"] + cur_key_dict["pub_client"] + self._cookie_r + self._cookie_i + SAr_b + IDir_b, SHA1)
            hash_data = prf_HASH_r.digest()
            if hash_data == p[ISAKMP_payload_Hash].load: # Server response hash could be verified, everything ok
                return "CONNECTED"
            else: # We probably messed up somewhere / packets got mixed up, hash could not be verified --> this is a strange case as it shouldnt happen. Either a server bug or in our implementation. Either way, have to restart the connection.
                # TODO: restart connection
                return "DISCONNECTED"
        elif self.parse_notification(resp): # if a message is returned, there was an error and server reset
            self._state = 'DISCONNECTED'
            return 'DISCONNECTED'
        else:
            print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
            self._state = 'DISCONNECTED'
            return 'DISCONNECTED' # ? Probably?

    def sa_quick(self):
        cur_key_dict = self._sas[0]["keys"]

        # generate unique message ID randomly:
        m_id = b""
        while True:
            r = random.randint(0, 4294967295)
            if r not in self._sas:
                m_id = (r).to_bytes(4, 'big')
                self._sas[r] = {"iv":b"", "keys":{}}
                break
        self._curr_m_id = m_id

        spi = (random.randint(0, 4294967295)).to_bytes(4, 'big') # makes rekeying easier
        
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
        show(policy_neg_quick_raw)

        # calc IV (hash of last block and id)
        print(f"last block {hexify(self._sas[0]['iv'])}")
        print(f"m_id: {m_id}")
        h = SHA1.new(self._sas[0]["iv"] + m_id)
        iv_new = h.digest()[:16]
        print(f"iv quick: {hexify(iv_new)}")

        # encrypt
        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, iv_new)
        payload_quick_enc = cipher.encrypt(pad(raw(policy_neg_quick_raw), AES.block_size))
        print(f"payload len: {len(payload_quick_enc)}")
        print(f"payload: {hexify(payload_quick_enc)}")
        print(f"payload plain: {hexify(raw(policy_neg_quick_raw))}")

        self._sas[int.from_bytes(m_id, 'big')]["iv"] = payload_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
        print(f"iv_new len: {len(self._sas[int.from_bytes(m_id, 'big')]['iv'])}")
        print(f"iv_new: {hexify(self._sas[int.from_bytes(m_id, 'big')]['iv'])}")

        msg = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=188)/Raw(load=payload_quick_enc)
        resp = self._conn.send_recv_data(msg)
        self._resp = resp

        # check that the next payload is correct and that it is encrypted
        if resp[ISAKMP].exch_type == 32 and Raw in resp: # Raw means that its encrypted (or extra data was sent)
            # decrypt resp body
            cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, self._sas[int.from_bytes(m_id, 'big')]["iv"])
            self._sas[int.from_bytes(m_id, 'big')]["iv"] = (raw(resp[Raw])[-AES.block_size:]) # keep iv updated
            print(f"iv new: {hexify(self._sas[int.from_bytes(m_id, 'big')]['iv'])}")
            
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
                self._nonce_i = raw(nonce_quick)[4:36]
                self._nonce_r = raw(nonce_recv)[4:36]
                self._state = 'SA QUICK' # TODO: absolutely change these, just return server respones or w.e.
                return "SA QUICK SUCCESS"
            else:
                print(f"hash calculated: {hexify(hash_data)}")
                return "DISCONNECTED" # Prob fall back to phase 1 connected?
        elif self.parse_notification(resp): # if a message is returned, there was an error and server reset
            self._state = 'DISCONNECTED' # TODO: rethink return value
            return 'DISCONNECTED'
        else:
            print(f"Error: encountered unimplemented Payload type: {resp[ISAKMP].next_payload}")
            self._state = 'DISCONNECTED'
            return 'DISCONNECTED' # ? Probably?

    def ack_quick(self):
        cur_key_dict = self._sas[0]["keys"] # TODO: rethink/work this keys thing
        m_id = self._curr_m_id

        # HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
        prf_HASH = HMAC.new(cur_key_dict["SKEYID_a"], b"\x00" + m_id + self._nonce_i + self._nonce_r , SHA1)
        hash_data = prf_HASH.digest()
        print(f"ACK hash quick: {hexify(hash_data)}")
        ack_hash_quick = ISAKMP_payload_Hash(length=24, load=hash_data)

        # encrypt and send packet
        cipher = AES.new(cur_key_dict["key"], AES.MODE_CBC, self._sas[int.from_bytes(m_id, 'big')]["iv"])
        payload_hash_quick_enc = cipher.encrypt(pad(raw(ack_hash_quick), AES.block_size))
        print(f"payload len: {len(payload_hash_quick_enc)}")
        print(f"payload: {hexify(payload_hash_quick_enc)}")
        print(f"payload plain: {hexify(raw(payload_hash_quick_enc))}")

        self._sas[int.from_bytes(m_id, 'big')]["iv"] = payload_hash_quick_enc[-AES.block_size:] # new iv is last block of last encrypted payload
        print(f"iv_new len: {len(self._sas[int.from_bytes(m_id, 'big')]['iv'])}")
        print(f"iv_new: {hexify(self._sas[int.from_bytes(m_id, 'big')]['iv'])}")

        msg = ISAKMP(init_cookie=self._cookie_i, resp_cookie=self._cookie_r, next_payload=8, exch_type=32, flags=["encryption"], id=int.from_bytes(m_id, 'big'), length=60)/Raw(load=payload_hash_quick_enc)

        self._conn.send_data(msg) #TODO: do a s/r here and wait for err response!
        print("ACK sent, tunnel up")
    
    # TODO: this --> look at generated delete messages again
    def delete(self):
        pass

    def rekey_quick(self):
        if self._sas[0]["keys"]["key"] == b"":
            pass # we do not rekey in main mode (TODO: maybe try this later, but definetly does not work on strongswan)
        else:
            self.sa_quick()
            self.ack_quick()

    # sanity check, runs all in sequence, should work with no problems
    def run_all(self):
        print("sa_main")
        ret = self.sa_main()
        assert(ret == "CONNECTING")
        print("key_ex_main")
        ret = self.key_ex_main()
        assert(ret == "CONNECTING_KEYED")
        print("authenticate")
        ret = self.authenticate()
        assert(ret == "CONNECTED")
        print("sa_quick")
        self.sa_quick()
        print("ack_quick")
        self.ack_quick()


map = IPSEC_Mapper()
map.run_all()