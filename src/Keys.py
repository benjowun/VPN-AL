from collections import deque

class Keys:
    def __init__(self, max_size=3):
        self._keys = deque(maxlen=max_size)

    def new_key(self, key_map):
        self._keys.append(key_map)

    def get_latest_key(self):
        if len(self._keys) > 0:
            return self._keys[-1] # TODO check
        return None
    
    def get_key(self, index):
        if len(self._keys) >= index:
            return self._keys[index] # TODO check
        return None

def make_key_dict(psk, pub_serv, pub_client, shared, SKEYID_d, SKEYID_a, SKEYID_e):
    key_dict = {
        "psk" : psk,
        "pub_serv" : pub_serv,
        "pub_client" : pub_client,
        "shared" : shared,
        "SKEYID_d" : SKEYID_d,
        "SKEYID_a" : SKEYID_a,
        "SKEYID_e" : SKEYID_e
    }

    return key_dict