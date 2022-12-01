from isakmp import *

valid_names = ['Encryption', 'KeyLength', 'Hash', 'GroupDesc', 'Authentication', 'LifeType', 'LifeDuration']
debug = True

def get_transform_value(list, name):
    assert(name in valid_names)

    for v in list:
        if v[0] == name:
            return v[1]

def show(packet):
    if debug:
        packet.show()
    else:
        print("Debug prints disabled.")

def dprint(data):
    if debug:
        print(data)

# shows if a returned packet is encrypted
def is_encypted(packet):
    #print(f"Flags: {packet[ISAKMP].flags}")
    return packet[ISAKMP].flags == 1 # TODO: ensure it also works for other combinations (bit set)

# returns a printable representation of a bytearray
def hexify(data : bytes):
    hd = "".join("%02x " % b for b in data)
    return hd
