valid_names = ['Encryption', 'KeyLength', 'Hash', 'GroupDesc', 'Authentication', 'LifeType', 'LifeDuration']
debug = False

def get_transform_value(list, name):
    assert(name in valid_names)

    for v in list:
        if v[0] == name:
            return v[1]

def show(packet):
    if debug:
        packet.show()


# returns a printable representation of a bytearray
def hexify(data : bytes):
    hd = "".join("%02x " % b for b in data)
    return hd