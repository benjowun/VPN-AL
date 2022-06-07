valid_names = ['Encryption', 'KeyLength', 'Hash', 'GroupDesc', 'Authentication', 'LifeType', 'LifeDuration']

def get_transform_value(list, name):
    assert(name in valid_names)

    for v in list:
        if v[0] == name:
            return v[1]