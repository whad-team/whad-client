from whad.ant.crypto import is_valid_network_key

validate_xor_table = [0x20, 0x1a, 0x47, 0x11, 0x50, 0x93, 0x36, 0x8f]
validate_and_table = [0xec, 0x3f, 0xd7, 0xdb, 0x79, 0xf7, 0xbe, 0xef]


def generate_valid_keys():
    # Valid keys must satisfies the following constraints:
    # p[0] = r[2]
    # p[1] = r[2] ^ r[3]
    # p[2] = r[2] ^ r[3] ^ r[4]
    # p[3] = r[2] ^ r[3] ^ r[4] ^ r[5]
    # p[4] = r[2] ^ r[3] ^ r[4] ^ r[5] ^ r[6]
    # p[5] = r[2] ^ r[3] ^ r[4] ^ r[5] ^ r[6] ^ r[7]
    # p[6] = p[5] ^ r[1]
    # p[7] = p[6] ^ r[0]

    # For each position, generate all the p that matches the constraints
    possible_p = []

    for i in range(0, 8):
        expected_xor_result = validate_xor_table[i]
        mask = validate_and_table[i]

        candidates = []

        for x in range(256):
            if (x & mask) == expected_xor_result:
                candidates.append(x)

        possible_p.append(candidates)
        print("Possible p["+str(i)+"] values: " + str(candidates))
        
    # Iterate over all the different p
    import itertools
    for p in itertools.product(*possible_p):

        r = [0] * 8

        r[2] = p[0]
        r[3] = p[0] ^ p[1]
        r[4] = p[1] ^ p[2]
        r[5] = p[2] ^ p[3]
        r[6] = p[3] ^ p[4]
        r[7] = p[4] ^ p[5]

        r[1] = p[5] ^ p[6]
        r[0] = p[6] ^ p[7]

        network_key = bytes(r[::-1])

        if is_valid_network_key(network_key):
            yield network_key


if __name__ == "__main__":
    keys = list(generate_valid_keys())

    for key in keys:
        print(key.hex())