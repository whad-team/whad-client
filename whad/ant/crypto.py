ANT_PLUS_NETWORK_KEY = bytes.fromhex("45C372BDFB21A5B9")
ANT_FS_NETWORK_KEY = bytes.fromhex("C1635EF5B923A4A8")


def is_valid_network_key(network_key : bytes) -> bool:
    '''
    Checks if the provided key is a valid network key.

    :param network_key: Network key to use 
    :type network_key: bytes
    :returns: boolean indicating if the key is a valid key
    '''
    validate_xor_table = [0x20, 0x1a, 0x47, 0x11, 0x50, 0x93, 0x36, 0x8f]
    validate_and_table = [0xec, 0x3f, 0xd7, 0xdb, 0x79, 0xf7, 0xbe, 0xef]

    reversed_network_key = network_key[::-1]
    xor_start_offset = 2
    nb_xor = 1

    k_deriv = 0
    tmp = 0

    for i in range(8):
        tmp = 0
        for j in range(nb_xor):
            if j < 6:
                tmp ^= reversed_network_key[xor_start_offset + j]
            elif j == 6:
                tmp ^= reversed_network_key[1]
            else:
                tmp ^= reversed_network_key[0]
        tmp &= validate_and_table[i]
        tmp ^= validate_xor_table[i]

        k_deriv |= tmp
        nb_xor += 1
    return k_deriv == 0

def generate_sync_from_network_key(network_key) -> int:
    '''
    Generates a synchronization word from a network key for raw sniffing.

    :param network_key: Network key to use
    :type network_key: bytes
    :returns: synchronization word to use for raw sniffing
    '''
    sync_xor_key_table  = [0xfe, 0xff, 0x1c, 0x7c, 0xfc, 0x0c, 0x04, 0x3c]
    sync_and_table      = [0x41, 0x10, 0x28, 0x86, 0x08, 0xc0, 0x13, 0x24]

    reversed_network_key = network_key[::-1]
    low_sync = high_sync = 0
    tmp = tmp2 = 0

    for i in range(8):
        tmp2 = 0
        if i == 4:
            low_sync = tmp
            tmp = 0
        for j in range(8):
            if (sync_xor_key_table[i] & (1 << j)):
                tmp2 ^= reversed_network_key[j]
        tmp2 &= sync_and_table[i]
        tmp |= tmp2

    high_sync = tmp
    return low_sync | (high_sync << 8)

print(is_valid_network_key(ANT_PLUS_NETWORK_KEY), hex(generate_sync_from_network_key(ANT_PLUS_NETWORK_KEY)))
print(is_valid_network_key(ANT_FS_NETWORK_KEY))