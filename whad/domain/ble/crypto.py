from Cryptodome.Cipher import AES

def e(key, plaintext):
    """
    Implements the security function e, defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.1.
    """
    aes = AES.new(key,AES.MODE_ECB)
    return aes.encrypt(plaintext)

def em1(key, ciphertext):
    """
    Implements e{-1}, the inverse of the security function e, defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.1.
    """
    aes = AES.new(key,AES.MODE_ECB)
    return aes.decrypt(ciphertext)
