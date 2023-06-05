from Cryptodome.Cipher import AES
from whad.ble.crypto import e, aes_cmac

def aes_ccm(key, nonce, plaintext, additional_data=b""):
    """
    Implements AES_CCM, defined in Mesh Profile Specification, p.102 , Section 3.8.2.3.
    """
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(additional_data))
    cipher.update(additional_data)
    ciphertext = cipher.encrypt(plaintext)
    mic = cipher.digest()
    return ciphertext, mic

def s1(m):
    """
    Implements s1 SALT generation function,  defined in Mesh Profile Specification, p.102 , Section 3.8.2.4.
    """
    return aes_cmac(b"\x00"*16, m)

def k1(n, salt, p):
    """
    Implements k1 derivation function,  defined in Mesh Profile Specification, p.103 , Section 3.8.2.5.
    """
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)


def k2(n, p):
    """
    Implements k2 network key material derivation function,  defined in Mesh Profile Specification, p.103 , Section 3.8.2.6.
    """
    salt = s1(b"smk2")
    t = aes_cmac(salt, n)
    t0 = b""
    t1 = aes_cmac(t, t0 + p + b"\x01")
    t2 = aes_cmac(t, t1 + p + b"\x02")
    t3 = aes_cmac(t, t2 + p + b"\x03")
    return (int.from_bytes(t1 + t2 + t3) % (2 ** 263)).to_bytes(33)


def k3(n):
    """
    Implements k3 derivation function,  defined in Mesh Profile Specification, p.104 , Section 3.8.2.7.
    """
    salt = s1(b"smk3")
    t = aes_cmac(salt, n)
    return (int.from_bytes(aes_cmac(t, b"id64" + b"\x01"))).to_bytes(16)


def k4(n):
    """
    Implements k4 derivation function,  defined in Mesh Profile Specification, p.104 , Section 3.8.2.8.
    """
    salt = s1(b"smk4")
    t = aes_cmac(salt, n)
    return (int.from_bytes(aes_cmac(t, b"id6" + b"\x01"))).to_bytes(16)
