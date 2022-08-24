from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from Cryptodome.Random import get_random_bytes
from whad.protocol.ble.ble_pb2 import BleDirection
from struct import pack

def generate_random_value(bits):
    """Generate a random value of provided bit size.

    :param int bits: Number of bits (8-bit aligned) to generate.
    :return bytes: Random bytes
    """
    return get_random_bytes(int(bits/8))

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

def s1(key, r1, r2):
    """
    Implements the key generation function s1, defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.4.
    """
    r = r1[8:16] + r2[8:16]
    return e(key,r)

def aes_cmac(key, message):
    """
    Implements the AES-CMAC authentication function AES_CMAC, defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.5.
    """
    cmac = CMAC.new(key, ciphermod=AES)
    cmac.update(message)
    return cmac.digest()

def xor(a,b):
    """
    Implements a XOR operation applied to two bytes string.
    """
    return bytes([ai ^ bi for ai,bi in zip(a,b)])


def c1(key, r, pres, preq, iat, ia, rat, ra):
    """
    Implements the Confirm value generation function c1 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.3.
    """
    if isinstance(ia, str):
        ia = bytes.fromhex(ia.replace(":",""))

    if isinstance(ra, str):
        ra = bytes.fromhex(ra.replace(":",""))

    p1 = pres + preq + rat + iat
    p2 = b"\x00\x00\x00\x00" + ia + ra
    res1 = e(key,xor(p1,r))
    res2 = e(key,xor(res1,p2))
    return res2

def c1m1(key, confirm, pres, preq, iat, ia, rat, ra):
    """
    Implements the inverse of the Confirm value generation function c1{-1} defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.3.
    """
    if isinstance(ia, str):
        ia = bytes.fromhex(ia.replace(":",""))

    if isinstance(ra, str):
        ra = bytes.fromhex(ra.replace(":",""))

    p1 = pres + preq + rat + iat
    p2 = b"\x00\x00\x00\x00" + ia + ra
    res = xor(em1(key,xor(em1(key,confirm),p2)),p1)
    return res


def ah(key, r):
    """
    Implements the random address hash function ah defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.3.
    """
    if isinstance(r, str):
        r = bytes.fromhex(ia.replace(":",""))
    rp = 13*b"\x00" + r
    return e(key, rp)[-3:]

def f4(U, V, X, Z):
    """
    Implements the Confirm value generation function f4 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.6.
    """
    return aes_cmac(X,U + V + Z)

def f5(W, N1, N2, A1, A2):
    """
    Implements the key generation function f5 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.7.
    """
    salt = bytes.fromhex("6C888391AAF5A53860370BDB5A6083BE")
    T = aes_cmac(salt, W)
    return (
            aes_cmac(T, b"\x01" + b"\x62\x74\x6c\x65" + N1 + N2 + A1 + A2 + b"\x01\x00") +
            aes_cmac(T, b"\x00" + b"\x62\x74\x6c\x65" + N1 + N2 + A1 + A2 + b"\x01\x00")
    )

def f6(W, N1, N2, R, IOcap, A1, A2):
    """
    Implements the check value generation function f6 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.8.
    """
    return (
            aes_cmac(W, N1 + N2 + R + IOcap + A1 + A2)
    )


def g2(U, V, X , Y):
    """
    Implements the numeric comparison value generation function g2 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.9.
    """
    return (
            aes_cmac(X,U+V+Y)[-4:]
    )

def h6(W, keyID):
    """
    Implements the link key conversion function h6 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.10.
    """
    return (
            aes_cmac(W,keyID)
    )


def h7(salt, W):
    """
    Implements the link key conversion function h7 defined in Bluetooth Core Specification, [Vol 3] Part H, Section 2.2.11.
    """
    return (
            aes_cmac(salt,W)
    )

class LinkLayerCryptoManager:
    """
    This class implements the Link Layer encryption and authentication mechanisms.
    """

    def __init__(self, ltk, master_skd, master_iv, slave_skd, slave_iv):
        self.ltk = ltk
        self.master_skd = pack(">Q",master_skd)
        self.master_iv = pack("<L",master_iv)
        self.slave_skd = pack(">Q",slave_skd)
        self.slave_iv = pack("<L",slave_iv)
        self.master_cnt = 0
        self.slave_cnt = 0

        # Generate session key diversifier
        self.skd = self.slave_skd + self.master_skd

        # Generate initialization vector
        self.iv = self.master_iv + self.slave_iv

        # Generate session key
        self.session_key = e(self.ltk, self.skd)

    def update_slave_counter(self, new_value):
        """
        Update the slave's counter (counters must be updated to allow decryption and encryption).
        """
        self.slave_cnt = new_value

    def update_master_counter(self, new_value):
        """
        Update the master's counter (counters must be updated to allow decryption and encryption).
        """
        self.master_cnt = new_value


    def increment_slave_counter(self):
        """
        Increment the slave's counter (counters must be updated to allow decryption and encryption).
        """
        self.slave_cnt += 1

    def increment_master_counter(self):
        """
        Increment the master's counter (counters must be updated to allow decryption and encryption).
        """
        self.master_cnt += 1

    def generate_nonce(self, direction=BleDirection.MASTER_TO_SLAVE):
        """
        Generate a nonce according to the counter value, the direction and the IV.
        """
        counter = pack("i",self.master_cnt if direction == BleDirection.MASTER_TO_SLAVE else self.slave_cnt)
        direction = b"\x00" if direction == BleDirection.MASTER_TO_SLAVE else b"\x80"
        return counter + direction + self.iv

    def encrypt(self, payload, direction=BleDirection.MASTER_TO_SLAVE):
        """
        Encrypt a payload (according to the direction and payload).
        """
        header = bytes([payload[0] & 0xe3])
        nonce = self.generate_nonce(direction)
        plaintext = payload[2:]
        cipher = AES.new(self.session_key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(header))
        cipher.update(header)
        ciphertext = cipher.encrypt(plaintext)
        mic = cipher.digest()
        return payload[:2] + ciphertext + mic

    def decrypt(self, payload, direction=BleDirection.MASTER_TO_SLAVE):
        """
        Decrypt and verify a payload (according to the direction and payload).
        """
        header = bytes([payload[0] & 0xe3])
        ciphertext = payload[2:-4]
        mic = payload[-4:]
        nonce = self.generate_nonce(direction)
        cipher = AES.new(self.session_key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(header))
        cipher.update(header)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(mic)
            return (payload[:2] + plaintext, True)
        except ValueError:
            return (payload[:2] + plaintext, False)
