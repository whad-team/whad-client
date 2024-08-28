from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from Cryptodome.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, \
    generate_private_key, derive_private_key, EllipticCurvePublicNumbers, \
    ECDH
from scapy.layers.bluetooth4LE import LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ, \
    BTLE_CTRL, BTLE_DATA, BTLE, BTLE_CONNECT_REQ
from scapy.layers.bluetooth import SM_Hdr, SM_Pairing_Request, SM_Random, \
    SM_Pairing_Response, SM_Confirm, SM_Encryption_Information, SM_Master_Identification, \
    SM_Identity_Information, SM_Identity_Address_Information, SM_Signing_Information
from whad.common.analyzer import TrafficAnalyzer
from whad.hub.ble.bdaddr import BDAddress
from whad.protocol.ble.ble_pb2 import BleDirection
from whad.ble.exceptions import MissingCryptographicMaterial
from struct import pack
from binascii import hexlify

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

def generate_p256_keypair(private_number=None):
    """
    Generate a P256 valid secret key and the associated public key.
    If a private number is provided, use it to derive the private key.
    Otherwise, generate it from scratch.
    """
    if private_number is None:
        private_key = generate_private_key(SECP256R1())
    else:
        private_key = derive_private_key(private_number, SECP256R1())

    return private_key, private_key.public_key()

def generate_public_key_from_coordinates(x, y):
    """
    Generate the associated public key from the X and Y coordinates on the curve.
    """
    return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()

def generate_diffie_hellman_shared_secret(own_private_key, peer_public_key):
    """
    Generate the shared secret from a private key and the peer public key.
    """
    shared_key = own_private_key.exchange(ECDH(), peer_public_key)
    return shared_key

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
        counter = pack("I",self.master_cnt if direction == BleDirection.MASTER_TO_SLAVE else self.slave_cnt)
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

    def decrypt(self, payload, direction=BleDirection.MASTER_TO_SLAVE, error_tolerance=2):
        """
        Decrypt and verify a payload (according to the direction and payload).
        """
        header = bytes([payload[0] & 0xe3])
        ciphertext = payload[2:-4]
        mic = payload[-4:]
        if direction == BleDirection.MASTER_TO_SLAVE:
            old_counter = self.master_cnt
        else:
            old_counter = self.slave_cnt

        for i in range(error_tolerance):
            nonce = self.generate_nonce(direction)
            cipher = AES.new(self.session_key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(header))
            cipher.update(header)
            plaintext = cipher.decrypt(ciphertext)
            try:
                cipher.verify(mic)
                return (payload[:2] + plaintext, True)
            except ValueError:
                if direction == BleDirection.MASTER_TO_SLAVE:
                    self.master_cnt += 1
                else:
                    self.slave_cnt += 1
        if direction == BleDirection.MASTER_TO_SLAVE:
            self.master_cnt = old_counter
        else:
            self.slave_cnt = old_counter

        return (payload[:2] + plaintext, False)



class EncryptedSessionInitialization(TrafficAnalyzer):
    def __init__(self, master_skd = None, master_iv = None, slave_skd = None, slave_iv = None):
        self.reset()
        self.master_skd = master_skd
        self.master_iv = master_iv
        self.slave_skd = slave_skd
        self.slave_iv = slave_iv

    def reset(self):
        super().reset()
        self.master_skd = None
        self.master_iv = None
        self.slave_skd = None
        self.slave_iv = None
        self.started = False

    def process_packet(self, packet):
        if BTLE_CTRL not in packet:
            return

        if LL_ENC_REQ in packet:
            self.trigger()
            self.master_skd = packet.skdm
            self.master_iv = packet.ivm
            self.mark_packet(packet)
        elif LL_ENC_RSP in packet:
            self.trigger()
            self.slave_skd = packet.skds
            self.slave_iv = packet.ivs
            self.mark_packet(packet)
            #self.started = True
        elif LL_START_ENC_REQ in packet or packet.opcode == 0x05:
            self.trigger()
            self.mark_packet(packet)
            self.started = True

        if self.started:
            self.complete()

    @property
    def output(self):
        return {
            "master_skd" : self.master_skd,
            "master_iv" : self.master_iv,
            "slave_skd" : self.slave_skd,
            "slave_iv" : self.slave_iv,
            "started" : self.started
        }

    @property
    def crypto_material(self):
        if (
                self.master_skd is not None and
                self.master_iv is not None and
                self.slave_skd is not None and
                self.slave_iv is not None
        ):
            return (self.master_skd, self.master_iv, self.slave_skd, self.slave_iv)
        else:
            return None

    @property
    def encryption(self):
        return self.crypto_material is not None and self.started




class LinkLayerDecryptor:
    def __init__(self, *keys):
        self.keys = list(keys)
        self.managers = {}
        self.master_skd = []
        self.master_iv = []
        self.slave_skd = []
        self.slave_iv = []


    def add_crypto_material(self, master_skd, master_iv, slave_skd, slave_iv):
        self.master_skd.append(master_skd)
        self.master_iv.append(master_iv)
        self.slave_skd.append(slave_skd)
        self.slave_iv.append(slave_iv)


    def add_key(self, key):
        if isinstance(key, str):
            if len(key) == 16:
                key = key.encode('ascii')
            else:
                try:
                    key = bytes.fromhex(key.replace(":",""))
                except ValueError:
                    return False

        if not isinstance(key, bytes) or len(key) != 16:
            return False

        if key not in self.keys:
            self.keys.append(key)
            return True
        return False

    def attempt_to_decrypt(self, packet):
        if (
                len(self.master_skd) == 0 or
                len(self.master_iv) == 0 or
                len(self.slave_skd) == 0 or
                len(self.slave_iv) == 0 or
                len(self.keys) == 0
        ):
            raise MissingCryptographicMaterial()

        if BTLE_DATA not in packet:
            return (None, False)

        if packet.len == 0 and packet.LLID == 1:
            return (None, False)

        for i in range(len(self.master_skd)):
            for key in self.keys:

                if key not in self.managers:
                    manager = LinkLayerCryptoManager(key, self.master_skd[i], self.master_iv[i], self.slave_skd[i], self.slave_iv[i])
                else:
                    manager = self.managers[key]

                plaintext, success = manager.decrypt(bytes(packet)[4:-3], direction=BleDirection.MASTER_TO_SLAVE)
                if success:
                    manager.increment_master_counter()
                    self.managers[key] = manager
                else:
                    plaintext, success = manager.decrypt(bytes(packet)[4:-3], direction=BleDirection.SLAVE_TO_MASTER)
                    if success:
                        manager.increment_slave_counter()
                        self.managers[key] = manager

                if success:
                    decrypted_packet = BTLE_DATA(plaintext)
                    decrypted_packet.len = decrypted_packet.len - 4
                    return (decrypted_packet, True)
        return (None, False)


class IdentityResolvingKeyDistribution(TrafficAnalyzer):
    def __init__(self):
        self.reset()

    @property
    def output(self):
        return {
            "address" : self.address,
            "irk" : self.irk
        }

    def process_packet(self, packet):
        if SM_Identity_Information in packet:
            self.trigger()
            self.irk = packet.irk
            self.mark_packet(packet)
        elif SM_Identity_Address_Information in packet:
            self.trigger()
            self.address = BDAddress(packet.address, random=packet.atype == "random")
            self.mark_packet(packet)
            self.complete()

    def reset(self):
        super().reset()
        self.irk = None
        self.address = None

class LongTermKeyDistribution(TrafficAnalyzer):
    def __init__(self):
        self.reset()

    @property
    def output(self):
        return {
            "ltk" : self.ltk,
            "rand" : self.rand,
            "ediv" : self.ediv
        }

    def process_packet(self, packet):
        if SM_Encryption_Information in packet:
            self.trigger()
            self.ltk = packet.ltk
            self.mark_packet(packet)
        elif SM_Master_Identification in packet:
            self.trigger()
            self.ediv = packet.ediv
            self.rand = packet.rand
            self.mark_packet(packet)
            self.complete()

    def reset(self):
        super().reset()
        self.ediv = None
        self.rand = None
        self.ltk = None

class ConnectionSignatureResolvingKeyDistribution(TrafficAnalyzer):
    def __init__(self):
        self.reset()

    @property
    def output(self):
        return {
            "csrk" : self.csrk
        }

    def process_packet(self, packet):
        if SM_Signing_Information in packet:
            self.trigger()
            self.csrk = packet.csrk
            self.mark_packet(packet)
            self.complete()

    def reset(self):
        super().reset()
        self.csrk = None

class LegacyPairingCracking(TrafficAnalyzer):
        def __init__(
            self,
            initiator = None,
            responder = None,
            pairing_req = None,
            pairing_rsp = None,
            master_confirm = None,
            master_random = None,
            slave_confirm = None,
            slave_random = None
        ):
            self.reset()
            self.initiator = initiator
            self.responder = responder

            self.pairing_req = pairing_req
            self.pairing_rsp = pairing_rsp
            self.master_confirm = master_confirm
            self.master_random = master_random
            self.slave_confirm = slave_confirm
            self.slave_random = slave_random

        def reset(self):
            super().reset()
            self.initiator = None
            self.responder = None

            self.pairing_req = None
            self.pairing_rsp = None
            self.master_confirm = None
            self.master_random = None
            self.slave_confirm = None
            self.slave_random = None

            self.tk = None
            self.stk = None

        def process_packet(self, pkt):
            if BTLE_CONNECT_REQ in pkt:
                self.trigger()
                self.initiator = BDAddress(pkt.InitA, random=pkt.TxAdd == 1)
                self.responder = BDAddress(pkt.AdvA, random=pkt.RxAdd == 1)
                self.mark_packet(pkt)
            elif SM_Pairing_Request in pkt:
                self.trigger()
                self.pairing_req = bytes(pkt[SM_Hdr].build()) # why scapy why
                self.mark_packet(pkt)

            elif SM_Pairing_Response in pkt:
                self.trigger()
                self.pairing_rsp = bytes(pkt[SM_Hdr].build())
                self.mark_packet(pkt)

            elif SM_Confirm in pkt and self.master_confirm is None:
                self.trigger()
                self.master_confirm = bytes(pkt.confirm)
                self.mark_packet(pkt)
            elif SM_Confirm in pkt and self.master_confirm is not None:
                self.trigger()
                self.slave_confirm = bytes(pkt.confirm)
                self.mark_packet(pkt)
            elif SM_Random in pkt and self.master_random is None:
                self.trigger()
                self.master_random = bytes(pkt.random)
                self.mark_packet(pkt)
            elif SM_Random in pkt and self.master_random is not None:
                self.trigger()
                self.slave_random = bytes(pkt.random)
                self.mark_packet(pkt)
            if (
                self.initiator is not None and
                self.responder is not None and
                self.pairing_req is not None and
                self.pairing_rsp is not None and
                self.master_confirm is not None and
                self.slave_confirm is not None and
                self.master_random is not None and
                self.slave_random is not None
            ):
                self.complete()

        def process_connected(self, initiator, responder):
            self.initiator = initiator
            self.responder = responder

        # Harmonize this into Traffic Analyzer class, we CAN'T run a bruteforce every time a packet is processed
        @property
        def ready(self):
            return (
                self.initiator is not None and
                self.responder is not None and
                self.pairing_req is not None and
                self.pairing_rsp is not None and
                (
                    (self.master_confirm is not None or
                     self.slave_confirm is not None)
                    and
                    (self.master_random is not None and
                    self.slave_random is not None)
                )
            )

        @property
        def output(self):
            keys = self.keys
            if keys is None:
                return {
                    "tk" : None,
                    "stk" : None
                }
            else:
                tk, stk = keys
                return {
                    "tk" : tk,
                    "stk" : stk
                }

        @property
        def keys(self):

            if self.master_confirm is not None and self.master_random is not None:
                rand = self.master_random
                confirm = self.master_confirm
            elif  self.slave_confirm is not None and self.slave_random is not None:
                rand = self.slave_random
                confirm = self.slave_confirm
            else:
                return None

            if self.tk is not None and self.stk is not None:
                return (self.tk, self.stk)

            for i in range(0,1000000):
                tk = pack(">IIII", 0,0,0,i)

                p1 = self.pairing_rsp[::-1] + self.pairing_req[::-1] + (
                    (b"\x01" if self.responder.is_random() else b"\x00") +
                    (b"\x01" if self.initiator.is_random() else b"\x00")
                )

                p2 = b"\x00\x00\x00\x00" + self.initiator.value[::-1] + self.responder.value[::-1]

                a = xor(p1, rand[::-1])
                aes = AES.new(tk, AES.MODE_ECB)
                res1 = aes.encrypt(a)
                b = xor(res1, p2)
                res2 = aes.encrypt(b)

                if res2 == confirm[::-1]:

                    stk = s1(tk, self.slave_random[::-1], self.master_random[::-1])
                    self.tk = tk
                    self.stk = stk
                    return (tk, stk)
            return None
