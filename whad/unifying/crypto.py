from Cryptodome.Cipher import AES
from struct import pack
from copy import copy

from whad.unifying.exceptions import MissingEncryptedKeystrokePayload
from whad.common.analyzer import TrafficAnalyzer
from whad.scapy.layers.esb import ESB_Hdr
from whad.scapy.layers.unifying import bind, Logitech_Unifying_Hdr, \
    Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload, \
    Logitech_Pairing_Request_1_Payload, Logitech_Pairing_Request_2_Payload, \
    Logitech_Pairing_Response_1_Payload, Logitech_Pairing_Response_2_Payload


class LogitechUnifyingCryptoManager:
    def __init__(self, key):
        self.key = key

    def e(self, input_data):
        aes = AES.new(self.key, AES.MODE_ECB)
        return aes.encrypt(input_data)[:8]

    def xor(self, a, b):
        result = []
        for i in range(len(a)):
            result += [a[i] ^ b[i]]
        return bytes(result)

    def extractPayload(self, packet):
        return packet.hid_data + bytes([packet.unknown])

    def generateAESInputData(self, counter):
        return bytes([0x04, 0x14, 0x1d, 0x1f, 0x27, 0x28, 0x0d]) + pack(">I", counter) + bytes([0x0a, 0x0d, 0x13, 0x26, 0x0e])

    def decrypt(self, packet):
        if isinstance(packet, bytes):
            packet = Logitech_Unifying_Hdr(packet)

        elif isinstance(packet, ESB_Hdr):
            packet = packet[Logitech_Unifying_Hdr:]

        if Logitech_Encrypted_Keystroke_Payload not in packet:
            raise MissingEncryptedKeystrokePayload()

        ciphertext = self.extractPayload(packet)
        counter = packet.aes_counter

        aes_in = self.generateAESInputData(counter)
        vector = self.e(aes_in)

        result = self.xor(vector, ciphertext)

        decrypted_packet = copy(packet)
        decrypted_packet.hid_data = result[:7]
        decrypted_packet.unknown = result[7]
        decrypted_packet.aes_counter = counter
        return decrypted_packet

    def encrypt(self, packet):
        if isinstance(packet, bytes):
            packet = Logitech_Unifying_Hdr(packet)

        elif isinstance(packet, ESB_Hdr):
            packet = packet[Logitech_Unifying_Hdr:]

        if Logitech_Encrypted_Keystroke_Payload not in packet:
            raise MissingEncryptedKeystrokePayload()

        plaintext = self.extractPayload(packet)
        counter = packet.aes_counter

        aes_in = self.generateAESInputData(counter)
        vector = self.e(aes_in)

        result = self.xor(vector, plaintext)

        encrypted_packet = copy(packet)
        encrypted_packet.hid_data = result[:7]
        encrypted_packet.unknown = result[7]
        encrypted_packet.aes_counter = counter
        return encrypted_packet

class LogitechUnifyingKeyDerivation(TrafficAnalyzer):
    def __init__(self, address=None, dongle_wpid=None, device_wpid=None, dongle_nonce=None, device_nonce=None):
        self.reset()
        self.address = address
        self.dongle_wpid = dongle_wpid
        self.device_wpid = device_wpid
        self.dongle_nonce = dongle_nonce
        self.device_nonce = device_nonce

    def process_packet(self, packet):
        if Logitech_Pairing_Request_1_Payload in packet:
            self.trigger()
            self.device_wpid = pack(">H", packet.device_wpid)
            self.mark_packet(packet)
        elif Logitech_Pairing_Response_1_Payload in packet:
            self.address = bytes.fromhex(packet.rf_address.replace(":", ""))
            self.dongle_wpid = pack(">H", packet.dongle_wpid)
            self.mark_packet(packet)
        elif Logitech_Pairing_Request_2_Payload in packet:
            self.device_nonce = packet.device_nonce
            self.mark_packet(packet)
        elif Logitech_Pairing_Response_2_Payload in packet:
            self.dongle_nonce = packet.dongle_nonce
            self.mark_packet(packet)
        if (
                self.address is not None and
                self.dongle_wpid is not None and
                self.device_wpid is not None and
                self.dongle_nonce is not None and
                self.device_nonce is not None
        ):
            self.complete()

    @property
    def output(self):
        return {"key" : self.key}

    @property
    def key(self):
        if (
                self.address is not None and
                self.dongle_wpid is not None and
                self.device_wpid is not None and
                self.dongle_nonce is not None and
                self.device_nonce is not None
        ):
            return self._generate_key()
        else:
            return None

    def reset(self):
        super().reset()
        self.address = None
        self.dongle_wpid = None
        self.device_wpid = None
        self.dongle_nonce = None
        self.device_nonce = None

    def _generate_key(self):
        raw_key_material = self.address[:4] + self.device_wpid + self.dongle_wpid + self.device_nonce + self.dongle_nonce
        key = [0 for _ in range(16)]

        key[0] = raw_key_material[7]
        key[1] = raw_key_material[1] ^ 0xff
        key[2] = raw_key_material[0]
        key[3] = raw_key_material[3]
        key[4] = raw_key_material[10]
        key[5] = raw_key_material[2] ^ 0xff
        key[6] = raw_key_material[9] ^ 0x55
        key[7] = raw_key_material[14]
        key[8] = raw_key_material[8]
        key[9] = raw_key_material[6]
        key[10] = raw_key_material[12] ^ 0xff
        key[11] = raw_key_material[5]
        key[12] = raw_key_material[13]
        key[13] = raw_key_material[15] ^ 0x55
        key[14] = raw_key_material[4]
        key[15] = raw_key_material[11]

        return bytes(key)

class LogitechUnifyingDecryptor:
    def __init__(self, *keys):
        self.keys = list(keys)

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
        if Logitech_Encrypted_Keystroke_Payload not in packet:
            raise MissingEncryptedKeystrokePayload()

        for key in self.keys:
            manager = LogitechUnifyingCryptoManager(key)
            decrypted = manager.decrypt(packet)
            
            if b"\x00\x00" in decrypted.hid_data:
                return decrypted[Logitech_Unifying_Hdr:], True

        return packet[Logitech_Unifying_Hdr:], False
