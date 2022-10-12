from Cryptodome.Cipher import AES
from struct import pack
from copy import copy

from whad.unifying.exceptions import MissingEncryptedKeystrokePayload
from whad.scapy.layers.esb import ESB_Hdr
from whad.scapy.layers.unifying import bind, Logitech_Unifying_Hdr, \
    Logitech_Unencrypted_Keystroke_Payload, Logitech_Encrypted_Keystroke_Payload


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
        return encrypted_packet

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
