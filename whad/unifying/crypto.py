from whad.unifying.exceptions import MissingEncryptedKeystrokePayload

class LogitechUnifyingCryptoManager:
    def __init__(self, key):
        self.key = key

    def extractCiphertextPayload(self, packet):
        return bytes(packet)[2:10]

    def decrypt(self, packet):
        if isinstance(packet, bytes):
            packet = Logitech_Unifying_Hdr(packet)

        elif isinstance(packet, ESB_Hdr):
            packet = packet[Logitech_Unifying_Hdr:]

        if Logitech_Encrypted_Keystroke_Payload not in packet:
            raise MissingEncryptedKeystrokePayload()
