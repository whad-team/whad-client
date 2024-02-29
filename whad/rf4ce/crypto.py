from scapy.config import conf

conf.dot15d4_protocol = "rf4ce"

class RF4CECryptoManager:
    def __init__(self, key):
        self.key = key

    def decrypt(self, packet, source=None, destination=None):
        pass
