from whad.domain.zigbee.exceptions import MissingNetworkSecurityHeader
from Cryptodome.Cipher import AES
from scapy.layers.dot15d4 import Dot15d4,Dot15d4FCS
from scapy.layers.zigbee import ZigbeeSecurityHeader,ZigbeeNWK
from scapy.compat import raw
from scapy.config import conf
from struct import pack

conf.dot15d4_protocol = "zigbee"

class NetworkLayerCryptoManager:

    SECURITY_LEVELS = {
    	0x00: {"encryption":False,"integrity":False, "M":0},
    	0x01: {"encryption":False,"integrity":True, "M":4},
    	0x02: {"encryption":False,"integrity":True, "M":8},
    	0x03: {"encryption":False,"integrity":True, "M":16},
    	0x04: {"encryption":True,"integrity":False, "M":0},
    	0x05: {"encryption":True,"integrity":True, "M":4},
    	0x06: {"encryption":True,"integrity":True, "M":8},
    	0x07: {"encryption":True,"integrity":True, "M":16}
    }


    def __init__(self, key):
        self.key = key
        self.nonce = None
        self.auth = None
        self.M = None
        self.encryption = None
        self.integrity = None
        self.patched = False

    def generateNonce(self, packet):
        source = raw(packet[ZigbeeSecurityHeader])[5:13] # prevent struct failure on windows ...
        fc = pack("I", packet[ZigbeeSecurityHeader].fc)
        security_header = bytes([(
            packet[ZigbeeSecurityHeader].nwk_seclevel |
            (packet[ZigbeeSecurityHeader].key_type << 3) |
            (packet[ZigbeeSecurityHeader].extended_nonce << 5)|
            (packet[ZigbeeSecurityHeader].reserved1 << 6)
        )])
        return source + fc + security_header

    def checkSecurityLevel(self, packet):
        # If network security level equals to zero, we assume it's the bug mentioned in wireshark source code and patch it
        if packet[ZigbeeSecurityHeader].nwk_seclevel == 0:
            self.patched = True
            packet[ZigbeeSecurityHeader].nwk_seclevel = 0x05 # patched security header: MIC-ENC-32
            M = 4
            encryption = True
            integrity = True
        else:
            # Parse network security level to check how to process the packet
            self.patched = False
            level = NetworkLayerCrypto.SECURITY_LEVELS[packet[ZigbeeSecurityHeader].nwk_seclevel]
            encryption = level["encryption"]
            integrity = level["integrity"]
            if integrity:
                M = level["M"]
            else:
                M = 0
        return (packet, M, integrity, encryption)

    def generateAuth(self, packet):
        if self.encryption:
            auth = raw(packet[ZigbeeNWK:]).replace(packet.data,b"")
        else:
            auth = raw(packet[ZigbeeNWK:])[:-self.M]
        return auth

    def extractCiphertextPayload(self, packet):
        if self.encryption:
            message = packet[ZigbeeSecurityHeader].data[:-self.M]
            mic = packet[ZigbeeSecurityHeader].data[-self.M:]
        else:
            mic = raw(packet[ZigbeeNWK:])[-self.M:]
            message = b""
        return message, mic

    def generateMIC(self,packet):
        self.auth = self.generateAuth(packet)
        plaintext = packet.data
        auth = len(self.auth).to_bytes(2, byteorder = 'big')+self.auth
        auth = auth + (32 - len(auth))*b"\x00" + plaintext+(16 - len(plaintext))*b"\x00"

        flags = (0 << 7) | ((0 if len(self.auth) == 0 else 1) << 6 ) | ((2 - 1) << 3) | ((self.M-2)//2 if self.M else 0)
        B0 = bytes([flags]) + self.nonce + pack(">H",len(plaintext))
        X0 = b"\x00"*16
        cipher = AES.new(self.key, AES.MODE_CBC, X0)
        X1 = cipher.encrypt(B0 + auth)
        return X1[-16:-12]

    def encrypt(self, packet):
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4(packet)

        # don't process FCS if present
        if Dot15d4FCS in packet:
            packet = Dot15d4(raw(packet)[:-2])

        # raise MissingNetworkSecurityHeader exception if no security header is found
        if ZigbeeSecurityHeader not in packet:
            raise MissingNetworkSecurityHeader()

        # check security level (and patch the packet content if needed - see wireshark source code for details)
        packet, self.M, self.integrity, self.encryption = self.checkSecurityLevel(packet)

        # generate the nonce
        self.nonce = self.generateNonce(packet)

        # generate the AES-CCM parameters
        self.auth = self.generateAuth(packet)

        # Extract plaintext
        plaintext = packet.data[:-self.M]

        # Encrypt and generate MIC
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=self.M)
        cipher.update(self.auth)

        ciphertext = cipher.encrypt(plaintext)

        mic = cipher.digest()
        packet.data = ciphertext
        packet.mic = mic

        # Restore security level if patched
        if self.patched:
            packet[ZigbeeSecurityHeader].nwk_seclevel = 0

        return packet

    def decrypt(self, packet):
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4(packet)

        # don't process FCS if present
        if Dot15d4FCS in packet:
            packet = Dot15d4(raw(packet)[:-2])

        # raise MissingNetworkSecurityHeader exception if no security header is found
        if ZigbeeSecurityHeader not in packet:
            raise MissingNetworkSecurityHeader()

        # check security level (and patch the packet content if needed - see wireshark source code for details)
        packet, self.M, self.integrity, self.encryption = self.checkSecurityLevel(packet)

        # generate the nonce
        self.nonce = self.generateNonce(packet)

        # generate the AES-CCM parameters
        self.auth = self.generateAuth(packet)
        ciphertext, mic = self.extractCiphertextPayload(packet)

        # Perform the decryption and integrity check
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=self.M)
        cipher.update(self.auth)

        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(mic)
            packet.data = plaintext
            packet.mic = self.generateMIC(packet)
            # Reverse patching if needed
            if self.patched:
                packet[ZigbeeSecurityHeader].nwk_seclevel = 0

            return (packet, True)

        except ValueError:
            # Reverse patching if needed
            if self.patched:
                packet[ZigbeeSecurityHeader].nwk_seclevel = 0
            return (packet, False) # integrity check
