from whad.zigbee.exceptions import MissingNetworkSecurityHeader
from Cryptodome.Cipher import AES
from scapy.layers.dot15d4 import Dot15d4,Dot15d4FCS
from scapy.layers.zigbee import ZigbeeSecurityHeader,ZigbeeNWK, ZigbeeAppDataPayload
from scapy.compat import raw
from scapy.config import conf
from struct import pack

conf.dot15d4_protocol = "zigbee"

def e(key, plaintext):
    cipher = AES.new(plaintext, AES.MODE_ECB)
    output = cipher.encrypt(key)
    return output

def hash(input):
    output = b"\x00"*16
    M = input
    M += b"\x80"
    while len(M) % 16 != 0:
        M += b"\x00"
    M = M[:-2] + bytes([(0xFF & (len(input)*8 >> 8)),(0xFF & (len(input)*8 >> 0))])
    i = 0
    while i < len(M):
        bloc = M[i:i+16]
        ciphertext = e(bloc,output)
        output = b""
        for j in range(len(bloc)):
            output += bytes([ciphertext[j] ^ bloc[j]])
        i+=16
    return output

def hash_key(key, input):
    ipad = 0x36
    opad = 0x5c

    hash_in = hash_out = b""
    for i in key:
        hash_in += bytes([opad ^ i])
        hash_out += bytes([ipad ^ i])

    hash_out += bytes([input])
    hash_in += hash(hash_out)
    return hash(hash_in)


class CryptoManager:
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
        self.base_class = None
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
            level = CryptoManager.SECURITY_LEVELS[packet[ZigbeeSecurityHeader].nwk_seclevel]
            encryption = level["encryption"]
            integrity = level["integrity"]
            if integrity:
                M = level["M"]
            else:
                M = 0
        return (packet, M, integrity, encryption)

    def generateAuth(self, packet):
        if self.encryption:
            auth = raw(packet[self.base_class:]).replace(packet.data,b"")
        else:
            auth = raw(packet[self.base_class:])[:-self.M]
        return auth

    def extractCiphertextPayload(self, packet):
        if self.encryption:
            message = packet[ZigbeeSecurityHeader].data[:-self.M]
            mic = packet[ZigbeeSecurityHeader].data[-self.M:]
        else:
            mic = raw(packet[self.base_class:])[-self.M:]
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
        padding = b""
        while len(padding + B0 + auth) % 16 != 0:
            padding += b"\x00"
        X1 = cipher.encrypt(padding + B0 + auth)
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

        if self.base_class is None:
            self.base_class = packet[ZigbeeSecurityHeader].underlayer.__class__

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

        if self.base_class is None:
            self.base_class = packet[ZigbeeSecurityHeader].underlayer.__class__

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
        #try:
        cipher.verify(mic)
        packet.data = plaintext
        packet.mic = self.generateMIC(packet)
        # Reverse patching if needed
        if self.patched:
            packet[ZigbeeSecurityHeader].nwk_seclevel = 0

        return (packet, True)

        #except ValueError:
        # Reverse patching if needed
        #    if self.patched:
        #        packet[ZigbeeSecurityHeader].nwk_seclevel = 0
        #    return (packet, False) # integrity check

class NetworkLayerCryptoManager(CryptoManager):

    def __init__(self, key):
        super().__init__(key)
        self.base_class = ZigbeeNWK

class ApplicationSubLayerCryptoManager(CryptoManager):

    def __init__(self, key, input):
        if input is None:
            generated_key = self.base_key = key
        else:
            self.input = input
            self.base_key = key
            generated_key = hash_key(key, self.input)
        super().__init__(generated_key)
        self.base_class = ZigbeeAppDataPayload
